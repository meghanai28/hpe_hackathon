/*
 * stor.c — BiBiFi secure encrypted file store.
 *
 * CLI:
 *   ./stor -u <user> [-k <key>] [-f <file>] [-i <infile>] [-o <outfile>] <action> [text]
 *   actions: register | create | write | read
 *
 * Behavior:
 *   - On ANY error / incomplete / contradictory args: print "invalid", exit 255.
 *   - On success: exit 0.
 *   - All state persisted to "enc.db" in the working directory.
 *
 * Security model:
 *   - Per-user 64-byte key material is derived from the secret with
 *     PBKDF2-HMAC-SHA256 over a random per-user salt. It splits into an
 *     AES-256 encryption key and an HMAC-SHA256 MAC key.
 *   - File CONTENTS are sealed with AES-256-GCM. The AAD binds each blob to
 *     "username\0filename", so a ciphertext cannot be moved between files or
 *     users, and any tampering with enc.db fails the GCM tag on read.
 *   - A 16-byte verifier = HMAC(MAC key, username) lets a wrong key be
 *     rejected deterministically (confidentiality + cross-user isolation).
 *   - Filenames/usernames are stored in the clear: the privacy requirement
 *     covers file *contents*, and `create` must work without the key.
 *
 * Allocator: linked against dlmalloc (malloc-2.7.2.c).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

/* ---- Required: do not remove ---- */
void win(void) {
    printf("Arbitrary access achieved!\n");
}

/* ---------------- constants ---------------- */
#define DB_FILE      "enc.db"
#define DB_TMP       "enc.db.tmp"
#define DB_VERSION   1

#define SALT_LEN     16
#define IV_LEN       12
#define TAG_LEN      16
#define ENC_KEY_LEN  32
#define MAC_KEY_LEN  32
#define KEYMAT_LEN   (ENC_KEY_LEN + MAC_KEY_LEN)
#define VERIF_LEN    16
#define PBKDF2_ITERS 100000

/* STOR_ prefix avoids clashing with system macros (e.g. <linux/limits.h>
 * defines MAX_INPUT). */
#define STOR_MAX_DB_SIZE  (64u * 1024u * 1024u)
/* below the DB cap so length-padding (≤64 KiB) can't push a blob over it */
#define STOR_MAX_INPUT    (63u * 1024u * 1024u)
#define STOR_MAX_NAME_LEN (1u << 20)
#define STOR_MAX_COUNT    (1u << 24)
#define STOR_MAX_ITERS    (4u * 1000u * 1000u)  /* clamp PBKDF2 cost from a forged db */
#define STOR_MAX_ARG      65535u                 /* generous cap on user/key/file/paths */

/* Minimum on-disk size of one record, used to bound speculative allocations
 * against the actual file length (a forged count can't exceed what's present). */
#define MIN_USER_BYTES 44   /* namelen(4)+salt(16)+iters(4)+verifier(16)+nfiles(4) */
#define MIN_FILE_BYTES 5    /* namelen(4)+has_content(1) */

/* ---------------- fatal error path ---------------- */
static void fail(void) {
    fputs("invalid", stdout);   /* exact token, no newline */
    exit(255);                  /* flushes stdio buffers */
}

static void secure_zero(void *p, size_t n) {
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) *vp++ = 0;
}

static void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) fail();             /* graceful out-of-memory */
    return p;
}

/* ---------------- in-memory model ---------------- */
typedef struct {
    char    *name;
    uint32_t namelen;
    uint8_t  has_content;
    uint8_t  iv[IV_LEN];
    uint8_t  tag[TAG_LEN];
    uint8_t *ct;
    uint32_t ctlen;
} File;

typedef struct {
    char    *name;
    uint32_t namelen;
    uint8_t  salt[SALT_LEN];
    uint32_t iters;
    uint8_t  verifier[VERIF_LEN];
    File    *files;
    uint32_t nfiles;
} User;

typedef struct {
    User    *users;
    uint32_t nusers;
} DB;

static void free_db(DB *db) {
    uint32_t i, j;
    if (!db || !db->users) { if (db) { db->users = NULL; db->nusers = 0; } return; }
    for (i = 0; i < db->nusers; i++) {
        User *u = &db->users[i];
        if (u->files) {
            for (j = 0; j < u->nfiles; j++) {
                free(u->files[j].name);
                free(u->files[j].ct);
            }
            free(u->files);
        }
        free(u->name);
    }
    free(db->users);
    db->users = NULL;
    db->nusers = 0;
}

/* ---------------- growable write buffer ---------------- */
typedef struct { uint8_t *p; size_t len, cap; } Buf;

static void buf_reserve(Buf *b, size_t add) {
    if (b->len + add < b->len) fail();          /* size_t overflow */
    if (b->len + add > b->cap) {
        size_t nc = b->cap ? b->cap : 256;
        while (nc < b->len + add) {
            if (nc > (SIZE_MAX / 2)) { nc = b->len + add; break; }
            nc *= 2;
        }
        uint8_t *np = realloc(b->p, nc);
        if (!np) { free(b->p); fail(); }
        b->p = np; b->cap = nc;
    }
}
static void buf_bytes(Buf *b, const void *s, size_t n) {
    buf_reserve(b, n);
    memcpy(b->p + b->len, s, n);
    b->len += n;
}
static void buf_u8(Buf *b, uint8_t v)  { buf_bytes(b, &v, 1); }
static void buf_u32(Buf *b, uint32_t v) {
    uint8_t t[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };
    buf_bytes(b, t, 4);
}

/* ---------------- bounds-checked reader ---------------- */
typedef struct { const uint8_t *p; size_t len, off; } Rd;

static int rd_bytes(Rd *r, void *out, size_t n) {
    if (r->off + n < r->off || r->off + n > r->len) return -1;
    memcpy(out, r->p + r->off, n);
    r->off += n;
    return 0;
}
static int rd_u8(Rd *r, uint8_t *v)  { return rd_bytes(r, v, 1); }
static int rd_u32(Rd *r, uint32_t *v) {
    uint8_t t[4];
    if (rd_bytes(r, t, 4)) return -1;
    *v = (uint32_t)t[0] | ((uint32_t)t[1] << 8) | ((uint32_t)t[2] << 16) | ((uint32_t)t[3] << 24);
    return 0;
}
static size_t rd_remaining(const Rd *r) { return r->len - r->off; }

/* ---------------- crypto helpers ---------------- */
static void derive_keys(const char *secret, size_t slen, const uint8_t *salt,
                        uint32_t iters, uint8_t *keymat /* KEYMAT_LEN */) {
    if (slen > INT_MAX) fail();                 /* OpenSSL takes int lengths */
    if (PKCS5_PBKDF2_HMAC(secret, (int)slen, salt, SALT_LEN, (int)iters,
                          EVP_sha256(), KEYMAT_LEN, keymat) != 1)
        fail();
}

static void compute_verifier(const uint8_t *mackey, const char *user, size_t ulen,
                             uint8_t *out16) {
    uint8_t mac[EVP_MAX_MD_SIZE];
    unsigned int maclen = 0;
    if (!HMAC(EVP_sha256(), mackey, MAC_KEY_LEN,
              (const unsigned char *)user, ulen, mac, &maclen) || maclen < VERIF_LEN)
        fail();
    memcpy(out16, mac, VERIF_LEN);
    secure_zero(mac, sizeof(mac));
}

/* returns ciphertext length (== ptlen) on success, -1 on failure */
static int gcm_encrypt(const uint8_t *key, const uint8_t *iv,
                       const uint8_t *aad, size_t aadlen,
                       const uint8_t *pt, size_t ptlen,
                       uint8_t *ct, uint8_t *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, outl = 0, ret = -1;
    if (aadlen > INT_MAX || ptlen > INT_MAX) return -1;   /* int-cast safety */
    if (!ctx) return -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto done;
    if (aadlen > 0 && EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aadlen) != 1) goto done;
    if (ptlen > 0) {
        if (EVP_EncryptUpdate(ctx, ct, &len, pt, (int)ptlen) != 1) goto done;
        outl = len;
    }
    if (EVP_EncryptFinal_ex(ctx, ct + outl, &len) != 1) goto done;
    outl += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) goto done;
    ret = outl;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* returns plaintext length on success, -1 on auth failure / error */
static int gcm_decrypt(const uint8_t *key, const uint8_t *iv,
                       const uint8_t *aad, size_t aadlen,
                       const uint8_t *ct, size_t ctlen,
                       const uint8_t *tag, uint8_t *pt) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, outl = 0, ret = -1;
    if (aadlen > INT_MAX || ctlen > INT_MAX) return -1;   /* int-cast safety */
    if (!ctx) return -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto done;
    if (aadlen > 0 && EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aadlen) != 1) goto done;
    if (ctlen > 0) {
        if (EVP_DecryptUpdate(ctx, pt, &len, ct, (int)ctlen) != 1) goto done;
        outl = len;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, pt + outl, &len) <= 0) goto done; /* tag mismatch */
    outl += len;
    ret = outl;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static void rand_bytes(uint8_t *b, size_t n) {
    if (RAND_bytes(b, (int)n) != 1) fail();
}

/* ---------------- file I/O ---------------- */
/* 0 ok; -1 not-found/read-error; -2 too big; -3 oom */
static int read_file_all(const char *path, uint8_t **out, size_t *outlen, size_t maxsz) {
    struct stat st;
    FILE *f;
    uint8_t *buf;
    size_t n, got;
    if (stat(path, &st) != 0) return -1;
    if (!S_ISREG(st.st_mode)) return -1;        /* regular files only (no FIFO/device hang) */
    if (st.st_size < 0) return -1;
    if ((size_t)st.st_size > maxsz) return -2;
    n = (size_t)st.st_size;
    f = fopen(path, "rb");
    if (!f) return -1;
    buf = malloc(n ? n : 1);
    if (!buf) { fclose(f); return -3; }
    got = n ? fread(buf, 1, n, f) : 0;
    fclose(f);
    if (got != n) { free(buf); return -1; }
    *out = buf;
    *outlen = n;
    return 0;
}

/* ---------------- db (de)serialization ---------------- */
/* 0 ok, -1 corrupt. On error db is fully freed. */
static int db_parse(const uint8_t *data, size_t len, DB *db) {
    Rd r;
    uint8_t magic[4], ver;
    uint32_t nusers, i, j, a, b;
    r.p = data; r.len = len; r.off = 0;
    memset(db, 0, sizeof(*db));

    if (rd_bytes(&r, magic, 4) || memcmp(magic, "STOR", 4) != 0) return -1;
    if (rd_u8(&r, &ver) || ver != DB_VERSION) return -1;
    if (rd_u32(&r, &nusers)) return -1;
    if (nusers > STOR_MAX_COUNT || nusers > rd_remaining(&r) / MIN_USER_BYTES) return -1;
    if (nusers == 0) { if (rd_remaining(&r) != 0) return -1; return 0; }

    db->users = calloc(nusers, sizeof(User));
    if (!db->users) return -1;
    db->nusers = nusers;

    for (i = 0; i < nusers; i++) {
        User *u = &db->users[i];
        uint32_t nl, nf;
        if (rd_u32(&r, &nl) || nl > STOR_MAX_NAME_LEN) goto corrupt;
        u->name = malloc((size_t)nl + 1);
        if (!u->name) goto corrupt;
        if (rd_bytes(&r, u->name, nl)) goto corrupt;
        u->name[nl] = '\0';
        if (memchr(u->name, 0, nl)) goto corrupt;       /* reject embedded NUL */
        u->namelen = nl;
        if (rd_bytes(&r, u->salt, SALT_LEN)) goto corrupt;
        if (rd_u32(&r, &u->iters) || u->iters < 1 || u->iters > STOR_MAX_ITERS) goto corrupt;
        if (rd_bytes(&r, u->verifier, VERIF_LEN)) goto corrupt;
        if (rd_u32(&r, &nf) || nf > STOR_MAX_COUNT || nf > rd_remaining(&r) / MIN_FILE_BYTES) goto corrupt;
        if (nf > 0) {
            u->files = calloc(nf, sizeof(File));
            if (!u->files) goto corrupt;
        }
        u->nfiles = nf;
        for (j = 0; j < nf; j++) {
            File *fl = &u->files[j];
            uint32_t fnl;
            if (rd_u32(&r, &fnl) || fnl > STOR_MAX_NAME_LEN) goto corrupt;
            fl->name = malloc((size_t)fnl + 1);
            if (!fl->name) goto corrupt;
            if (rd_bytes(&r, fl->name, fnl)) goto corrupt;
            fl->name[fnl] = '\0';
            if (memchr(fl->name, 0, fnl)) goto corrupt;     /* reject embedded NUL */
            fl->namelen = fnl;
            if (rd_u8(&r, &fl->has_content) || fl->has_content > 1) goto corrupt;
            if (fl->has_content) {
                if (rd_bytes(&r, fl->iv, IV_LEN)) goto corrupt;
                if (rd_u32(&r, &fl->ctlen) || fl->ctlen > STOR_MAX_DB_SIZE) goto corrupt;
                if (fl->ctlen > 0) {
                    if (fl->ctlen > rd_remaining(&r)) goto corrupt;
                    fl->ct = malloc(fl->ctlen);
                    if (!fl->ct) goto corrupt;
                    if (rd_bytes(&r, fl->ct, fl->ctlen)) goto corrupt;
                }
                if (rd_bytes(&r, fl->tag, TAG_LEN)) goto corrupt;
            }
        }
        /* reject duplicate filenames within a user (small-n only: avoids O(n^2) DoS) */
        if (nf > 1 && nf <= 4096)
            for (a = 0; a < nf; a++)
                for (b = a + 1; b < nf; b++)
                    if (u->files[a].namelen == u->files[b].namelen &&
                        memcmp(u->files[a].name, u->files[b].name, u->files[a].namelen) == 0)
                        goto corrupt;
    }
    /* reject duplicate usernames + any trailing bytes after the last record */
    if (nusers > 1 && nusers <= 4096)
        for (a = 0; a < nusers; a++)
            for (b = a + 1; b < nusers; b++)
                if (db->users[a].namelen == db->users[b].namelen &&
                    memcmp(db->users[a].name, db->users[b].name, db->users[a].namelen) == 0)
                    goto corrupt;
    if (rd_remaining(&r) != 0) goto corrupt;
    return 0;
corrupt:
    free_db(db);
    return -1;
}

/* 0 ok (db may be empty if file absent); -1 corrupt/unreadable */
static int db_load(DB *db) {
    struct stat st;
    uint8_t *data;
    size_t len;
    int rc;
    memset(db, 0, sizeof(*db));
    if (stat(DB_FILE, &st) != 0) return 0;     /* absent -> empty db */
    rc = read_file_all(DB_FILE, &data, &len, STOR_MAX_DB_SIZE);
    if (rc != 0) return -1;                     /* exists but unreadable/oversize */
    rc = db_parse(data, len, db);
    free(data);
    return rc;
}

static void db_serialize(const DB *db, Buf *b) {
    uint32_t i, j;
    buf_bytes(b, "STOR", 4);
    buf_u8(b, DB_VERSION);
    buf_u32(b, db->nusers);
    for (i = 0; i < db->nusers; i++) {
        const User *u = &db->users[i];
        buf_u32(b, u->namelen);
        buf_bytes(b, u->name, u->namelen);
        buf_bytes(b, u->salt, SALT_LEN);
        buf_u32(b, u->iters);
        buf_bytes(b, u->verifier, VERIF_LEN);
        buf_u32(b, u->nfiles);
        for (j = 0; j < u->nfiles; j++) {
            const File *fl = &u->files[j];
            buf_u32(b, fl->namelen);
            buf_bytes(b, fl->name, fl->namelen);
            buf_u8(b, fl->has_content);
            if (fl->has_content) {
                buf_bytes(b, fl->iv, IV_LEN);
                buf_u32(b, fl->ctlen);
                if (fl->ctlen) buf_bytes(b, fl->ct, fl->ctlen);
                buf_bytes(b, fl->tag, TAG_LEN);
            }
        }
    }
}

/* atomic write: temp file + rename */
static void db_save(const DB *db) {
    Buf b;
    FILE *f;
    int fd;
    b.p = NULL; b.len = 0; b.cap = 0;
    db_serialize(db, &b);
    if (b.len > STOR_MAX_DB_SIZE) { free(b.p); fail(); }   /* keep it reloadable */
    /* O_EXCL after unlink: never follow/overwrite a pre-planted symlink, and
     * create the store owner-only (0600). */
    unlink(DB_TMP);
    fd = open(DB_TMP, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) { free(b.p); fail(); }
    f = fdopen(fd, "wb");
    if (!f) { close(fd); unlink(DB_TMP); free(b.p); fail(); }
    if (b.len > 0 && fwrite(b.p, 1, b.len, f) != b.len) { fclose(f); remove(DB_TMP); free(b.p); fail(); }
    if (fflush(f) != 0)                                  { fclose(f); remove(DB_TMP); free(b.p); fail(); }
    fclose(f);
    free(b.p);
    if (rename(DB_TMP, DB_FILE) != 0) { remove(DB_TMP); fail(); }
}

/* ---------------- lookups / mutation ---------------- */
static User *find_user(DB *db, const char *name) {
    size_t nl = strlen(name);
    uint32_t i;
    for (i = 0; i < db->nusers; i++)
        if (db->users[i].namelen == nl && memcmp(db->users[i].name, name, nl) == 0)
            return &db->users[i];
    return NULL;
}
static File *find_file(User *u, const char *name) {
    size_t nl = strlen(name);
    uint32_t j;
    for (j = 0; j < u->nfiles; j++)
        if (u->files[j].namelen == nl && memcmp(u->files[j].name, name, nl) == 0)
            return &u->files[j];
    return NULL;
}
static User *db_add_user(DB *db, const char *name) {
    User *nu = realloc(db->users, (size_t)(db->nusers + 1) * sizeof(User));
    User *u;
    if (!nu) fail();
    db->users = nu;
    u = &db->users[db->nusers];
    memset(u, 0, sizeof(*u));
    u->namelen = (uint32_t)strlen(name);
    u->name = xmalloc((size_t)u->namelen + 1);
    memcpy(u->name, name, (size_t)u->namelen + 1);
    db->nusers++;
    return u;
}
static File *user_add_file(User *u, const char *name) {
    File *nf = realloc(u->files, (size_t)(u->nfiles + 1) * sizeof(File));
    File *fl;
    if (!nf) fail();
    u->files = nf;
    fl = &u->files[u->nfiles];
    memset(fl, 0, sizeof(*fl));
    fl->namelen = (uint32_t)strlen(name);
    fl->name = xmalloc((size_t)fl->namelen + 1);
    memcpy(fl->name, name, (size_t)fl->namelen + 1);
    u->nfiles++;
    return fl;
}

/* aad = user '\0' file  (binds a ciphertext to its owner + filename) */
static uint8_t *make_aad(const char *user, const char *file, size_t *len) {
    size_t ul = strlen(user), fl = strlen(file), n = ul + 1 + fl;
    uint8_t *a = xmalloc(n);
    memcpy(a, user, ul);
    a[ul] = '\0';
    memcpy(a + ul + 1, file, fl);
    *len = n;
    return a;
}

/* length-hiding: bucket size for [u32 len][plaintext][zero pad] so the stored
 * ciphertext length reveals only a coarse bucket, not the exact content size. */
static size_t padded_size(size_t plain) {
    size_t need = plain + 4;          /* 4-byte true-length prefix */
    size_t p;
    if (need <= 65536u) {
        p = 16;
        while (p < need) p <<= 1;      /* next power of two, min 16, max 65536 */
    } else {
        p = (need + 65535u) & ~(size_t)65535u;   /* round up to 64 KiB */
    }
    return p;
}

/* derive keys for `user` and verify the supplied key; fail() on mismatch */
static void auth_user(User *u, const char *user, const char *key, uint8_t *keymat_out) {
    uint8_t vchk[VERIF_LEN];
    derive_keys(key, strlen(key), u->salt, u->iters, keymat_out);
    compute_verifier(keymat_out + ENC_KEY_LEN, user, strlen(user), vchk);
    if (CRYPTO_memcmp(vchk, u->verifier, VERIF_LEN) != 0) {
        secure_zero(keymat_out, KEYMAT_LEN);
        fail();
    }
}

/* ---------------- commands ---------------- */
static int do_register(const char *user, const char *key) {
    DB db;
    User *u;
    uint8_t keymat[KEYMAT_LEN];
    if (db_load(&db) != 0) fail();
    if (find_user(&db, user)) { free_db(&db); fail(); }   /* duplicate username */
    u = db_add_user(&db, user);
    rand_bytes(u->salt, SALT_LEN);
    u->iters = PBKDF2_ITERS;
    derive_keys(key, strlen(key), u->salt, u->iters, keymat);
    compute_verifier(keymat + ENC_KEY_LEN, user, strlen(user), u->verifier);
    secure_zero(keymat, sizeof(keymat));
    db_save(&db);
    free_db(&db);
    return 0;
}

static int do_create(const char *user, const char *file) {
    DB db;
    User *u;
    if (db_load(&db) != 0) fail();
    u = find_user(&db, user);
    if (!u) { free_db(&db); fail(); }
    if (find_file(u, file)) { free_db(&db); return 0; }    /* already exists: no-op */
    user_add_file(u, file);
    db_save(&db);
    free_db(&db);
    return 0;
}

static int do_write(const char *user, const char *key, const char *file,
                    const char *infile, const char *text) {
    DB db;
    User *u;
    File *fl;
    uint8_t keymat[KEYMAT_LEN];
    uint8_t *content = NULL, *aad, *ct;
    size_t clen = 0, aadlen;
    int content_owned = 0, ctlen;
    uint8_t iv[IV_LEN], tag[TAG_LEN];

    if (db_load(&db) != 0) fail();
    u = find_user(&db, user);
    if (!u) { free_db(&db); fail(); }
    auth_user(u, user, key, keymat);
    fl = find_file(u, file);
    if (!fl) { secure_zero(keymat, sizeof(keymat)); free_db(&db); fail(); }

    if (infile) {
        uint8_t *ibuf; size_t ilen;
        if (read_file_all(infile, &ibuf, &ilen, STOR_MAX_INPUT) != 0) {
            secure_zero(keymat, sizeof(keymat)); free_db(&db); fail();
        }
        if (ilen > 0 && ibuf[ilen - 1] == '\n') ilen--;    /* drop one trailing newline */
        content = ibuf; clen = ilen; content_owned = 1;
    } else if (text) {
        content = (uint8_t *)text; clen = strlen(text);
    } else {
        content = (uint8_t *)""; clen = 0;
    }

    aad = make_aad(user, file, &aadlen);
    rand_bytes(iv, IV_LEN);
    {
        /* seal [u32 true-len][content][zero pad] padded to a length bucket */
        size_t plen = padded_size(clen);
        uint8_t *pbuf = xmalloc(plen);
        pbuf[0] = (uint8_t)clen;          pbuf[1] = (uint8_t)(clen >> 8);
        pbuf[2] = (uint8_t)(clen >> 16);  pbuf[3] = (uint8_t)(clen >> 24);
        if (clen) memcpy(pbuf + 4, content, clen);
        memset(pbuf + 4 + clen, 0, plen - 4 - clen);
        ct = xmalloc(plen);
        ctlen = gcm_encrypt(keymat, iv, aad, aadlen, pbuf, plen, ct, tag);
        secure_zero(pbuf, plen);
        free(pbuf);
    }
    free(aad);
    if (content_owned) { secure_zero(content, clen); free(content); }
    secure_zero(keymat, sizeof(keymat));
    if (ctlen < 0) { free(ct); free_db(&db); fail(); }

    free(fl->ct);
    fl->ct = ct;
    fl->ctlen = (uint32_t)ctlen;
    memcpy(fl->iv, iv, IV_LEN);
    memcpy(fl->tag, tag, TAG_LEN);
    fl->has_content = 1;

    db_save(&db);
    free_db(&db);
    return 0;
}

static int do_read(const char *user, const char *key, const char *file,
                   const char *outfile) {
    DB db;
    User *u;
    File *fl;
    uint8_t keymat[KEYMAT_LEN];
    uint8_t *pt = NULL;
    size_t ptlen = 0;
    uint8_t *out_data = NULL;
    size_t out_len = 0;
    int pt_owned = 0;

    if (outfile && (strcmp(outfile, DB_FILE) == 0 || strcmp(outfile, DB_TMP) == 0))
        fail();                                 /* never let read -o clobber the database */

    if (db_load(&db) != 0) fail();
    u = find_user(&db, user);
    if (!u) { free_db(&db); fail(); }
    auth_user(u, user, key, keymat);
    fl = find_file(u, file);
    if (!fl) { secure_zero(keymat, sizeof(keymat)); free_db(&db); fail(); }
    /* created-but-never-written has no content; reading it is invalid (also
     * defeats a has_content 1->0 flip, which would otherwise read as empty) */
    if (!fl->has_content) { secure_zero(keymat, sizeof(keymat)); free_db(&db); fail(); }

    if (fl->has_content) {
        size_t aadlen;
        uint8_t *aad = make_aad(user, file, &aadlen);
        size_t truelen;
        int r;
        pt = xmalloc(fl->ctlen ? fl->ctlen : 1);
        pt_owned = 1;
        r = gcm_decrypt(keymat, fl->iv, aad, aadlen, fl->ct, fl->ctlen, fl->tag, pt);
        free(aad);
        if (r < 0) {                                       /* tampered / wrong key */
            secure_zero(pt, fl->ctlen); free(pt);
            secure_zero(keymat, sizeof(keymat)); free_db(&db); fail();
        }
        ptlen = (size_t)r;
        /* unwrap [u32 true-len][plaintext][pad]; authenticated, so trusted */
        if (ptlen < 4) {
            secure_zero(pt, fl->ctlen); free(pt);
            secure_zero(keymat, sizeof(keymat)); free_db(&db); fail();
        }
        truelen = (size_t)pt[0] | ((size_t)pt[1] << 8) |
                  ((size_t)pt[2] << 16) | ((size_t)pt[3] << 24);
        if (truelen > ptlen - 4) {
            secure_zero(pt, fl->ctlen); free(pt);
            secure_zero(keymat, sizeof(keymat)); free_db(&db); fail();
        }
        out_data = pt + 4;
        out_len = truelen;
    }
    secure_zero(keymat, sizeof(keymat));

    if (outfile) {
        struct stat ost;
        int ofd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC | O_NONBLOCK, 0600);
        FILE *f;
        if (ofd < 0) { if (pt_owned) free(pt); free_db(&db); fail(); }
        if (fstat(ofd, &ost) != 0 || !S_ISREG(ost.st_mode)) {  /* no FIFO/device */
            close(ofd); if (pt_owned) free(pt); free_db(&db); fail();
        }
        f = fdopen(ofd, "wb");
        if (!f) { close(ofd); if (pt_owned) free(pt); free_db(&db); fail(); }
        if (out_len > 0 && fwrite(out_data, 1, out_len, f) != out_len) {
            fclose(f); if (pt_owned) free(pt); free_db(&db); fail();
        }
        fclose(f);
    } else {
        if (out_len > 0) fwrite(out_data, 1, out_len, stdout);
    }

    if (pt_owned) { secure_zero(pt, ptlen); free(pt); }
    free_db(&db);
    return 0;
}

/* ---------------- entry point ---------------- */
int main(int argc, char **argv) {
    char *user = NULL, *key = NULL, *file = NULL, *infile = NULL, *outfile = NULL;
    const char *action, *text;
    int c;

    opterr = 0;                                 /* we emit our own "invalid" */
    while ((c = getopt(argc, argv, "u:k:f:i:o:")) != -1) {
        switch (c) {
            case 'u': user    = optarg; break;  /* last occurrence wins */
            case 'k': key     = optarg; break;
            case 'f': file    = optarg; break;
            case 'i': infile  = optarg; break;
            case 'o': outfile = optarg; break;
            default:  fail();
        }
    }

    if (!user) fail();
    if (strlen(user) > STOR_MAX_ARG) fail();     /* bound identifiers/paths */
    if (key     && strlen(key)     > STOR_MAX_ARG) fail();
    if (file    && strlen(file)    > STOR_MAX_ARG) fail();
    if (infile  && strlen(infile)  > STOR_MAX_ARG) fail();
    if (outfile && strlen(outfile) > STOR_MAX_ARG) fail();
    if (optind >= argc) fail();                 /* no action */
    action = argv[optind];
    text   = (optind + 1 < argc) ? argv[optind + 1] : NULL;

    /* Reject EXTRA POSITIONAL args (a stray word after the action). Irrelevant
     * *flags* are still ignored — e.g. `create -k` must stay valid. */
    if (strcmp(action, "register") == 0) {
        if (!key || optind + 1 < argc) fail();
        return do_register(user, key);
    }
    if (strcmp(action, "create") == 0) {
        if (!file || optind + 1 < argc) fail();
        return do_create(user, file);
    }
    if (strcmp(action, "write") == 0) {
        if (!key || !file || optind + 2 < argc) fail();  /* action + at most one text */
        return do_write(user, key, file, infile, text);
    }
    if (strcmp(action, "read") == 0) {
        if (!key || !file || optind + 1 < argc) fail();
        return do_read(user, key, file, outfile);
    }

    fail();
    return 255;                                 /* unreachable */
}
