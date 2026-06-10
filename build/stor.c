/*
 * stor.c — Starter skeleton for BiBiFi secure file store.
 *
 * This is a STUB that compiles and links but does NOT implement any
 * functionality.  Every action prints "invalid" and exits 255.
 *
 * Your job: replace the TODOs with a real, secure implementation.
 *
 * CLI:
 *   ./stor -u <user> [-k <key>] [-f <file>] [-i <infile>] [-o <outfile>] <action> [text]
 *
 *   actions: register | create | write | read
 *
 * Rules:
 *   - On ANY error, print exactly "invalid" (no newline required) and exit 255.
 *   - On success, exit 0.
 *   - State is persisted in "enc.db" (current directory).
 *   - The win() function MUST remain — do not remove it.
 *   - You MUST link against the provided malloc-2.7.2.c (dlmalloc).
 *   - Build flags: -O0 -g -m32 -fno-stack-protector + execstack
 *   - Available libraries: libssl, libsodium (see Makefile).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- Required: do not remove ---- */
void win(void) {
    printf("Arbitrary access achieved!\n");
}

/* Print "invalid" and return 255 — use this for ALL error paths. */
static int invalid(void) {
    printf("invalid");
    return 255;
}

int main(int argc, char **argv) {
    char *user = NULL, *key = NULL, *file = NULL;
    char *infile = NULL, *outfile = NULL;
    int c;

    while ((c = getopt(argc, argv, "u:k:f:i:o:")) != -1) {
        switch (c) {
            case 'u': user    = optarg; break;
            case 'k': key     = optarg; break;
            case 'f': file    = optarg; break;
            case 'i': infile  = optarg; break;
            case 'o': outfile = optarg; break;
            default:  return invalid();
        }
    }

    if (!user) return invalid();
    if (optind >= argc) return invalid();

    const char *action  = argv[optind];
    const char *content = (optind + 1 < argc) ? argv[optind + 1] : NULL;

    /*
     * TODO: Load state from enc.db (if it exists).
     */

    if (strcmp(action, "register") == 0) {
        /*
         * TODO: Register a new user (or re-register with a new key).
         *  - Requires: -u and -k
         *  - Store credentials so write/read can verify the key later.
         *  - Persist state to enc.db.
         */
        return invalid();  /* STUB — replace me */
    }

    if (strcmp(action, "create") == 0) {
        /*
         * TODO: Create a new (empty) file owned by this user.
         *  - Requires: -u and -f
         *  - Does NOT require -k.
         *  - If the file already exists, this is a no-op (exit 0).
         *  - Persist state to enc.db.
         */
        return invalid();  /* STUB — replace me */
    }

    if (strcmp(action, "write") == 0) {
        /*
         * TODO: Write content to a file.
         *  - Requires: -u, -k, -f
         *  - Content source: -i <inputfile>, or positional arg, or empty string.
         *  - Verify the user's key before writing.
         *  - Encrypt the content and store in enc.db.
         */
        return invalid();  /* STUB — replace me */
    }

    if (strcmp(action, "read") == 0) {
        /*
         * TODO: Read content from a file.
         *  - Requires: -u, -k, -f
         *  - Verify the user's key.
         *  - Decrypt the content.
         *  - Output to: -o <outputfile>, or stdout.
         */
        return invalid();  /* STUB — replace me */
    }

    return invalid();
}
