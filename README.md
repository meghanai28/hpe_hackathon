# BiBiFi Starter Package — `stor` (Secure File Store)

## What's in here

```
build/
  stor.c             ← Stub source — compiles but fails all tests
  Makefile           ← Build rules (gcc -m32, dlmalloc, execstack)
  malloc-2.7.2.c     ← Required allocator (DO NOT MODIFY)
Dockerfile.sandbox   ← Ubuntu 18.04 build environment
tests.json           ← 10 functionality tests the grader runs
```

## Quick Start

### Option A: Build in Docker (recommended)

```bash
# Build the sandbox image (one-time)
docker build -t bibifi-sandbox -f Dockerfile.sandbox .

# Run interactively — your build/ dir is mounted at /connect
docker run --rm -it -v $(pwd)/build:/connect bibifi-sandbox

# Inside the container:
make
./stor -u alice -k secret123 register    # should exit 0 when implemented
```

### Option B: Build natively (requires 32-bit toolchain)

```bash
cd build/
make
```

## The Problem

Implement `stor`, a CLI encrypted file store. Commands:

| Command    | Required flags        | Description                        |
|------------|-----------------------|------------------------------------|
| `register` | `-u <user> -k <key>`  | Register user with auth token      |
| `create`   | `-u <user> -f <file>` | Create an empty file (no key needed) |
| `write`    | `-u <user> -k <key> -f <file>` | Write content (from arg, or `-i` file) |
| `read`     | `-u <user> -k <key> -f <file>` | Read content (to stdout, or `-o` file) |

**On any error:** print exactly `invalid` and exit 255.  
**On success:** exit 0.  
**State:** persisted in `enc.db` (current directory).

## Security Requirements

- Privacy: an adversary without the auth token must not learn file contents
- Integrity: detect any unauthorized modifications to `enc.db`
- The `win()` function must remain in the binary (do not remove it)

## Test Format

`tests.json` contains 10 tests. Each test has a sequence of commands and expected outcomes (exit code and/or stdout). The grader runs each test in a fresh directory with a 60-second timeout.

Example test manually:
```bash
rm -f enc.db
./stor -u alice -k secret123 register       # expect exit 0
./stor -u alice -f notes create              # expect exit 0
./stor -u alice -k secret123 -f notes write "hello world"  # expect exit 0
./stor -u alice -k secret123 -f notes read   # expect stdout: "hello world", exit 0
```

## Build Constraints

- Compiler: `gcc -O0 -g -m32 -fno-stack-protector`
- Must link `malloc-2.7.2.c` (dlmalloc)
- Stack must be executable (`execstack --set-execstack stor`)
- Available libraries: `-lssl -lcrypto` (OpenSSL), `-lsodium` (libsodium)
- Target: 32-bit x86 on Ubuntu 18.04

## Submission

Push your `build/` directory (containing `stor.c`, `Makefile`, and `malloc-2.7.2.c`) to your team's GitHub repo. The CI pipeline will build and test automatically.
