sfinx
=====

> Stateless hash-based signatures

Signing uses a SPHINCS+-inspired scheme built on hash chains over a merkle tree
that is never stored. Every key is derived from the seed and the path that
reaches it, so there is no counter and no state file to keep in sync. The secret
is a seed, and the public key is a single hash.

The hash size and the path length are arguments rather than build options, and
the top of the tree is fixed, so one keypair covers every path length at a given
hash size.

This project makes use of [dep](https://git.finwo.net/app/dep) to manage its
dependencies and exports.

Features
--------

- The seed is any byte string up to 64 MiB, random bytes recommended
- Hash size and path length are chosen per call
- Hashing comes from [keccak-fast](https://git.finwo.net/lib/keccak-fast.c),
  dispatched per CPU and batched
- C99 with POSIX calls, needing only libc and the hash core

Summary
-------

```
usage: sfinx <command> [options]

commands:
  version      Show the version
  verify       Verify a message signature
  sign         Sign a message
  seed         Generate a random seed
  printkey     Print or convert a key file
  help         Show this help
  generate     Generate a seed and its public key
```

Run `sfinx help` or `sfinx <command> --help` for the options of a single
command. The full reference, including the key and signature file formats, is
in [docs/cli.md](docs/cli.md).

Building
--------

```sh
make
```

The binary lands in a target-specific directory, so on linux-x86_64 it ends up
at `build/linux-x86_64/sfinx`.

Usage
-----

### Signing and verifying

```sh
sfinx generate -o demo.key
sfinx sign   -k demo.key -p 32 -m "hello sfinx" -o demo.sig
sfinx verify -k demo.key -S demo.sig -m "hello sfinx"
```

`generate` writes one file holding the seed and its public key. `sign` draws a
random 32-byte path, so the same message signs differently every time, and
`verify` prints `OK` or `FAIL`. At these defaults a signature is 43,042 bytes.

The path is the randomizer and must not repeat across messages. Drawn at random
it collides after roughly `2^128` signatures, which is what makes a one-time
construction usable many times.

### Single-key mode

```sh
sfinx generate --single -o single.key
sfinx sign -k single.key --single -m "one shot" -o single.sig
```

`--single` collapses the tree to a single Winternitz key signing `H(message)`.
Signatures drop to 1,090 bytes, but the mode really is one-time: signing two
different messages under one seed destroys unforgeability, so use a fresh seed
per message. It has its own public key, and `verify` reads the mode from the
signature rather than a flag.

Embedding
---------

```sh
dep add finwo/sfinx https://git.finwo.net/app/sfinx/archives/heads/main.tar.gz
dep install
```

After that, simply add `include lib/.dep/config.mk` in your makefile and include
the header file by adding `#include <finwo/sfinx.h>`. Installing pulls in the
hash core as well.

The export covers `src/sfinx.c`, `src/keypair.c` and `src/fmt/*.c`. No CLI,
argparse or util code is reachable from the library, and `test/test_embed.sh`
builds exactly that set.

pthread is optional. The bundled CLI links it and spreads the subtree build over
a worker pool, while the library export leaves it to the consumer. The output is
identical either way.

Benchmark
---------

```sh
make bench
make bench BENCH_ARGS='-L 512 -p 8 -n 5'
```

This builds `test/bench.c` both threaded and sequential, then times key
derivation, signing and verification for both the tree and the single key. `-L`
sets the hash size (default 256), `-p` the path length in bytes (default 32) and
`-n` the repetitions, of which the best is reported (default 3).

Testing
-------

If you want to run the project's tests, simply run `make test` to build and run
the test binaries along with the shell suites.

Docs
----

- [docs/idea.md](docs/idea.md): the rough idea, the glossary, and how it fits
- [docs/scheme.md](docs/scheme.md): the precise scheme, formulas and pseudocode
- [docs/cli.md](docs/cli.md): the command reference and the file formats
- [docs/api.md](docs/api.md): the C API, generated from `src/sfinx.h`

License
-------

sfinx source code is available under the [FGPL License](LICENSE.md)
