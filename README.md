# sfinx

<small>a small, stateless, hash-based signing library and CLI in C</small>

sfinx signs data with a SPHINCS+-inspired scheme built from hash chains and a
tree you never build. The secret is one seed. The public key is a single hash.
Nothing is stored between signatures, and one keypair verifies any tree depth.

- No state, no counters, no state file.
- The seed is any byte string, up to 64 MiB. Random bytes are recommended, a passphrase is allowed.
- `L` and the tree depth are runtime values, so the same seed works with any hash size.
- Hashing is SHA3/SHAKE from `finwo/keccak-fast`, runtime-dispatched and batched.
- The library is C99 with POSIX calls and depends only on libc plus the hash core.

## Quick start

    make
    BIN=build/$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)/sfinx

    $BIN generate -o demo.key
    $BIN sign   -k demo.key -p 32 -m "hello sfinx" -o demo.sig
    $BIN verify -k demo.key -S demo.sig -m "hello sfinx"

`generate` writes one file with the seed and its public key. `sign` picks a
random path of 32 bytes, so the same message signs differently every time.
`verify` prints `OK`. Run `$BIN help` or `$BIN <command> --help` for every
option.

## How it works

Think of sfinx as a tree you never build. The public key is a hash, and below it
sit subtrees whose leaves are one-time signature keys. Nothing is stored: every
key is derived from the seed plus the path that reaches it.

- The signer picks a random path. It is the randomizer, so signing the same message twice lands on different one-time keys.
- The bottom key signs `H(path | message)`. Each key above it signs the root of the subtree below, and the top subtree root is the public key.
- Each one-time key is a Winternitz chain set with a checksum, so no chain can be run backward.
- Each subtree parent is hashed together with its position, so a node cannot be replayed at another depth or in another subtree.

A signature is a proof that you can produce the path to a given root, with no
secret kept between signatures. The idea is in `docs/idea.md`, and the formulas
are in `docs/scheme.md`.

## Single-key mode

`--single` collapses the tree to one one-time key (`N = 0`). It is small and
fast, but one-time: signing two different messages with the same seed destroys
unforgeability, so use a fresh seed per message. `verify` reads the mode from
the signature and needs no flag.

## Embedding

The library is `src/sfinx.c`, `src/keypair.c`, and `src/fmt/*.c`, listed in
`export.mk`. Compile those plus the `finwo/keccak-fast` sources and include
`<finwo/sfinx.h>`. No CLI, argparse, or util code is reachable from the library;
`test/test_embed.sh` builds exactly that set.

pthread is optional. The bundled CLI links it and runs the subtree build on a
worker pool. The library manifest does not, so a consumer opts in.

## Docs

- `docs/idea.md`: the rough idea, the glossary, and how the pieces fit.
- `docs/scheme.md`: the precise scheme, the formulas, and pseudocode.
- `docs/cli.md`: the command reference and the key and signature file formats.
