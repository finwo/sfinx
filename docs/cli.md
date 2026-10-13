# sfinx command line

`sfinx` is one binary that dispatches on its first argument. Build it with
`make`; the binary lands at `build/$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)/sfinx`.

## Quick start

```
$ sfinx generate -o demo.key
$ sfinx sign   -k demo.key -m "hello sfinx" -o demo.sig
$ sfinx verify -k demo.key -S demo.sig -m "hello sfinx"
OK
```

`generate` writes one file holding the seed and its public key. `sign` picks a
random path of 32 bytes, so the same message signs differently every time.
`verify` prints `OK` or `FAIL`.

## Commands

- `sfinx seed [length] [-o file] [--force]`: write `length` random seed bytes, default 32, to stdout or a file.
- `sfinx generate [length] [-L hash] [-p path-len] [--out-fmt fmt] [--single] [-o file] [-F]`: generate a seed and derive its public key. `--out-fmt hdr` writes one combined file, `raw` and `hex` write a key file and a `.pub` file beside it. Stdout carries the seed alone.
- `sfinx printkey -k file [-L hash] [-p path-len] [--in-fmt fmt] [--out-fmt fmt] [--single] [-o file] [--public-only] [--force]`: read a key file, derive the public key from the seed, and re-encode it. `--in-fmt` defaults to auto-detect, `--out-fmt` to `hdr`. `--public-only` drops the seed.
- `sfinx sign -k keyfile [-L hash] [--single | -p path-len | -P path] [-m message | -M message-file] [--key-fmt fmt] [--sig-fmt fmt] [-o file] [-F]`: sign a message and write the signature. `--key-fmt` defaults to auto-detect with a `raw` seed fallback, `--sig-fmt` to `hex` on stdout and `raw` to a file.
- `sfinx verify -k keyfile [-L hash] [-p path-len] [-s signature | -S signature-file] [-m message | -M message-file] [--key-fmt fmt] [--sig-fmt fmt]`: verify a signature and print `OK` or `FAIL`. `--key-fmt` defaults to auto-detect with a `rawpub` fallback, `--sig-fmt` to auto-detect with a `raw` fallback.
- `sfinx help` and `sfinx version`.

`-h/--help` on any command prints its options.

## Hashing and paths

- `-L hash`: hash size, one of `224`, `256`, `384`, `512`. Default `256`.
- `-p path-len`: the path length. `sign` draws a random path that long, `generate` and `printkey` derive the public key for it, `verify` cross-checks it against the signature.
- `-P path`: use an explicit path, as hex.
- `--single`: single-key mode (`N = 0`), one WOTS key signing `H(message)` for a seed.
- `-F`, `--force`: overwrite existing output files.

`--single` is mutually exclusive with `-p` and `-P`. It is small and fast, but
one-time: signing two different messages with the same seed destroys
unforgeability, so use a fresh seed per message. `verify` takes no flag and
reads the mode from the signature.

## File formats

A key file carries a seed, a public key, or both. A signature file carries a
signature. The encode and decode code lives in the library, so any program using
sfinx reads and writes the same files.

Key and signature formats (`--key-fmt`, `--sig-fmt`, `--in-fmt`, `--out-fmt`):

- `hdr`: text, self-detecting. Lines are `hash:`, `seed:`, `public-key:`, `path-len:`, and `signature:`. `path-len:` is decimal and accompanies a public key, the rest are hex.
- `raw`: bare bytes. A key seed is bare seed bytes, a signature is bare signature bytes.
- `hex`: lowercase hex, one line.
- `rawpub`: a bare public key, `L` bytes. Explicit only.
- `hexpub`: a public key as lowercase hex. Explicit only.

Auto-detect (a null or omitted format) recognises `hdr` and `hex` by looking at
the content. `raw`, `rawpub`, and `hexpub` are never guessed; name them
explicitly.

`verify` reads the path length from the signature. Only `hdr` records one, and a
recorded length is cross-checked, naming a mismatch instead of reporting `FAIL`.

The wire layout of the signature itself, including `E4M4(N)` and the path, is in
`scheme.md`.
