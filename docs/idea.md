# sfinx, the idea

`sfinx` is a stateless, SPHINCS+-inspired hash-based signature. Think of it as a
tree you never build. The public key is a hash, and below it sit subtrees whose
leaves are one-time signature keys. Nothing is stored: every key is derived from
the seed plus the path that reaches it, so the whole keyspace is a function
rather than a pile of bytes on disk.

This document is the intuition and the vocabulary. The precise formulas are in
`scheme.md`.

## Glossary

- `L`: hash output size in bytes, one of `28`, `32`, `48`, `64` (SHA3-224, SHA3-256, SHA3-384, SHA3-512). Every example uses `32`.
- `H`: the hash function, `SHA3-8*L`.
- `seed`: the secret, any byte string up to 64 MiB. Random bytes are recommended, a passphrase is allowed.
- `w`: Winternitz chain length (256, so one chain digit is one byte).
- `len1`: message chains (`= L`).
- `len2`: checksum chains (`= 2`).
- `c`: chains per WOTS (`= len1 + len2 = L + 2`).
- `b`: bits per subtree (8, one path byte, so 256 leaves).
- `N`: path length in bytes, E4M4-representable. `N` subtrees and `N` WOTS keys for `N >= 1`.
- `bitlen`, `mask`: the sub-byte part of a node's position. `bitlen` is the bit count (0..8), `mask` one byte holding those bits in its top `bitlen` positions with the low `8 - bitlen` bits zeroed.
- `layer`: which WOTS key in the stack, `1..N`. A layer-`k` key is named by `E4M4(N)` and the first `k` path bytes.
- `org`: what the bottom WOTS signs, `= H(path | message)`, so the same message on a different path signs a different value. With no path, `org = H(message)`.
- `E4M4`: the log-ish length byte, 4-bit exponent then 4-bit mantissa. Exponent `0` is the mantissa (0..15); for exponent `E >= 1` the value is `(16 + mantissa) << (E-1)`, so `0x10` is 16, `0x20` is 32, `0x30` is 64, and each exponent step doubles.

## The shape

The tree is binary, stacked as `N` subtrees of height `b = 8`.

- Each subtree has 256 leaves, and each leaf is a WOTS public key.
- Each subtree root is only a hash of its children.
- The WOTS at layer `k` signs the root of the subtree below it.
- The bottom WOTS has no subtree below it, so it signs `org = H(path | message)`.
- The public key is the top subtree root, with nothing above it.
- The path length is part of every key derivation, so each depth has its own public key.

`N = 0` collapses the whole thing: no subtrees, no path, and the public key is a
single WOTS key over `org = H(message)`.

## The path

The signer picks a random path of `N` bytes. It is the randomizer, so it never
derives from the message, and signing the same message twice lands on different
keys.

- `path[0]` is the most significant byte (near the root), `path[N-1]` the least significant (near the message).
- One path byte selects a leaf in one subtree, most significant bit first.
- A one-time key is named `E4M4(N) | path[0..k-1]` for a layer-`k` key. No mask, because the path is already split into bytes and SHA3 resists length extension.
- `N` must be E4M4-representable, because the signature carries it as an E4M4 byte.

## WOTS

Each key is a Winternitz one-time signature over an `L`-byte value.

- Pre-image: `SHAKE256(seed | E4M4(N) | path[0..k-1])` for a layer-`k` key, `c * L` bytes, split into `c = L + 2` chains of `L` bytes.
- Chain `i` signs digit `i` by hashing its pre-image `digit[i]` times.
- The first `L` digits are the signed value. The last `len2 = 2` digits are the checksum `C = sum(255 - digit[i])`.
- The pubkey is `H(chain_end[0] | ... | chain_end[c-1])`, where a chain end is the pre-image hashed `w = 256` times.

The checksum is what stops a chain from being reversed. Increasing any digit
decreases `C`, and an attacker can only hash forward, so a checksum chain would
have to run backward, which needs a preimage. `len2 = 2` because `L * 255` fits
in two base-256 bytes for every supported `L` (7,140 at `L = 28`, 16,320 at
`L = 64`).

## The Merkle tree

Each subtree is a plain binary hash tree, but the hash is keyed by position:

```
H(bitlen | mask | prefix | left | right)
```

`prefix` is `E4M4(N)` plus the byte-aligned path prefix above the node. `bitlen`
(0..8) and `mask` carry the sub-byte remainder, so a node at depth `8k + d` is
named by `k` path bytes plus `d` bits. `mask` keeps the top `bitlen` bits and
zeroes the rest, so `0xff` and `0xfc` are the same prefix at `bitlen = 4`. The
prefix itself is never padded. No node hash can be replayed at another depth or
in another subtree, so the tree rests on second-preimage resistance instead of
collision resistance. An `L`-byte hash is not silently cut in half.

## Signing

- Output `E4M4(N)`, the random path, then `E4M4(L)`, then the proof data.
- `N = 0`: no path, just the single WOTS proof for `org = H(message)`.
- `N >= 1`: walk bottom up. At each subtree, output the WOTS proof for the path key, then the `b = 8` Merkle neighbours in verification order: LSB (deepest) first, up to MSB (subtree root) last.

## Verifying

Verification walks from the bottom up.

- Read `N`, then the path, then `L`, and check `L` against the public key length.
- Recompute `org = H(path | message)`.
- Advance each of the `c` proof values to `w = 256`, hash the chain ends into the WOTS pubkey, and check the checksum digits.
- Hash up the `b = 8` Merkle neighbours to this subtree root, one level at a time, LSB first.
- Repeat with the next WOTS up, each one signing the subtree root below it.
- The last subtree root is the public key.

When `N = 0` there is nothing to climb, so the WOTS pubkey over `org = H(message)`
is compared to the public key directly.

## Wire order

- Numbers are MSB first, matching human notation: `E4M4(N)`, `E4M4(L)`, the path bytes (most significant, near the root, first), the `bitlen` and `mask` bytes, and the checksum (high byte first).
- The Merkle neighbour list is a sequence, not a number, so it follows the verification algorithm: LSB (deepest) first, MSB (top) last.

## How many times can a seed sign?

A key is named `E4M4(N) | path[0..k-1]`, which fixes what it signs: the subtree
root beneath it when `k < N`, `org` when `k = N`. Two signatures share a key
only at the same `N` and the same prefix.

The limit is therefore a path collision: same `N`, same path, different message.
The bottom key is named by the full path, so at the default `N = 32` the
collision space is 256 bits.

- Random path, what the library does: the birthday bound gives a 50 percent chance of one collision at about `2^128` signatures.
- Tracked paths, where the caller never repeats one: the limit is the path space, `2^256`. The library tracks nothing, so the caller builds this.
- Single-key mode (`N = 0`): one key signs `H(message)` every time, so two messages break it.

## No state

A signature is a proof that you can produce the path to a given root, not a
record that you did.

## Cost and parallelism

- `size(0) = 2 + c * L`, `size(N) = 2 + N + N*(c*L) + N*(b*L) = 2 + N + N*(L + 10)*L` for `N >= 1`.
- `keygen(N)`: `c * w` hashes for `N = 0`, `2^b * c * w` hashes for `N >= 1`.
- `sign(N)`: `c * w` hashes for `N = 0`, `N * 2^b * c * w` hashes for `N >= 1`.

| N  | WOTS | subtrees | size     | keygen | sign hashes |
|---:|-----:|---------:|---------:|-------:|------------:|
|  0 |    1 |        0 |  1,090 B |   8.7k |        8.7k |
|  1 |    1 |        1 |  1,347 B |   2.2M |        2.2M |
| 16 |   16 |       16 | 21,522 B |   2.2M |       35.7M |
| 32 |   32 |       32 | 43,042 B |   2.2M |       71.3M |

Hash chains are independent, so the library runs the 256-leaf subtree build on
a worker pool when compiled with pthread support, and sequentially when it is
not. The switch is compile-time only, and the output is identical either way, so
it is invisible in the signature.
