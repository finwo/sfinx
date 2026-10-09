# sfinx

<small>sphincs+ inspired data signing library</small>

## Rough idea

- Glossary:
  - `L`: hash output size in bytes, one of `28`, `32`, `48`, `64` (SHA3-224, SHA3-256, SHA3-384, SHA3-512). Every example here uses `32`.
  - `H`: the hash function, `SHA3-8*L`.
  - `seed`: the secret, any byte string up to 64 MiB. Random bytes are recommended, a passphrase is allowed.
  - `w`: Winternitz chain length (256, so one chain digit is one byte).
  - `len1`: message chains (`= L`).
  - `len2`: checksum chains (`= 2`).
  - `c`: chains per WOTS (`= len1 + len2 = L + 2`).
  - `b`: bits per subtree (8, one path byte, so 256 leaves).
  - `N`: path length in bytes, E4M4-representable. `N` subtrees and `N` WOTS keys for `N >= 1`.
  - `bitlen`, `mask`: the sub-byte part of a node's position. `bitlen` is the bit count (0..8), `mask` one byte holding those bits in its top `bitlen` positions with the low `8 - bitlen` bits zeroed.
  - `layer`: which WOTS key in the stack, `1..N`. A layer-`k` key is named by the first `k` path bytes.
  - `org`: what the bottom WOTS signs, `= H(path | message)`, so the same message on a different path signs a different value. With no path, `org = H(message)`.
  - `E4M4`: the log-ish length byte, 4-bit exponent then 4-bit mantissa. Exponent `0` is the mantissa (0..15); for exponent `E >= 1` the value is `(16 + mantissa) << (E-1)`, so `0x10` is 16, `0x20` is 32, `0x30` is 64, and each exponent step doubles.

- Tree:
  - Binary, built as `N` stacked subtrees of height `b = 8`.
  - Every subtree leaf is a WOTS public key.
  - Every subtree root is a hash, never a signature.
  - The public key is the top subtree root, with no WOTS above it. This matches SPHINCS+, whose key is `(PK.seed, PK.root)`.
  - The WOTS at layer `k` signs the root of subtree `k`. The bottom WOTS (layer `N`) has no subtree below it and signs `org`.
  - The top subtree root is the same for every `N >= 1`, so one keypair verifies any tree depth.
  - `N = 0` is the single-key mode: no subtrees, and the public key is the layer-0 WOTS pubkey itself.

- Merkle hash:
  - Keyed by the parent's position, `H(bitlen | mask | prefix | left | right)`.
  - `bitlen` is one byte, 0..8, the number of sub-byte bits in the position. `mask` holds those bits in its top `bitlen` positions, low bits zeroed, so `bitlen = 4` gives `0xff` and `0xfc` the same `0xf0`.
  - `prefix` is the byte-aligned path prefix above the parent.
  - `left` and `right` are ordered by the path bit, not by value.
  - Keying moves the tree from collision resistance to second-preimage resistance, so an `L`-byte hash is not silently halved.

- Path:
  - The signer picks a random path of `N` bytes. It is the randomizer, so it never derives from the message.
  - `path[0]` is the most significant byte (near the root), `path[N-1]` the least significant (near the message).
  - One path byte selects a leaf in one subtree. The most significant bit (bit 7) is the decision nearest the subtree root, the least significant bit (bit 0) the decision at the leaf.
  - `N` must be E4M4-representable, because the signature carries it as an E4M4 byte.

- WOTS:
  - Pre-image: `SHAKE256(seed | path[0..k-1])` for a layer-`k` key, `c * L` bytes, split into `c` chains of `L` bytes. The path is truncated, not masked, and there is no layer byte, because SHA3 has no length extension.
  - Chain `i` signs digit `i` by hashing its pre-image `digit[i]` times.
  - Digits `0..L-1`: the `L` bytes of the signed value (a subtree root, or `org` at the bottom).
  - Digits `L..c-1`: the checksum `C = sum(255 - digit[i])`, big-endian in 2 bytes.
  - Proof: `c` values, `c * L` bytes.
  - Pubkey: `H(chain_end[0] | ... | chain_end[c-1])`, chain end = pre-image hashed `w = 256` times.

- Signing:
  - Output `E4M4(N)`, the random path, then `E4M4(L)`, then the proof data.
  - `N = 0`: no path, just the single WOTS proof for `org = H(message)`.
  - `N >= 1`: walk bottom up. At each subtree, output the WOTS proof for the path key, then the `b = 8` Merkle neighbours in verification order: LSB (deepest) first, up to MSB (subtree root) last.

- Signature layout:
  - `E4M4(N)` (1 byte) `|` `path` (`N` bytes) `|` `E4M4(L)` (1 byte) `|` data.
  - `N = 0`: data is one WOTS proof, `c * L` bytes.
  - `N >= 1`: data is `N` rounds of `c * L` bytes WOTS proof followed by `b * L` bytes Merkle neighbours (LSB first).

- Verifying:
  - Read `N`, then the path, then `L`, and check `L` against the public key length.
  - When `N = 0`, `org = H(message)`, otherwise recompute `org = H(path | message)`.
  - Advance each of the `c` proof values to `w = 256`, hash the chain ends into the WOTS pubkey, and check the checksum chains.
  - `N = 0`: compare the WOTS pubkey directly to the public key.
  - `N >= 1`: hash up to the subtree root one level at a time, consuming one neighbour and the matching path bit per step, LSB first. Repeat with the next WOTS up, until the top subtree root is compared to the public key.

- Wire order:
  - Numbers are MSB first, matching human notation: `E4M4(N)`, `E4M4(L)`, the path bytes (most significant, near the root, first), the `bitlen` and `mask` bytes, and the checksum (high byte first).
  - The Merkle neighbour list is a sequence, not a number, so it follows the verification algorithm: LSB (deepest) first, MSB (top) last.

- Size and cost:
  - `size(0) = 2 + c * L`, `size(N) = 2 + N + N*(c*L) + N*(b*L) = 2 + N + N*(L + 10)*L` for `N >= 1`.
  - `keygen(N)`: `c * w` hashes for `N = 0`, `2^b * c * w` hashes for `N >= 1`.
  - `sign(N)`: `c * w` hashes for `N = 0`, `N * 2^b * c * w` hashes for `N >= 1`.

| N  | WOTS | subtrees | size     | keygen | sign hashes |
|---:|-----:|---------:|---------:|-------:|------------:|
|  0 |    1 |        0 |  1,090 B |   8.7k |        8.7k |
|  1 |    1 |        1 |  1,347 B |   2.2M |        2.2M |
| 16 |   16 |       16 | 21,522 B |   2.2M |       35.7M |
| 32 |   32 |       32 | 43,042 B |   2.2M |       71.3M |

- Why the checksum:
  - Any increased digit decreases `C`.
  - An attacker can only hash chains forward, so increasing a message digit forces a checksum chain backward, which needs a preimage.
  - `len2 = 2` because `L * 255` fits in 2 base-256 bytes for every supported `L` (7,140 at `L = 28`, 16,320 at `L = 64`).

- Parallelism:
  - Hash chains are independent, so the library runs them in parallel when it is compiled with pthread support, and sequentially when it is not.
  - Work is spread over a small worker pool sized to the machine's CPU count, and the switch is compile-time only. The output is identical either way, so it is invisible in the signature.

## How it works

Think of sfinx as a tree you never build. The public key is a hash, and below
it sit subtrees whose leaves are one-time signature keys. Nothing is stored:
every key is derived from the seed plus the path that reaches it, so the whole
keyspace is a function rather than a pile of bytes on disk.

### The shape

The tree is binary, stacked as `N` subtrees of height `b = 8`.

- Each subtree has 256 leaves, and each leaf is a WOTS public key.
- Each subtree root is only a hash of its children.
- The WOTS at layer `k` signs the root of the subtree below it.
- The public key is the top subtree root, with nothing above it. That is the SPHINCS+ shape.

Because the top subtree is fixed, its root is the same for every `N >= 1`, so
one keypair covers every tree depth. The bottom WOTS has no subtree below it, so
it signs `org = H(path | message)`.

`N = 0` collapses the whole thing: no subtrees, no path, and the public key is a
single WOTS key over `org = H(message)`.

### The path

The signer picks a random path of `N` bytes. It is the randomizer, so it never
derives from the message, and signing the same message twice lands on different
keys.

- `path[0]` is the most significant byte (near the root), `path[N-1]` the least significant (near the message).
- One path byte selects a leaf in one subtree, most significant bit first.
- A one-time key is named by the truncated path that reaches it, `path[0..k-1]` for a layer-`k` key. No mask and no layer byte, because the path is already split into bytes and SHA3 resists length extension.

### WOTS

Each key is a Winternitz one-time signature over an `L`-byte value.

- Pre-image: `SHAKE256(seed | path[0..k-1])` for a layer-`k` key, `c * L` bytes, split into `c = L + 2` chains of `L` bytes.
- Chain `i` signs digit `i` by hashing its pre-image `digit[i]` times.
- The first `L` digits are the signed value. The last `len2 = 2` digits are the checksum `C = sum(255 - digit[i])`.
- The pubkey is `H(chain_end[0] | ... | chain_end[c-1])`, where a chain end is the pre-image hashed `w = 256` times.

The checksum is what stops a chain from being reversed. Increasing any digit
decreases `C`, and the attacker can only hash forward, so a checksum chain would
have to run backward, which needs a preimage.

### The Merkle tree

Each subtree is a plain binary hash tree, but the hash is keyed by position:

```
H(bitlen | mask | prefix | left | right)
```

`prefix` is the byte-aligned path prefix above the node. `bitlen` (0..8) and
`mask` carry the sub-byte remainder, so a node at depth `8k + d` is named by
`k` path bytes plus `d` bits. `mask` keeps the top `bitlen` bits and zeroes the
rest, so `0xff` and `0xfc` are the same prefix at `bitlen = 4`. No node hash can
be replayed at another depth or in another subtree, so the tree rests on
second-preimage resistance instead of collision resistance. An `L`-byte hash is
not silently cut in half.

### Reading the path

The path is read one byte at a time, and a node is named by a prefix of it. The
prefix is truncated at a byte boundary, and the leftover bits travel as `bitlen`
and `mask`. Only the uncovered bits of the `mask` byte are zeroed, so the prefix
itself is never padded. SHA3 has no length extension, so `seed | prefix` cannot
be stretched into another prefix.

### Verifying

Verification walks from the bottom up.

- Read `N`, then the path, then `L`, and check `L` against the public key length.
- Recompute `org = H(path | message)`.
- Advance each of the `c` proof values to `w = 256`, hash the chain ends into the WOTS pubkey, and check the checksum digits.
- Hash up the `b = 8` Merkle neighbours to this subtree root, one level at a time, LSB first.
- Repeat with the next WOTS up, each one signing the subtree root below it.
- The last subtree root is the public key.

When `N = 0` there is nothing to climb, so the WOTS pubkey over `org = H(message)`
is compared to the public key directly.

### Why reuse is fine

The path is random, so every signature lands on a fresh set of one-time keys.
The upper keys only ever sign a fixed subtree root, and the bottom key signs
`org`, which changes with the path. No key is ever asked to sign two different
values.

### No state

sfinx is stateless. There is no counter and no state file. A signature is a
proof that you can produce the path to a given root, and the virtual tree gives
a universal keyspace.

## Pseudocode

A sketch, not reference code.

```c
// A one-time key is named by the truncated path that reaches it.
pre_image(seed, prefix) = SHAKE256(seed | prefix, c * L)   // c = L + 2

// L message digits, then the 2 checksum digits.
digits(value) = value[0..L-1] ++ be16(sum(255 - value[i]))

// Keyed subtree parent: byte prefix plus the sub-byte remainder.
// mask keeps the top bitlen bits of the byte, low bits zeroed.
parent(bitlen, mask, prefix, left, right) =
    H(bitlen | mask | prefix | left | right)

// WOTS
single_sign(seed, prefix, value):
    pre = pre_image(seed, prefix)
    d   = digits(value)
    return [ pre[i] hashed d[i] times, for i in 0..c-1 ]

single_pubkey(proof, value):
    d    = digits(value)
    ends = [ proof[i] hashed (w - d[i]) times, for i in 0..c-1 ]
    return H(ends[0] | ... | ends[c-1])
```

Signing, with `value` starting at `org` and climbing one subtree per round:

```c
tree_sign(seed, message, N):
    path  = random(N bytes)
    value = (N == 0) ? H(message) : H(path | message)

    out = E4M4(N) | path | E4M4(L)

    if N == 0:
        out += single_sign(seed, "", value)
        return out

    for k = N down to 1:
        out   += single_sign(seed, path[0..k-1], value)  // the value from below
        out   += auth(subtree = k-1, path)               // 8 neighbours, LSB first
        value  = root(subtree = k-1, path)               // what the next round signs

    return out
```

Verifying:

```c
verify(pubkey, message, sig):
    N    = E4M4_decode(sig)
    path = read_path(N)
    L    = E4M4_decode(sig)

    if N == 0:
        return single_pubkey(read_proof(), H(message)) == pubkey

    value = H(path | message)

    for k = N down to 1:
        pub = single_pubkey(read_proof(), value)     // proof for layer k
        if k == 1:
            return hash_up(pub, read_auth()) == pubkey   // root of subtree 0
        value = hash_up(pub, read_auth())            // root of subtree k-1

    return false
```
