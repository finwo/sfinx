# sfinx

<small>sphincs+ inspired data signing library</small>

## Rough idea

- Glossary:
  - `L`: hash output size in bytes (32 for a 256-bit hash).
  - `H`: the hash function.
  - `w`: Winternitz chain length (256, so one chain digit is one byte).
  - `len1`: message chains (`= L`).
  - `len2`: checksum chains (`= 2`).
  - `c`: chains per WOTS (`= len1 + len2 = 34`).
  - `b`: bits per subtree (8, one path byte, so 256 leaves).
  - `N`: path length in bytes (`L` recommended). `N` subtrees and `N` WOTS keys for `N >= 1`.
  - `mask`: a node's depth in bits.
  - `layer`: subtree index, `= mask / 8`.
  - `org`: what the bottom WOTS signs, `= H(path | message)`, so the same message on a different path signs a different value.
  - `E4M4`: the log-ish length byte, 4-bit exponent then 4-bit mantissa. Exponent `0` is the mantissa (0..15); for exponent `E >= 1` the value is `(16 + mantissa) << (E-1)`, so `0x10` is 16, `0x20` is 32, `0x30` is 64, and each exponent step doubles.

- Tree:
  - Binary, built as `N` stacked subtrees of height `b = 8`.
  - Every subtree leaf is a WOTS public key.
  - Every subtree root is a hash, never a signature.
  - The public key is the top subtree root, with no WOTS above it. This matches SPHINCS+, whose key is `(PK.seed, PK.root)`.
  - The WOTS at layer `k` signs the root of subtree `k`. The bottom WOTS (layer `N`) has no subtree below it and signs `org`.
  - `N = 0` is the special case: no subtrees, and the public key is the layer-0 WOTS pubkey itself.

- Merkle hash:
  - Keyed by the parent's position, `H(mask | cidr(path, mask) | left | right)`.
  - `mask` is the parent's depth in bits, so nodes at different depths in the same subtree stay distinct.
  - `left` and `right` are ordered by the path bit, not by value.
  - Keying moves the tree from collision resistance to second-preimage resistance, so a 256-bit hash is not silently halved.

- Path:
  - The signer picks a random path of `N` bytes. It is the randomizer, so it never derives from the message.
  - `path[0]` is near the root, `path[N-1]` selects the bottom leaf.
  - One path byte selects a leaf in one subtree. Bit 7 (MSB) is the decision nearest the subtree root, bit 0 (LSB) is the decision at the leaf.

- WOTS:
  - Pre-image: `SHAKE256(seed | layer | cidr(path, 8*layer))`, `c * L = 1088` bytes, split into `c` chains of `L` bytes.
  - Chain `i` signs digit `i` by hashing its pre-image `digit[i]` times.
  - Digits `0..L-1`: the `L` bytes of the signed value (a subtree root, or `org` at the bottom).
  - Digits `L..c-1`: the checksum `C = sum(255 - digit[i])`, big-endian in 2 bytes.
  - Proof: `c` values, `c * L = 1088` bytes.
  - Pubkey: `H(chain_end[0] | ... | chain_end[c-1])`, chain end = pre-image hashed `w = 256` times.

- Signing:
  - Output the path length, E4M4 encoded (`0x00..0x0F` = 0..15, `0x10..0x1F` = 16..31, `0x20..0x2F` = 32..62, `0x30..0x3F` = 64..124, and so on).
  - `N = 0`: output the single WOTS proof for `org`. No path, no subtrees.
  - `N >= 1`: output the random path, then walk bottom up. At each subtree, output the WOTS proof for the path key, then the `b = 8` Merkle neighbours in verification order: LSB (deepest) first, up to MSB (subtree root) last.

- Signature layout:
  - `N = 0`: `1` byte length, then `c * L` bytes WOTS proof.
  - `N >= 1`: `1` byte length, `N` bytes path, then `N` times `c * L` bytes WOTS proof followed by `b * L` bytes Merkle neighbours (LSB first).

- Verifying:
  - Read the length. When `N = 0`, `org = H(message)`, otherwise read the path and recompute `org = H(path | message)`.
  - Advance each of the `c` proof values to `w = 256`, hash the chain ends into the WOTS pubkey, and check the checksum chains.
  - `N = 0`: compare the WOTS pubkey directly to the public key.
  - `N >= 1`: hash up to the subtree root one level at a time, consuming one neighbour and the matching path bit per step, LSB first. Repeat with the next WOTS up, until the top subtree root is compared to the public key.

- Wire order:
  - Numbers are MSB first, matching human notation: the E4M4 length, the path bytes (top byte first), and the checksum (high byte first).
  - The Merkle neighbour list is a sequence, not a number, so it follows the verification algorithm: LSB (deepest) first, MSB (top) last.

- Size and cost:
  - `size(0) = 1 + c * L`, `size(N) = 1 + N + N*(c*L) + N*(b*L)` for `N >= 1`.
  - `keygen(N)`: `c * w` hashes for `N = 0`, `2^b * c * w` hashes for `N >= 1`.
  - `sign(N)`: `c * w` hashes for `N = 0`, `N * 2^b * c * w` hashes for `N >= 1`.

| N  | WOTS | subtrees | size     | keygen | sign hashes |
|---:|-----:|---------:|---------:|-------:|------------:|
|  0 |    1 |        0 |  1,089 B |   8.7k |        8.7k |
|  1 |    1 |        1 |  1,346 B |   2.2M |        2.2M |
| 16 |   16 |       16 | 21,521 B |   2.2M |       35.7M |
| 32 |   32 |       32 | 43,041 B |   2.2M |       71.3M |

- Why the checksum:
  - Any increased digit decreases `C`.
  - An attacker can only hash chains forward, so increasing a message digit forces a checksum chain backward, which needs a preimage.
  - `len2 = 2` because `len1 * (w-1) = 32 * 255 = 8160` fits in 2 base-256 bytes.

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

The bottom WOTS has no subtree below it, so it signs `org = H(path | message)`.

`N = 0` collapses the whole thing: no subtrees, and the public key is a single
WOTS key.

### The path

The signer picks a random path of `N` bytes. It is the randomizer, so it never
derives from the message, and signing the same message twice lands on different
keys.

- `path[0]` is near the root, `path[N-1]` selects the bottom leaf.
- One path byte selects a leaf in one subtree, MSB first.
- A one-time key is fully named by `(layer, cidr(path, 8*layer))`.

### WOTS

Each key is a Winternitz one-time signature over an `L`-byte value.

- Pre-image: `SHAKE256(seed | layer | cidr(path, 8*layer))`, `c * L = 1088` bytes, split into `c = 34` chains of `L` bytes.
- Chain `i` signs digit `i` by hashing its pre-image `digit[i]` times.
- The first `L` digits are the signed value. The last `len2 = 2` digits are the checksum `C = sum(255 - digit[i])`.
- The pubkey is `H(chain_end[0] | ... | chain_end[c-1])`, where a chain end is the pre-image hashed `w = 256` times.

The checksum is what stops a chain from being reversed. Increasing any digit
decreases `C`, and the attacker can only hash forward, so a checksum chain would
have to run backward, which needs a preimage.

### The Merkle tree

Each subtree is a plain binary hash tree, but the hash is keyed by position:

```
H(mask | cidr(path, mask) | left | right)
```

`mask` is the depth of the node being computed, so no node hash can be replayed
at another depth or in another subtree. Keying means the tree rests on
second-preimage resistance instead of collision resistance, so a 256-bit hash
is not silently cut in half.

### Reading the path

`cidr(path, mask)` is a bit mask. It keeps the top `mask` bits and zeroes the
rest, the way a netmask does: `255.255.255.255/24` becomes `255.255.255.0`, and
`/25` becomes `255.255.255.128`. Here it trims the path to the depth we are at.

### Verifying

Verification walks from the bottom up.

- Read the length, then the path.
- Recompute `org = H(path | message)`.
- Advance each of the `c` proof values to `w = 256`, hash the chain ends into the WOTS pubkey, and check the checksum digits.
- Hash up the `b = 8` Merkle neighbours to this subtree root, one level at a time, LSB first.
- Repeat with the next WOTS up, each one signing the subtree root below it.
- The last subtree root is the public key.

When `N = 0` there is nothing to climb, so the WOTS pubkey is compared to the
public key directly.

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
// A one-time key is named by (layer, path prefix).
pre_image(seed, layer, path) =
    SHAKE256(seed | layer | cidr(path, 8 * layer), c * L)

// L message digits, then the 2 checksum digits.
digits(value) = value[0..L-1] ++ be16(sum(255 - value[i]))

// Keyed subtree parent.
parent(mask, path, left, right) = H(mask | cidr(path, mask) | left | right)

// WOTS
wots_sign(seed, layer, path, value):
    pre = pre_image(seed, layer, path)
    d   = digits(value)
    return [ pre[i] hashed d[i] times, for i in 0..c-1 ]

wots_pubkey(proof, value):
    d    = digits(value)
    ends = [ proof[i] hashed (w - d[i]) times, for i in 0..c-1 ]
    return H(ends[0] | ... | ends[c-1])
```

Signing, with `value` starting at `org` and climbing one subtree per round:

```c
sign(seed, message, N):
    path  = random(N bytes)
    value = (N == 0) ? H(message) : H(path | message)

    out = E4M4(N)

    if N == 0:
        out += wots_sign(seed, 0, path, value)
        return out

    out += path

    for k = N down to 1:
        out   += wots_sign(seed, k, path, value)   // signs the value from below
        out   += auth(subtree = k-1, path)         // 8 neighbours, LSB first
        value  = root(subtree = k-1, path)         // what the next round signs

    return out
```

Verifying:

```c
verify(pubkey, message, sig):
    N = E4M4_decode(sig)

    if N == 0:
        return wots_pubkey(read_proof(), H(message)) == pubkey

    path  = read_path()
    value = H(path | message)

    for k = N down to 1:
        pub = wots_pubkey(read_proof(), value)     // proof for layer k
        if k == 1:
            return hash_up(pub, read_auth()) == pubkey   // root of subtree 0
        value = hash_up(pub, read_auth())          // root of subtree k-1

    return false
```
