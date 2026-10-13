# sfinx scheme spec

This is the implementable specification. A compatible signer and verifier can be
written from this document alone. For the intuition, read `idea.md`; for the
command line and file formats, read `cli.md`.

`sfinx` is a stateless, SPHINCS+-inspired hash-based signature. The tree is
binary, stacked as `N` subtrees of height `b = 8`, with a Winternitz one-time
key (WOTS) at each subtree leaf. Every key is derived from the seed and the path
that reaches it, so the tree is never built or stored.

## Constants

| name    |       value | meaning                                                                            |
| :------ | ----------: | :--------------------------------------------------------------------------------- |
| `L`     | 28/32/48/64 | hash output size in bytes, from `sfinx_hash` (SHA3-224/256/384/512). Default `32`. |
| `len1`  |         `L` | message chains, one per byte of the signed value                                   |
| `len2`  |           2 | checksum chains                                                                    |
| `c`     |     `L + 2` | chains per WOTS key (`= len1 + len2`)                                              |
| `w`     |         256 | chain length, `1 << 8`, so one digit is one byte                                   |
| `b`     |           8 | subtree height in bits, so `1 << b = 256` leaves per subtree                       |
| `N`     |          32 | path length in bytes, E4M4-representable. Default `32`.                            |
| `layer` |      `1..N` | which WOTS key in the stack; layer-`k` is named by `E4M4(N)` and `k` path bytes    |

- `H` is `SHA3-8*L`, so SHA3-224/256/384/512, and returns `L` bytes.
- `SHAKE256(x)` is the XOF; the WOTS pre-image asks for `c * L = (L + 2) * L` bytes.
- The seed is any byte string up to `SFINX_SEED_LEN_MAX` (64 MiB), not a fixed length.
- `N` is bounded only by E4M4: any representable value up to `SFINX_PATH_LEN_MAX` (507904) is accepted.

## E4M4 length byte

`N` and `L` each travel as one byte called E4M4: high nibble is the exponent
`E`, low nibble is the mantissa `M`.

- `E == 0`: value = `M`, so `0x00..0x0F` = 0..15.
- `E >= 1`: value = `(16 + M) << (E - 1)`.
- Rows: `0x00..0x0F` = 0..15, `0x10..0x1F` = 16..31, `0x20..0x2F` = 32..62, `0x30..0x3F` = 64..124, doubling each exponent step.
- `N = 0` encodes as `0x00`, `N = 32` as `0x20`. `L` encodes as `0x1C` (28), `0x20` (32), `0x28` (48), `0x30` (64).

## Node position

A node is named by a path prefix, not a mask. WOTS keys sit at byte-aligned
depths, so their prefix is `E4M4(N)` plus a whole number of path bytes. Merkle
internals can sit at any depth, so their position is `prefix` bytes plus a
sub-byte remainder carried as `bitlen` (0..8) and `mask` (the partial byte, top
`bitlen` bits kept and the rest zeroed). Nothing else is zero-padded, because
SHA3 has no length extension, so `seed | prefix` cannot be confused with another
prefix.

## Path

- The signer draws `N` bytes from a CSPRNG. This is the randomizer and it is carried in the signature.
- `path[0]` is the most significant byte (near the root), `path[N-1]` the least significant (near the message).
- Each path byte navigates one subtree of height `b = 8`, most significant bit first: bit 7 is the decision nearest the subtree root, bit 0 the decision at the leaf.
- A WOTS key is named by `E4M4(N)` and the truncated path that reaches it: a layer-`k` key uses `E4M4(N) | path[0..k-1]`.
- `N` must be E4M4-representable, because `E4M4(N)` leads the signature.
- The library never draws the path. `sfinx_tree_sign` takes `path` as an argument, and `sfinx_random_bytes` is a helper the caller uses.

## WOTS

One WOTS key signs one `L`-byte value, derived from the seed, the path length
and the truncated path that reaches it.

Pre-image, `c * L = (L + 2) * L` bytes:

```
stream = SHAKE256(seed | E4M4(N) | path[0..k-1])    for a layer-k key
pre[i] = stream[i*L .. i*L + L-1]      for i in 0..c-1
```

- `E4M4(N)` is at a fixed offset and the prefix length gives `k`, so the key is a bottom key iff `k = N` and interior otherwise.
- `N = 0` is single mode: empty prefix, `stream = SHAKE256(seed)`.

Digits, from the `L`-byte `value`:

```
d[i]   = value[i]                      for i in 0..L-1
d[L]   = (C >> 8) & 0xff               where C = sum(255 - value[i])
d[L+1] = C & 0xff
```

`C` max is `L * 255`, which fits in two bytes for every supported `L` (7,140 at
`L = 28`, 16,320 at `L = 64`), so `len2 = 2`.

Chain and keys:

```
chain_i(x, 0) = x
chain_i(x, k) = H(chain_i(x, k-1))

proof[i] = chain_i(pre[i], d[i])                 sign
end[i]   = chain_i(pre[i], w)                    pubkey build
pubkey   = H(end[0] | end[1] | ... | end[c-1])
```

Verify a proof against a value: recompute the digits from the value, then
`end[i] = chain_i(proof[i], w - d[i])`, then the pubkey hash. An attacker can
only hash forward, so raising any `d[i]` lowers `C`, which forces a checksum
chain backward, which needs a preimage.

## Merkle subtree

Each subtree is binary with height `b = 8`, so 256 leaves, each leaf a WOTS
public key. The parent hash is keyed by the parent's position:

```
parent = H(bitlen (1) | mask (1) | prefix (p) | left (L) | right (L))
```

- For a node at depth `8k + d`, `prefix` is `E4M4(N) | path[0..k-1]`, so `p = k + 1`, and `bitlen` is `d`.
- `bitlen` is 0..8, the number of sub-byte bits in the position. `mask` holds those bits in its top `bitlen` positions with the low `8 - bitlen` bits zeroed, so a prefix has one encoding.
- `left` is the child reached by a 0 bit, `right` the child reached by a 1 bit.
- Keying by position is what moves the tree from collision resistance to second-preimage resistance.
- A leaf input is `c * L` bytes and a parent input `2 + p + 2L`, so the two coincide at `L*L + 2L` bytes, where `p = L*L - 2`. The verifier's walk is fixed by `N` and the subtree height, so a leaf is never read as a parent.

## Tree structure

- `N` subtrees, `0` top to `N-1` bottom, and `N` WOTS keys at layers `1..N`.
- `R_k` is the root of subtree `k`. `R_0` is the public key. `R_N := org`.
- WOTS at layer `k` signs `R_k`, so `k = N` signs `org` and `1 <= k <= N-1` signs `R_k`.
- `R_{k-1}` is the WOTS pubkey at layer `k` hashed up subtree `k-1` with its `b` neighbours. At `k = 1` that is the public key.
- `N >= 1`: the public key is `R_0`, the top subtree root, with no WOTS above it, matching SPHINCS+. `R_0` depends on the seed, `L` and `N`: one public key per length.
- `N = 0`: no subtrees and no path. The public key is the layer-0 WOTS pubkey over `SHAKE256(seed)`, and that key signs `org = H(message)`.

## org

- `N >= 1`: `org = H(path | message)`, so the same message on a different path signs a different value.
- `N = 0`: `org = H(message)`.

## Signature layout

```
offset       field       size
0            N           1 (E4M4)
1            PATH        N
1 + N        L           1 (E4M4)
2 + N        DATA        see below
```

- `N` is the path length, E4M4-encoded.
- `PATH` is `N` bytes, `path[0]` first.
- `L` is the hash size in bytes, E4M4-encoded, and must match the public key length.
- `N = 0`: `DATA` is one WOTS proof, `c * L` bytes.
- `N >= 1`: `DATA` is `N` rounds. Round `k` counts `N` down to `1` and holds the WOTS proof for layer `k` (`c * L` bytes), then the `b` neighbours of subtree `k-1` (`b * L` bytes), LSB (deepest) first.

Sizes:

- `size(0) = 2 + c * L = 2 + (L + 2) * L`
- `size(N) = 2 + N + N * (c + b) * L = 2 + N + N * (L + 10) * L`
- At `L = 32`: `size(0) = 1,090` and `size(N) = 2 + 1345 * N`.

## Signing

1. Draw `path`, `N` random bytes.
2. `org = H(path | message)` for `N >= 1`, else `H(message)`.
3. Emit `E4M4(N)`, then `path`, then `E4M4(L)`.
4. `N = 0`: emit the WOTS proof for layer 0 over `org`. Done.
5. `N >= 1`: for `k = N` down to `1`: emit the WOTS proof for layer `k` over `R_k` (`R_N = org`), then the `b` neighbours of subtree `k-1` along the path, LSB first.

## Verifying

1. Read `E4M4(N)` and decode `N`.
2. Read the `N`-byte `path`, then read `E4M4(L)` and check it against the public key length.
3. `N = 0`: read one WOTS proof, rebuild its pubkey over `H(message)`, compare to the public key.
4. `N >= 1`: compute `org = H(path | message)`.
5. Set `value = org`. For `k = N` down to `1`:
   - read a WOTS proof and rebuild its pubkey over `value`;
   - read `b` neighbours and hash the pubkey up subtree `k-1` to its root, LSB first;
   - if `k == 1`, that root is the public key, so compare and finish;
   - else set `value` to that root.

## Sizes and hash counts

With `c = L + 2`, at the default `L = 32` (`c = 34`):

- keygen `N = 0`: `c * w = 8,704` hashes.
- keygen `N >= 1`: `(1 << b) * c * w = 2,228,224` hashes, because the top subtree needs its 256 WOTS pubkeys.
- sign `N = 0`: `c * w = 8,704` hashes.
- sign `N >= 1`: `N * (1 << b) * c * w`, which is `71,303,168` at `N = 32`.
- verify `N >= 1`: about `N * c * w` chain hashes plus `N * b` parent hashes.

## Number formats

- All multi-byte integers are MSB first (big-endian).
- `E4M4(N)`, `E4M4(L)`, and the checksum are MSB first.
- The Merkle neighbour list is a sequence, not a number, so it follows verification order: LSB (deepest) first, MSB (subtree root) last.
- Path bytes run most significant (near the root, `path[0]`) to least significant (near the message, `path[N-1]`). Within a byte, the most significant bit is nearest the subtree root and the least significant bit is at the leaf.

## Pseudocode

A sketch, not reference code.

```c
// A key is named E4M4(N) | path[0..k-1] for a layer-k key.
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
        out   += single_sign(seed, E4M4(N) | path[0..k-1], value)
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
