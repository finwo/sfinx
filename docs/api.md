sfinx api
=========

Reference for the sfinx C library, generated from `src/sfinx.h`. The scheme
is described in [scheme.md](scheme.md), the command line in
[cli.md](cli.md).

Sizing calls are pure and return a byte count, or 0 when the arguments do
not describe a valid signature. Every other entry point returns an
`sfinx_status`.

Hash sizes
----------

SHA3 digest size in bits, `L` is the byte size: 224 -> 28, 256 -> 32,
384 -> 48, 512 -> 64.

```c
#define SFINX_HASH_DEFAULT SFINX_HASH_256
#define SFINX_HASH_LEN_MAX 64

typedef enum {
 SFINX_HASH_224 = 224,
 SFINX_HASH_256 = 256,
 SFINX_HASH_384 = 384,
 SFINX_HASH_512 = 512
} sfinx_hash;
```

<details>
  <summary>sfinx_hash_len(hash)</summary>

  Byte length `L` of a hash size, 0 when the size is not supported

```c
size_t sfinx_hash_len(sfinx_hash hash);
```

</details>

Path and seed
-------------

`N` is the path length in bytes, and the number of subtrees. The path is
the randomizer, so it is drawn fresh per signature rather than derived from
the message. The upper bound is what E4M4 can represent.

```c
#define SFINX_PATH_LEN_DEFAULT 32
#define SFINX_PATH_LEN_MAX     507904
```

The seed is the secret, any byte string up to 64 MiB. Random bytes are
recommended, a passphrase is allowed.

```c
#define SFINX_SEED_LEN_MAX (64u * 1024u * 1024u)
```

Status
------

Returned by every entry point that can fail.

```c
typedef enum {
 SFINX_OK = 0,
 SFINX_ERR_ARGS,
 SFINX_ERR_PATH_LEN,
 SFINX_ERR_NOSPACE,
 SFINX_ERR_FORMAT,
 SFINX_ERR_VERIFY,
 SFINX_ERR_RANDOM,
 SFINX_ERR_UNIMPLEMENTED
} sfinx_status;
```

<details>
  <summary>sfinx_strerror(status)</summary>

  Names a status code, never null

```c
const char *sfinx_strerror(sfinx_status status);
```

</details>
<details>
  <summary>sfinx_version()</summary>

  Library version as a dotted string

```c
const char *sfinx_version(void);
```

</details>

Sizing
------

<details>
  <summary>sfinx_signature_len(hash, path_len)</summary>

  Exact signature size for a hash size and path length

```c
size_t sfinx_signature_len(sfinx_hash hash, size_t path_len);
```

</details>
<details>
  <summary>sfinx_signature_len_max(hash)</summary>

  Signature size at the longest representable path

```c
size_t sfinx_signature_len_max(sfinx_hash hash);
```

</details>
<details>
  <summary>sfinx_path_len_valid(path_len)</summary>

  Non-zero when the length fits both the bound and the E4M4 encoding

```c
int sfinx_path_len_valid(size_t path_len);
```

</details>
<details>
  <summary>sfinx_signature_info(sig, sig_len, hash_out, path_len_out)</summary>

  Read the hash size and path length out of a signature, without verifying
  it. Either output may be null.

```c
sfinx_status sfinx_signature_info(const uint8_t *sig, size_t sig_len, sfinx_hash *hash_out, size_t *path_len_out);
```

</details>

Signing
-------

Signing and key derivation take the seed, verification takes raw bytes. The
`_cap` argument is the size of the caller's buffer, and the `_len_out`
argument reports what was written and may be null.
<details>
  <summary>sfinx_single_public_key(hash, seed, seed_len, pubkey_out, pubkey_cap, pubkey_len_out)</summary>

  Derive the single-key (`N = 0`) public key from a seed

```c
sfinx_status sfinx_single_public_key(sfinx_hash hash, const uint8_t *seed, size_t seed_len, uint8_t *pubkey_out,
                                    size_t pubkey_cap, size_t *pubkey_len_out);
```

</details>
<details>
  <summary>sfinx_single_sign(hash, seed, seed_len, msg, msg_len, sig, sig_cap, sig_len_out)</summary>

  Sign `H(message)` with one Winternitz key. One-time: signing two
  different messages under one seed destroys unforgeability.

```c
sfinx_status sfinx_single_sign(sfinx_hash hash, const uint8_t *seed, size_t seed_len, const uint8_t *msg,
                              size_t msg_len, uint8_t *sig, size_t sig_cap, size_t *sig_len_out);
```

</details>
<details>
  <summary>sfinx_tree_public_key(hash, seed, seed_len, path_len, pubkey_out, pubkey_cap, pubkey_len_out)</summary>

  Derive the tree public key from a seed. `N` is bound into every key, so a
  public key verifies one path length.

```c
sfinx_status sfinx_tree_public_key(sfinx_hash hash, const uint8_t *seed, size_t seed_len, size_t path_len,
                                  uint8_t *pubkey_out, size_t pubkey_cap, size_t *pubkey_len_out);
```

</details>
<details>
  <summary>sfinx_tree_sign(hash, seed, seed_len, path, path_len, msg, msg_len, sig, sig_cap, sig_len_out)</summary>

  Sign a message under a path. The caller supplies the path, which must not
  repeat across messages.

```c
sfinx_status sfinx_tree_sign(sfinx_hash hash, const uint8_t *seed, size_t seed_len, const uint8_t *path,
                            size_t path_len, const uint8_t *msg, size_t msg_len, uint8_t *sig, size_t sig_cap,
                            size_t *sig_len_out);
```

</details>
<details>
  <summary>sfinx_verify(pubkey, pubkey_len, msg, msg_len, sig, sig_len)</summary>

  Verify a signature, reading the mode and hash size from the signature
  itself. Returns `SFINX_OK` or `SFINX_ERR_VERIFY`.

```c
sfinx_status sfinx_verify(const uint8_t *pubkey, size_t pubkey_len, const uint8_t *msg, size_t msg_len,
                         const uint8_t *sig, size_t sig_len);
```

</details>
<details>
  <summary>sfinx_random_bytes(out, len)</summary>

  Fill a buffer from the system entropy source

```c
sfinx_status sfinx_random_bytes(uint8_t *out, size_t len);
```

</details>

Keys
----

A key holds a seed, a public key, or both. A null `seed` means public-only.
Decoding allocates into the key, `sfinx_key_free` releases it. `path_len`
is the length the public half was derived for, -1 when not recorded.

```c
typedef struct {
 uint8_t   *seed;
 size_t     seed_len;
 uint8_t   *pub;
 size_t     pub_len;
 ssize_t    path_len;
 sfinx_hash hash;
} sfinx_key;
```

<details>
  <summary>sfinx_key_init(key)</summary>

  Zero a key and set the default hash size and path length

```c
void sfinx_key_init(sfinx_key *key);
```

</details>
<details>
  <summary>sfinx_key_free(key)</summary>

  Release both halves and zero the key

```c
void sfinx_key_free(sfinx_key *key);
```

</details>
<details>
  <summary>sfinx_key_derive(key)</summary>

  Fill in the public key from the seed, for the key's `path_len`. A key
  that already carries one is left alone.

```c
sfinx_status sfinx_key_derive(sfinx_key *key);
```

</details>

Formats
-------

Key and signature encodings are pluggable and register themselves on load,
so the encode and decode code is shared with anything linking the library.
The bundled set is `hdr`, `raw`, `hex`, `rawpub` and `hexpub`, described in
[cli.md](cli.md).

```c
typedef struct sfinx_format {
 struct sfinx_format *next;
 const char          *name;

 int (*key_detect)(const uint8_t *data, size_t len);
 sfinx_status (*key_decode)(const uint8_t *data, size_t len, sfinx_key *out);
 size_t (*key_encode_len)(const sfinx_key *key);
 sfinx_status (*key_encode)(const sfinx_key *key, uint8_t *out, size_t cap, size_t *len_out);

 int (*sig_detect)(const uint8_t *data, size_t len);
 sfinx_status (*sig_decode)(const uint8_t *data, size_t len, uint8_t *out, size_t cap, size_t *len_out);
 size_t (*sig_encode_len)(const uint8_t *sig, size_t sig_len);
 sfinx_status (*sig_encode)(const uint8_t *sig, size_t sig_len, uint8_t *out, size_t cap, size_t *len_out);
} sfinx_format;
```

<details>
  <summary>sfinx_format_register(format)</summary>

  Add a format. Registration prepends, so a later format wins a name tie.

```c
void sfinx_format_register(sfinx_format *format);
```

</details>
<details>
  <summary>sfinx_format_find(name)</summary>

  Look up a registered format by name, null when there is no match

```c
const sfinx_format *sfinx_format_find(const char *name);
```

</details>

Passing a null `format` to either decode call auto-detects. Signature
auto-detect falls back to `raw` when nothing matches, key auto-detect does
not. Call `encode_len` to size the buffer before `encode`.
<details>
  <summary>sfinx_key_decode(data, len, format, out)</summary>

  Decode a key file, allocating into `out`

```c
sfinx_status sfinx_key_decode(const uint8_t *data, size_t len, const char *format, sfinx_key *out);
```

</details>
<details>
  <summary>sfinx_key_encode_len(key, format)</summary>

  Encoded size of a key, 0 when the format is unknown

```c
size_t sfinx_key_encode_len(const sfinx_key *key, const char *format);
```

</details>
<details>
  <summary>sfinx_key_encode(key, format, out, cap, len_out)</summary>

  Encode a key into the caller's buffer

```c
sfinx_status sfinx_key_encode(const sfinx_key *key, const char *format, uint8_t *out, size_t cap, size_t *len_out);
```

</details>
<details>
  <summary>sfinx_sig_decode(data, len, format, out, cap, len_out)</summary>

  Decode a signature into the caller's buffer

```c
sfinx_status sfinx_sig_decode(const uint8_t *data, size_t len, const char *format, uint8_t *out, size_t cap,
                             size_t *len_out);
```

</details>
<details>
  <summary>sfinx_sig_encode_len(sig, sig_len, format)</summary>

  Encoded size of a signature, 0 when the format is unknown

```c
size_t sfinx_sig_encode_len(const uint8_t *sig, size_t sig_len, const char *format);
```

</details>
<details>
  <summary>sfinx_sig_encode(sig, sig_len, format, out, cap, len_out)</summary>

  Encode a signature into the caller's buffer

```c
sfinx_status sfinx_sig_encode(const uint8_t *sig, size_t sig_len, const char *format, uint8_t *out, size_t cap,
                             size_t *len_out);
```

</details>
