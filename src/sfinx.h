#ifndef __SFINX_H__
#define __SFINX_H__

#include <stddef.h>
#include <stdint.h>

// Hash sizes {{{
//
// SHA3 digest size in bits, L is the byte size
//   224 -> 28, 256 -> 32, 384 -> 48, 512 -> 64

#define SFINX_HASH_DEFAULT SFINX_HASH_256
#define SFINX_HASH_LEN_MAX 64

typedef enum {
  SFINX_HASH_224 = 224,
  SFINX_HASH_256 = 256,
  SFINX_HASH_384 = 384,
  SFINX_HASH_512 = 512
} sfinx_hash;

size_t sfinx_hash_len(sfinx_hash hash);
// }}}

// Path {{{
//
// N is the number of subtrees, and the path length in bytes
//   32 by default, the only bound is E4M4, 507904

#define SFINX_PATH_LEN_DEFAULT 32
#define SFINX_PATH_LEN_MAX     507904
// }}}

// Seed {{{
//
// Any byte string, at most 64 MiB, random recommended

#define SFINX_SEED_LEN_MAX (64u * 1024u * 1024u)
// }}}

// Status {{{
//
// Every entry point returns one of these, sfinx_strerror names them

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

const char *sfinx_strerror(sfinx_status status);
const char *sfinx_version(void);
// }}}

// API {{{
//
// Sizes are pure, the key and sign calls take the seed, verify takes raw bytes

size_t       sfinx_signature_len(sfinx_hash hash, size_t path_len);
size_t       sfinx_signature_len_max(sfinx_hash hash);
int          sfinx_path_len_valid(size_t path_len);
sfinx_status sfinx_signature_info(const uint8_t *sig, size_t sig_len, sfinx_hash *hash_out, size_t *path_len_out);

sfinx_status sfinx_single_public_key(sfinx_hash hash, const uint8_t *seed, size_t seed_len, uint8_t *pubkey_out,
                                     size_t pubkey_cap, size_t *pubkey_len_out);
sfinx_status sfinx_single_sign(sfinx_hash hash, const uint8_t *seed, size_t seed_len, const uint8_t *msg,
                               size_t msg_len, uint8_t *sig, size_t sig_cap, size_t *sig_len_out);
sfinx_status sfinx_tree_public_key(sfinx_hash hash, const uint8_t *seed, size_t seed_len, uint8_t *pubkey_out,
                                   size_t pubkey_cap, size_t *pubkey_len_out);
sfinx_status sfinx_tree_sign(sfinx_hash hash, const uint8_t *seed, size_t seed_len, const uint8_t *path,
                             size_t path_len, const uint8_t *msg, size_t msg_len, uint8_t *sig, size_t sig_cap,
                             size_t *sig_len_out);
sfinx_status sfinx_verify(const uint8_t *pubkey, size_t pubkey_len, const uint8_t *msg, size_t msg_len,
                          const uint8_t *sig, size_t sig_len);
sfinx_status sfinx_random_bytes(uint8_t *out, size_t len);
// }}}

// Key {{{
//
// Seed and public key pair, either half may be absent
//   seed NULL means public-only, decode mallocs, sfinx_key_free releases

typedef struct {
  uint8_t   *seed;
  size_t     seed_len;
  uint8_t   *pub;
  size_t     pub_len;
  sfinx_hash hash;
} sfinx_key;

void         sfinx_key_init(sfinx_key *key);
void         sfinx_key_free(sfinx_key *key);
sfinx_status sfinx_key_derive(sfinx_key *key);
// }}}

// Formats {{{
//
// Pluggable key and signature encodings, registered by constructors
//   decode with a NULL name auto-detects, encode_len sizes before encode
//   signature auto-detect falls back to raw when nothing matches

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

void                sfinx_format_register(sfinx_format *format);
const sfinx_format *sfinx_format_find(const char *name);

sfinx_status sfinx_key_decode(const uint8_t *data, size_t len, const char *format, sfinx_key *out);
size_t       sfinx_key_encode_len(const sfinx_key *key, const char *format);
sfinx_status sfinx_key_encode(const sfinx_key *key, const char *format, uint8_t *out, size_t cap, size_t *len_out);

sfinx_status sfinx_sig_decode(const uint8_t *data, size_t len, const char *format, uint8_t *out, size_t cap,
                              size_t *len_out);
size_t       sfinx_sig_encode_len(const uint8_t *sig, size_t sig_len, const char *format);
sfinx_status sfinx_sig_encode(const uint8_t *sig, size_t sig_len, const char *format, uint8_t *out, size_t cap,
                              size_t *len_out);
// }}}

#endif  // __SFINX_H__

// vim:fdm=marker:fdl=0
