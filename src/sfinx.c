#include "sfinx.h"

#include <finwo/keccak-fast.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef _REENTRANT
#include <pthread.h>
#endif

// E4M4 {{{
//
// Log-ish number format, only positive
//   E=0: M
//   E>0: (16+M)<<(E-1)

static inline uint32_t _sfinx_e4m4_decode(uint8_t byte) {
  uint8_t exponent = (uint8_t)(byte >> 4);
  uint8_t mantissa = (uint8_t)(byte & 0x0f);
  if (exponent == 0) {
    return mantissa;
  }
  return (uint32_t)(16 + mantissa) << (exponent - 1);
}

static inline uint32_t _sfinx_e4m4_encode(uint32_t value, uint8_t *out) {
  if (value <= 15) {
    *out = (uint8_t)value;
    return 1;
  }

  uint32_t base  = value;
  uint32_t shift = 0;
  while (base > 31) {
    base >>= 1;
    if (++shift > 14) {
      return 0;
    }
  }
  if (base < 16 || (base << shift) != value) {
    return 0;
  }

  *out = (uint8_t)(((shift + 1) << 4) | (base - 16));
  return 1;
}
// }}}

// Hash backend {{{
//
// SHA3 for fixed-size hashing, SHAKE256 for the pre-image XOF
//   _sfinx_hash(hash, in, in_len, out)
//   _sfinx_shake256(in, in_len, out, out_len)
//   the _batch forms drive the equal-length loops over keccak-fast's SIMD kernels

static inline void _sfinx_hash(sfinx_hash hash, const uint8_t *in, size_t in_len, uint8_t *out) {
  switch (hash) {
    case SFINX_HASH_224: kf_sha3_224(out, 28, in, in_len); break;
    case SFINX_HASH_256: kf_sha3_256(out, 32, in, in_len); break;
    case SFINX_HASH_384: kf_sha3_384(out, 48, in, in_len); break;
    case SFINX_HASH_512: kf_sha3_512(out, 64, in, in_len); break;
  }
}

static inline void _sfinx_hash_batch(sfinx_hash hash, size_t count, const uint8_t *in, size_t in_len, uint8_t *out,
                                     size_t out_len) {
  switch (hash) {
    case SFINX_HASH_224: kf_sha3_224_batch(count, in, in_len, out, out_len); break;
    case SFINX_HASH_256: kf_sha3_256_batch(count, in, in_len, out, out_len); break;
    case SFINX_HASH_384: kf_sha3_384_batch(count, in, in_len, out, out_len); break;
    case SFINX_HASH_512: kf_sha3_512_batch(count, in, in_len, out, out_len); break;
  }
}

static inline void _sfinx_shake256(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len) {
  kf_shake256(out, out_len, in, in_len);
}

static inline void _sfinx_shake256_batch(size_t count, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len) {
  kf_shake256_batch(count, in, in_len, out, out_len);
}

size_t sfinx_hash_len(sfinx_hash hash) {
  switch (hash) {
    case SFINX_HASH_224: return 28;
    case SFINX_HASH_256: return 32;
    case SFINX_HASH_384: return 48;
    case SFINX_HASH_512: return 64;
  }
  return 0;
}

static inline sfinx_hash _sfinx_hash_from_len(size_t len) {
  switch (len) {
    case 28: return SFINX_HASH_224;
    case 32: return SFINX_HASH_256;
    case 48: return SFINX_HASH_384;
    case 64: return SFINX_HASH_512;
  }
  return 0;
}
// }}}

// WOTS {{{
//
// One WOTS key over an L-byte value, c = L + 2 chains of length 256
//   key      = seed for N = 0, seed | path for a tree leaf
//   preimage = SHAKE256(key), c * L bytes, c elements of L bytes
//   digits   = the value bytes, then 2 checksum bytes of 255 - value[i]
//   pubkey   = H of every element chained w times
//   sign     = every preimage element chained d[i] times
//   rebuild  = chain every proof element w - d[i] times, then the pubkey hash
//   verify   = rebuild over the value and compare to a known pubkey

#define SFINX_WOTS_BYTES_MAX  ((SFINX_HASH_LEN_MAX + 2) * SFINX_HASH_LEN_MAX)
#define SFINX_WOTS_DIGITS_MAX (SFINX_HASH_LEN_MAX + 2)

// Cap on the seed-sized key staging buffer, so a large seed cannot force 256 copies at once
#ifndef SFINX_BATCH_KEY_BUDGET
#define SFINX_BATCH_KEY_BUDGET (64u * 1024u)
#endif

static inline void _sfinx_wots_preimage(sfinx_hash hash, const uint8_t *key, size_t key_len, uint8_t *out) {
  size_t len = sfinx_hash_len(hash);
  _sfinx_shake256(key, key_len, out, (len + 2) * len);
}

static inline void _sfinx_wots_digits(sfinx_hash hash, const uint8_t *value, uint8_t *out) {
  size_t   len      = sfinx_hash_len(hash);
  uint32_t checksum = 0;
  for (size_t i = 0; i < len; i++) {
    out[i] = value[i];
    checksum += 255 - value[i];
  }
  out[len]     = (uint8_t)(checksum >> 8);
  out[len + 1] = (uint8_t)checksum;
}

static inline void _sfinx_wots_chain(sfinx_hash hash, uint8_t *node, uint32_t steps) {
  uint8_t next[SFINX_HASH_LEN_MAX];
  size_t  len = sfinx_hash_len(hash);
  for (uint32_t i = 0; i < steps; i++) {
    _sfinx_hash(hash, node, len, next);
    memcpy(node, next, len);
  }
}

static inline void _sfinx_wots_pubkey(sfinx_hash hash, const uint8_t *key, size_t key_len, uint8_t *pubkey_out) {
  size_t  len   = sfinx_hash_len(hash);
  size_t  count = len + 2;
  uint8_t ends[SFINX_WOTS_BYTES_MAX];
  _sfinx_wots_preimage(hash, key, key_len, ends);
  for (uint32_t step = 0; step < 256u; step++) {
    _sfinx_hash_batch(hash, count, ends, len, ends, len);
  }
  _sfinx_hash(hash, ends, count * len, pubkey_out);
}

static inline sfinx_status _sfinx_wots_sign(sfinx_hash hash, const uint8_t *key, size_t key_len, const uint8_t *value,
                                            size_t value_len, uint8_t *proof_out) {
  size_t  len = sfinx_hash_len(hash);
  uint8_t digits[SFINX_WOTS_DIGITS_MAX];
  if (len == 0 || value_len != len) {
    return SFINX_ERR_ARGS;
  }
  _sfinx_wots_preimage(hash, key, key_len, proof_out);
  _sfinx_wots_digits(hash, value, digits);
  for (size_t i = 0; i < len + 2; i++) {
    _sfinx_wots_chain(hash, proof_out + i * len, digits[i]);
  }
  return SFINX_OK;
}

static inline void _sfinx_wots_rebuild(sfinx_hash hash, const uint8_t *value, const uint8_t *proof,
                                       uint8_t *pubkey_out) {
  size_t  len = sfinx_hash_len(hash);
  uint8_t digits[SFINX_WOTS_DIGITS_MAX];
  uint8_t ends[SFINX_WOTS_BYTES_MAX];
  uint8_t node[SFINX_HASH_LEN_MAX];
  _sfinx_wots_digits(hash, value, digits);
  for (size_t i = 0; i < len + 2; i++) {
    memcpy(node, proof + i * len, len);
    _sfinx_wots_chain(hash, node, 256 - digits[i]);
    memcpy(ends + i * len, node, len);
  }
  _sfinx_hash(hash, ends, (len + 2) * len, pubkey_out);
}

static inline int _sfinx_wots_verify(sfinx_hash hash, const uint8_t *pubkey, const uint8_t *value,
                                     const uint8_t *proof) {
  uint8_t want[SFINX_HASH_LEN_MAX];
  _sfinx_wots_rebuild(hash, value, proof, want);
  return memcmp(want, pubkey, sfinx_hash_len(hash)) == 0;
}
// }}}

// Pool {{{
//
// Compile-time worker pool for one top-level operation
//   _REENTRANT: a round pulls indices from a shared counter, one scratch per worker
//   otherwise, and for counts under two, the loop runs on the caller

typedef void (*_sfinx_job_fn)(void *ctx, size_t index, void *scratch);

#ifdef _REENTRANT
typedef struct {
  struct _sfinx_pool *pool;
  size_t              index;
} _sfinx_worker;
#endif

typedef struct _sfinx_pool {
  size_t count;
#ifdef _REENTRANT
  pthread_t      *threads;
  _sfinx_worker  *workers;
  pthread_mutex_t mutex;
  pthread_cond_t  work;
  pthread_cond_t  done;
  _sfinx_job_fn   fn;
  void           *ctx;
  size_t          total;
  size_t          next;
  size_t          completed;
  unsigned long   round;
  size_t          scratch;
  uint8_t        *scratch_mem;
  int             stop;
#endif
} _sfinx_pool;

static inline size_t _sfinx_pool_scratch(size_t key_len) {
  return key_len > SFINX_BATCH_KEY_BUDGET ? key_len : SFINX_BATCH_KEY_BUDGET;
}

#ifdef _REENTRANT
static void *_sfinx_pool_worker(void *arg) {
  _sfinx_worker *worker  = arg;
  _sfinx_pool   *pool    = worker->pool;
  uint8_t       *scratch = pool->scratch_mem + (worker->index + 1) * pool->scratch;
  unsigned long  seen    = 0;

  for (;;) {
    pthread_mutex_lock(&pool->mutex);
    while (!pool->stop && pool->round == seen) {
      pthread_cond_wait(&pool->work, &pool->mutex);
    }
    if (pool->stop) {
      pthread_mutex_unlock(&pool->mutex);
      return NULL;
    }
    seen = pool->round;
    pthread_mutex_unlock(&pool->mutex);
    for (;;) {
      size_t i;
      pthread_mutex_lock(&pool->mutex);
      if (pool->next >= pool->total) {
        pthread_mutex_unlock(&pool->mutex);
        break;
      }
      i = pool->next++;
      pthread_mutex_unlock(&pool->mutex);
      pool->fn(pool->ctx, i, scratch);
      pthread_mutex_lock(&pool->mutex);
      pool->completed++;
      if (pool->completed == pool->total) {
        pthread_cond_broadcast(&pool->done);
      }
      pthread_mutex_unlock(&pool->mutex);
    }
  }
}
#endif

static void _sfinx_pool_destroy(_sfinx_pool *pool) {
#ifdef _REENTRANT
  if (!pool) {
    return;
  }
  pthread_mutex_lock(&pool->mutex);
  pool->stop = 1;
  pthread_cond_broadcast(&pool->work);
  pthread_mutex_unlock(&pool->mutex);
  for (size_t i = 0; i < pool->count; i++) {
    pthread_join(pool->threads[i], NULL);
  }
  pthread_mutex_destroy(&pool->mutex);
  pthread_cond_destroy(&pool->work);
  pthread_cond_destroy(&pool->done);
  free(pool->scratch_mem);
  free(pool->threads);
  free(pool->workers);
  free(pool);
#else
  (void)pool;
#endif
}

static _sfinx_pool *_sfinx_pool_create(size_t scratch) {
#ifdef _REENTRANT
  _sfinx_pool *pool;
  long         n;

  if (scratch == 0) {
    scratch = 1;
  }
  n = sysconf(_SC_NPROCESSORS_ONLN);
  if (n <= 1) {
    return NULL;
  }
  pool = calloc(1, sizeof(*pool));
  if (!pool) {
    return NULL;
  }
  pool->count       = (size_t)n;
  pool->scratch     = scratch;
  pool->scratch_mem = malloc((pool->count + 1) * scratch);
  pool->threads     = calloc(pool->count, sizeof(*pool->threads));
  pool->workers     = calloc(pool->count, sizeof(*pool->workers));
  if (!pool->scratch_mem || !pool->threads || !pool->workers) {
    free(pool->scratch_mem);
    free(pool->threads);
    free(pool->workers);
    free(pool);
    return NULL;
  }
  if (pthread_mutex_init(&pool->mutex, NULL) != 0) {
    free(pool->scratch_mem);
    free(pool->threads);
    free(pool->workers);
    free(pool);
    return NULL;
  }
  if (pthread_cond_init(&pool->work, NULL) != 0) {
    pthread_mutex_destroy(&pool->mutex);
    free(pool->scratch_mem);
    free(pool->threads);
    free(pool->workers);
    free(pool);
    return NULL;
  }
  if (pthread_cond_init(&pool->done, NULL) != 0) {
    pthread_cond_destroy(&pool->work);
    pthread_mutex_destroy(&pool->mutex);
    free(pool->scratch_mem);
    free(pool->threads);
    free(pool->workers);
    free(pool);
    return NULL;
  }
  for (size_t i = 0; i < pool->count; i++) {
    pool->workers[i].pool  = pool;
    pool->workers[i].index = i;
  }
  for (size_t i = 0; i < pool->count; i++) {
    if (pthread_create(&pool->threads[i], NULL, _sfinx_pool_worker, &pool->workers[i]) != 0) {
      pool->count = i;
      _sfinx_pool_destroy(pool);
      return NULL;
    }
  }
  return pool;
#else
  (void)scratch;
  return NULL;
#endif
}

static void _sfinx_parallel_for(_sfinx_pool *pool, size_t count, _sfinx_job_fn fn, void *ctx) {
  uint8_t *scratch;
#ifdef _REENTRANT
  if (pool && count >= 2) {
    scratch = pool->scratch_mem;
    pthread_mutex_lock(&pool->mutex);
    pool->fn        = fn;
    pool->ctx       = ctx;
    pool->total     = count;
    pool->next      = 0;
    pool->completed = 0;
    pool->round++;
    pthread_cond_broadcast(&pool->work);
    pthread_mutex_unlock(&pool->mutex);
    for (;;) {
      size_t i;
      pthread_mutex_lock(&pool->mutex);
      if (pool->next >= pool->total) {
        pthread_mutex_unlock(&pool->mutex);
        break;
      }
      i = pool->next++;
      pthread_mutex_unlock(&pool->mutex);
      fn(ctx, i, scratch);
      pthread_mutex_lock(&pool->mutex);
      pool->completed++;
      if (pool->completed == pool->total) {
        pthread_cond_broadcast(&pool->done);
      }
      pthread_mutex_unlock(&pool->mutex);
    }
    pthread_mutex_lock(&pool->mutex);
    while (pool->completed < pool->total) {
      pthread_cond_wait(&pool->done, &pool->mutex);
    }
    pthread_mutex_unlock(&pool->mutex);
    return;
  }
  scratch = pool ? pool->scratch_mem : NULL;
#else
  (void)pool;
  scratch = NULL;
#endif
  for (size_t i = 0; i < count; i++) {
    fn(ctx, i, scratch);
  }
}
// }}}

// Subtree {{{
//
// One binary subtree of height 8, 256 WOTS leaves folded into a root
//   leaf i is keyed by SHAKE256(seed | prefix | i)
//   parent = H(bitlen | mask | prefix | left | right), the mask from the leaf index
//   build returns the root, and for one leaf the 8 auth siblings, deepest first
//   verify folds a leaf and its siblings back up to the root

static inline uint8_t _sfinx_node_mask(uint8_t bitlen, uint8_t index) {
  return (uint8_t)(index & (0xFFu << (8 - bitlen)));
}

static inline void _sfinx_merkle_parent(sfinx_hash hash, uint8_t bitlen, uint8_t mask, const uint8_t *prefix,
                                        size_t prefix_len, const uint8_t *left, const uint8_t *right, uint8_t *out) {
  size_t  len = sfinx_hash_len(hash);
  uint8_t buf[2 + prefix_len + 2 * len];
  size_t  at = 0;
  buf[at++]  = bitlen;
  buf[at++]  = mask;
  if (prefix_len > 0) {
    memcpy(buf + at, prefix, prefix_len);
    at += prefix_len;
  }
  memcpy(buf + at, left, len);
  at += len;
  memcpy(buf + at, right, len);
  at += len;
  _sfinx_hash(hash, buf, at, out);
}

static inline void _sfinx_subtree_leaves(sfinx_hash hash, const uint8_t *seed, size_t seed_len, const uint8_t *prefix,
                                         size_t prefix_len, size_t begin, size_t end, uint8_t *ends, uint8_t *nodes,
                                         uint8_t *keybuf) {
  size_t len     = sfinx_hash_len(hash);
  size_t c       = len + 2;
  size_t key_len = seed_len + prefix_len + 1;
  size_t chunk   = SFINX_BATCH_KEY_BUDGET / key_len;
  size_t n       = end - begin;

  if (chunk == 0) {
    chunk = 1;
  }
  for (size_t base = 0; base < n; base += chunk) {
    size_t m = n - base;
    if (m > chunk) {
      m = chunk;
    }
    for (size_t i = 0; i < m; i++) {
      uint8_t *key = keybuf + i * key_len;
      memcpy(key, seed, seed_len);
      if (prefix_len > 0) {
        memcpy(key + seed_len, prefix, prefix_len);
      }
      key[key_len - 1] = (uint8_t)(begin + base + i);
    }
    _sfinx_shake256_batch(m, keybuf, key_len, ends + (begin + base) * c * len, c * len);
  }
  for (uint32_t step = 0; step < 256u; step++) {
    _sfinx_hash_batch(hash, n * c, ends + begin * c * len, len, ends + begin * c * len, len);
  }
  _sfinx_hash_batch(hash, n, ends + begin * c * len, c * len, nodes + begin * len, len);
}

typedef struct {
  sfinx_hash     hash;
  const uint8_t *seed;
  size_t         seed_len;
  const uint8_t *prefix;
  size_t         prefix_len;
  size_t         chunk;
  size_t         count;
  uint8_t       *ends;
  uint8_t       *nodes;
} _sfinx_subtree_ctx;

static void _sfinx_subtree_job(void *vctx, size_t index, void *scratch) {
  _sfinx_subtree_ctx *ctx   = vctx;
  size_t              begin = index * ctx->chunk;
  size_t              end   = begin + ctx->chunk;

  if (end > ctx->count) {
    end = ctx->count;
  }
  _sfinx_subtree_leaves(ctx->hash, ctx->seed, ctx->seed_len, ctx->prefix, ctx->prefix_len, begin, end, ctx->ends,
                        ctx->nodes, scratch);
}

static inline int _sfinx_subtree_build(_sfinx_pool *pool, sfinx_hash hash, const uint8_t *seed, size_t seed_len,
                                       const uint8_t *prefix, size_t prefix_len, uint8_t leaf_index, uint8_t *root_out,
                                       uint8_t *auth_out) {
  size_t   len     = sfinx_hash_len(hash);
  size_t   c       = len + 2;
  size_t   key_len = seed_len + prefix_len + 1;
  size_t   count   = 256;
  size_t   pos     = leaf_index;
  uint8_t  nodes[256 * SFINX_HASH_LEN_MAX];
  uint8_t *ends;

  ends = malloc(count * c * len);
  if (!ends) {
    return 0;
  }
  if (pool) {
    _sfinx_subtree_ctx ctx = {
        .hash       = hash,
        .seed       = seed,
        .seed_len   = seed_len,
        .prefix     = prefix,
        .prefix_len = prefix_len,
        .chunk      = (count + pool->count - 1) / pool->count,
        .count      = count,
        .ends       = ends,
        .nodes      = nodes,
    };
    size_t jobs;
    if (ctx.chunk == 0) {
      ctx.chunk = 1;
    }
    jobs = (count + ctx.chunk - 1) / ctx.chunk;
    _sfinx_parallel_for(pool, jobs, _sfinx_subtree_job, &ctx);
  } else {
    size_t   chunk = SFINX_BATCH_KEY_BUDGET / key_len;
    uint8_t *keybuf;
    if (chunk == 0) {
      chunk = 1;
    }
    if (chunk > count) {
      chunk = count;
    }
    keybuf = malloc(chunk * key_len);
    if (!keybuf) {
      free(ends);
      return 0;
    }
    _sfinx_subtree_leaves(hash, seed, seed_len, prefix, prefix_len, 0, count, ends, nodes, keybuf);
    free(keybuf);
  }
  for (size_t bitlen = 8; bitlen-- > 0;) {
    if (auth_out) {
      memcpy(auth_out + (7 - bitlen) * len, nodes + (pos ^ 1) * len, len);
    }
    count /= 2;
    for (size_t j = 0; j < count; j++) {
      _sfinx_merkle_parent(hash, (uint8_t)bitlen, _sfinx_node_mask((uint8_t)bitlen, (uint8_t)(j << (8 - bitlen))),
                           prefix, prefix_len, nodes + (2 * j) * len, nodes + (2 * j + 1) * len, nodes + j * len);
    }
    pos >>= 1;
  }
  memcpy(root_out, nodes, len);
  free(ends);
  return 1;
}

static inline void _sfinx_subtree_verify(sfinx_hash hash, const uint8_t *prefix, size_t prefix_len, const uint8_t *leaf,
                                         uint8_t leaf_index, const uint8_t *auth, uint8_t *root_out) {
  size_t  len = sfinx_hash_len(hash);
  uint8_t node[SFINX_HASH_LEN_MAX];
  uint8_t tmp[SFINX_HASH_LEN_MAX];
  size_t  pos = leaf_index;
  memcpy(node, leaf, len);
  for (size_t bitlen = 8; bitlen-- > 0;) {
    uint8_t        mask = _sfinx_node_mask((uint8_t)bitlen, (uint8_t)((pos >> 1) << (8 - bitlen)));
    const uint8_t *sib  = auth + (7 - bitlen) * len;
    if (pos & 1) {
      _sfinx_merkle_parent(hash, (uint8_t)bitlen, mask, prefix, prefix_len, sib, node, tmp);
    } else {
      _sfinx_merkle_parent(hash, (uint8_t)bitlen, mask, prefix, prefix_len, node, sib, tmp);
    }
    memcpy(node, tmp, len);
    pos >>= 1;
  }
  memcpy(root_out, node, len);
}
// }}}

// API - Sign {{{
//
// Thin wrappers over WOTS and Subtree, one WOTS per layer
//   single = one WOTS over SHAKE256(seed), signs H(message)
//   tree   = N subtrees, layer k signs R_k, R_N = org = H(path | message)

sfinx_status sfinx_single_public_key(sfinx_hash hash, const uint8_t *seed, size_t seed_len, uint8_t *pubkey_out,
                                     size_t pubkey_cap, size_t *pubkey_len_out) {
  size_t len = sfinx_hash_len(hash);
  if (len == 0 || !seed || seed_len > SFINX_SEED_LEN_MAX) {
    return SFINX_ERR_ARGS;
  }
  if (!pubkey_out || pubkey_cap < len) {
    return SFINX_ERR_NOSPACE;
  }
  _sfinx_wots_pubkey(hash, seed, seed_len, pubkey_out);
  if (pubkey_len_out) {
    *pubkey_len_out = len;
  }
  return SFINX_OK;
}

sfinx_status sfinx_single_sign(sfinx_hash hash, const uint8_t *seed, size_t seed_len, const uint8_t *msg,
                               size_t msg_len, uint8_t *sig, size_t sig_cap, size_t *sig_len_out) {
  size_t  len  = sfinx_hash_len(hash);
  size_t  need = sfinx_signature_len(hash, 0);
  uint8_t org[SFINX_HASH_LEN_MAX];
  if (len == 0 || !seed || !msg || seed_len > SFINX_SEED_LEN_MAX) {
    return SFINX_ERR_ARGS;
  }
  if (!sig || sig_cap < need) {
    return SFINX_ERR_NOSPACE;
  }
  _sfinx_hash(hash, msg, msg_len, org);
  _sfinx_e4m4_encode(0, sig);
  _sfinx_e4m4_encode((uint32_t)len, sig + 1);
  if (_sfinx_wots_sign(hash, seed, seed_len, org, len, sig + 2) != SFINX_OK) {
    return SFINX_ERR_ARGS;
  }
  if (sig_len_out) {
    *sig_len_out = need;
  }
  return SFINX_OK;
}

sfinx_status sfinx_tree_public_key(sfinx_hash hash, const uint8_t *seed, size_t seed_len, uint8_t *pubkey_out,
                                   size_t pubkey_cap, size_t *pubkey_len_out) {
  size_t       len = sfinx_hash_len(hash);
  _sfinx_pool *pool;
  int          ok;
  if (len == 0 || !seed || seed_len > SFINX_SEED_LEN_MAX) {
    return SFINX_ERR_ARGS;
  }
  if (!pubkey_out || pubkey_cap < len) {
    return SFINX_ERR_NOSPACE;
  }
  pool = _sfinx_pool_create(_sfinx_pool_scratch(seed_len + 1));
  ok   = _sfinx_subtree_build(pool, hash, seed, seed_len, NULL, 0, 0, pubkey_out, NULL);
  _sfinx_pool_destroy(pool);
  if (!ok) {
    return SFINX_ERR_NOSPACE;
  }
  if (pubkey_len_out) {
    *pubkey_len_out = len;
  }
  return SFINX_OK;
}

sfinx_status sfinx_tree_sign(sfinx_hash hash, const uint8_t *seed, size_t seed_len, const uint8_t *path,
                             size_t path_len, const uint8_t *msg, size_t msg_len, uint8_t *sig, size_t sig_cap,
                             size_t *sig_len_out) {
  size_t       len  = sfinx_hash_len(hash);
  size_t       c    = len + 2;
  size_t       need = sfinx_signature_len(hash, path_len);
  uint8_t      org[SFINX_HASH_LEN_MAX];
  uint8_t      value[SFINX_HASH_LEN_MAX];
  uint8_t      root[SFINX_HASH_LEN_MAX];
  uint8_t      auth[8 * SFINX_HASH_LEN_MAX];
  uint8_t     *key;
  uint8_t     *joined;
  size_t       at;
  _sfinx_pool *pool;

  if (len == 0 || !seed || !msg || seed_len > SFINX_SEED_LEN_MAX || !path || path_len == 0 ||
      !sfinx_path_len_valid(path_len)) {
    return SFINX_ERR_ARGS;
  }
  if (!sig || sig_cap < need) {
    return SFINX_ERR_NOSPACE;
  }
  joined = malloc(path_len + msg_len);
  key    = malloc(seed_len + path_len);
  if (!joined || !key) {
    free(joined);
    free(key);
    return SFINX_ERR_NOSPACE;
  }
  pool = _sfinx_pool_create(_sfinx_pool_scratch(seed_len + path_len));
  // Sign (path||message)
  memcpy(joined, path, path_len);
  memcpy(joined + path_len, msg, msg_len);
  _sfinx_hash(hash, joined, path_len + msg_len, org);
  free(joined);
  // Start at (seed||full-path) for WOTS
  memcpy(key, seed, seed_len);
  memcpy(key + seed_len, path, path_len);

  // Prep sig header
  _sfinx_e4m4_encode((uint32_t)path_len, sig);
  memcpy(sig + 1, path, path_len);
  at = 1 + path_len;
  _sfinx_e4m4_encode((uint32_t)len, sig + at);
  at += 1;

  // WOTS-sign up the tree
  memcpy(value, org, len);
  for (size_t k = path_len; k >= 1; k--) {
    if (!_sfinx_subtree_build(pool, hash, seed, seed_len, path, k - 1, path[k - 1], root, auth)) {
      _sfinx_pool_destroy(pool);
      free(key);
      return SFINX_ERR_NOSPACE;
    }
    if (_sfinx_wots_sign(hash, key, seed_len + k, value, len, sig + at) != SFINX_OK) {
      _sfinx_pool_destroy(pool);
      free(key);
      return SFINX_ERR_ARGS;
    }
    at += c * len;
    memcpy(sig + at, auth, 8 * len);
    at += 8 * len;
    memcpy(value, root, len);
  }

  _sfinx_pool_destroy(pool);
  free(key);
  if (sig_len_out) {
    *sig_len_out = need;
  }
  return SFINX_OK;
}

// }}}

// API - Verify {{{
//
// Parse the layout, then walk from the top round down
//   single: rebuild the one WOTS pubkey over H(message) and compare
//   tree: rebuild layer k over R_k, fold subtree k-1 to R_{k-1}, R_0 is the pubkey

sfinx_status sfinx_verify(const uint8_t *pubkey, size_t pubkey_len, const uint8_t *msg, size_t msg_len,
                          const uint8_t *sig, size_t sig_len) {
  size_t         path_len;
  size_t         len;
  size_t         c;
  size_t         at;
  sfinx_hash     hash;
  uint8_t        org[SFINX_HASH_LEN_MAX];
  uint8_t        value[SFINX_HASH_LEN_MAX];
  uint8_t        leaf[SFINX_HASH_LEN_MAX];
  uint8_t        root[SFINX_HASH_LEN_MAX];
  const uint8_t *path;
  uint8_t       *joined;

  if (!pubkey || !msg || !sig || sig_len < 2) {
    return SFINX_ERR_ARGS;
  }
  path_len = _sfinx_e4m4_decode(sig[0]);
  path     = sig + 1;
  at       = 1 + path_len;
  if (!sfinx_path_len_valid(path_len) || sig_len < at + 1) {
    return SFINX_ERR_FORMAT;
  }
  len = _sfinx_e4m4_decode(sig[at]);
  at += 1;
  hash = _sfinx_hash_from_len(len);
  if (!hash || len != pubkey_len || sig_len != sfinx_signature_len(hash, path_len)) {
    return SFINX_ERR_FORMAT;
  }
  c = len + 2;
  if (path_len == 0) {
    _sfinx_hash(hash, msg, msg_len, org);
    _sfinx_wots_rebuild(hash, org, sig + at, leaf);
    return memcmp(leaf, pubkey, len) == 0 ? SFINX_OK : SFINX_ERR_VERIFY;
  }
  joined = malloc(path_len + msg_len);
  if (!joined) {
    return SFINX_ERR_NOSPACE;
  }
  memcpy(joined, path, path_len);
  memcpy(joined + path_len, msg, msg_len);
  _sfinx_hash(hash, joined, path_len + msg_len, org);
  free(joined);
  memcpy(value, org, len);
  for (size_t k = path_len; k >= 1; k--) {
    _sfinx_wots_rebuild(hash, value, sig + at, leaf);
    at += c * len;
    _sfinx_subtree_verify(hash, path, k - 1, leaf, path[k - 1], sig + at, root);
    at += 8 * len;
    if (k == 1) {
      return memcmp(root, pubkey, len) == 0 ? SFINX_OK : SFINX_ERR_VERIFY;
    }
    memcpy(value, root, len);
  }
  return SFINX_ERR_FORMAT;
}
// }}}

// API - Utilities {{{
//
// Pure size helpers, status names, and the optional RNG
//   sizes = E4M4(N) | path | E4M4(L) | N rounds of WOTS proof and auth path

const char *sfinx_strerror(sfinx_status status) {
  switch (status) {
    case SFINX_OK:                return "ok";
    case SFINX_ERR_ARGS:          return "invalid arguments";
    case SFINX_ERR_PATH_LEN:      return "invalid path length";
    case SFINX_ERR_NOSPACE:       return "no space available";
    case SFINX_ERR_FORMAT:        return "invalid signature format";
    case SFINX_ERR_VERIFY:        return "verification failed";
    case SFINX_ERR_RANDOM:        return "random source failed";
    case SFINX_ERR_UNIMPLEMENTED: return "unimplemented";
  }
  return "unknown error";
}

const char *sfinx_version(void) {
  return "0.1.0";
}

size_t sfinx_signature_len(sfinx_hash hash, size_t path_len) {
  size_t len = sfinx_hash_len(hash);
  if (len == 0) {
    return 0;
  }
  if (path_len == 0) {
    return 2 + (len + 2) * len;
  }
  return 2 + path_len + path_len * (len + 10) * len;
}

size_t sfinx_signature_len_max(sfinx_hash hash) {
  return sfinx_signature_len(hash, SFINX_PATH_LEN_MAX);
}

int sfinx_path_len_valid(size_t path_len) {
  uint8_t byte;
  return path_len <= SFINX_PATH_LEN_MAX && _sfinx_e4m4_encode((uint32_t)path_len, &byte);
}

sfinx_status sfinx_signature_info(const uint8_t *sig, size_t sig_len, sfinx_hash *hash_out, size_t *path_len_out) {
  size_t     path_len;
  sfinx_hash hash;
  if (!sig || sig_len < 2) {
    return SFINX_ERR_ARGS;
  }
  path_len = _sfinx_e4m4_decode(sig[0]);
  if (!sfinx_path_len_valid(path_len) || sig_len < 2 + path_len) {
    return SFINX_ERR_FORMAT;
  }
  hash = _sfinx_hash_from_len(_sfinx_e4m4_decode(sig[1 + path_len]));
  if (!hash) {
    return SFINX_ERR_FORMAT;
  }
  if (hash_out) {
    *hash_out = hash;
  }
  if (path_len_out) {
    *path_len_out = path_len;
  }
  return SFINX_OK;
}

sfinx_status sfinx_random_bytes(uint8_t *out, size_t len) {
  if (!out) {
    return SFINX_ERR_ARGS;
  }
  while (len > 0) {
    size_t chunk = len > 256 ? 256 : len;
    if (getentropy(out, chunk) != 0) {
      return SFINX_ERR_RANDOM;
    }
    out += chunk;
    len -= chunk;
  }
  return SFINX_OK;
}
// }}}

// vim:fdm=marker:fdl=0
