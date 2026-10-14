#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "keccak-fast-internal.h"
#include "src/sfinx.c"

#define KF_CHAIN_PROTO(name) \
  void name(size_t, uint8_t *, size_t, const uint8_t *, size_t, size_t, uint8_t, uint32_t, size_t, uint8_t)
#define KF_HASH_PROTO(name) int name(uint8_t *, size_t, const uint8_t *, size_t)

KF_CHAIN_PROTO(kf_scalar_chain);
KF_CHAIN_PROTO(kf_scalar_chain12);
void kf_scalar_batch(uint64_t states[][25], size_t count);
void kf_scalar_batch12(uint64_t states[][25], size_t count);
KF_HASH_PROTO(kf_scalar_sha3_224);
KF_HASH_PROTO(kf_scalar_sha3_256);
KF_HASH_PROTO(kf_scalar_sha3_384);
KF_HASH_PROTO(kf_scalar_sha3_512);

#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && !defined(KECCAK_FAST_NO_BMI)
KF_CHAIN_PROTO(kf_bmi_chain);
KF_CHAIN_PROTO(kf_bmi_chain12);
void kf_bmi_batch(uint64_t states[][25], size_t count);
void kf_bmi_batch12(uint64_t states[][25], size_t count);
KF_HASH_PROTO(kf_bmi_sha3_224);
KF_HASH_PROTO(kf_bmi_sha3_256);
KF_HASH_PROTO(kf_bmi_sha3_384);
KF_HASH_PROTO(kf_bmi_sha3_512);
#endif

#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && !defined(KECCAK_FAST_NO_AVX2)
KF_CHAIN_PROTO(kf_avx2_chain);
KF_CHAIN_PROTO(kf_avx2_chain12);
void kf_avx2_batch(uint64_t states[][25], size_t count);
void kf_avx2_batch12(uint64_t states[][25], size_t count);
#endif
#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && !defined(KECCAK_FAST_NO_AVX512)
KF_CHAIN_PROTO(kf_avx512_chain);
KF_CHAIN_PROTO(kf_avx512_chain12);
void kf_avx512_batch(uint64_t states[][25], size_t count);
void kf_avx512_batch12(uint64_t states[][25], size_t count);
#endif
#if defined(__aarch64__) && !defined(KECCAK_FAST_NO_SHA3)
int kf_armsha3_available(void);
KF_CHAIN_PROTO(kf_armsha3_chain);
KF_CHAIN_PROTO(kf_armsha3_chain12);
void kf_armsha3_batch(uint64_t states[][25], size_t count);
void kf_armsha3_batch12(uint64_t states[][25], size_t count);
#endif

typedef struct {
  const char      *label;
  kf_batch_perm_fn perm;
  kf_batch_perm_fn perm12;
  kf_chain_fn      chain;
  kf_chain_fn      chain12;
  int              lanes;
  kf_hash_fn       one[4];
} row;

static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static double mhs(uint64_t ns, size_t hashes) {
  return (double)hashes * 1000.0 / (double)ns;
}

static void cell(double v) {
  if (v < 0.0) {
    printf(" %10s", "-");
  } else {
    printf(" %10.3f", v);
  }
}

int main(int argc, char **argv) {
  static const sfinx_hash hashes[] = {SFINX_HASH_224, SFINX_HASH_256, SFINX_HASH_384, SFINX_HASH_512};
  static const char      *sizes[]  = {"SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"};
  unsigned                reps     = 5;
  row                     rows[5];
  int                     nr = 0;

  for (int i = 1; i + 1 < argc; i += 2) {
    if (strcmp(argv[i], "-n") == 0) {
      reps = (unsigned)strtoul(argv[i + 1], NULL, 10);
    }
  }
  if (reps == 0) {
    reps = 1;
  }

  rows[nr++] = (row){"scalar",
                     kf_scalar_batch,
                     kf_scalar_batch12,
                     kf_scalar_chain,
                     kf_scalar_chain12,
                     1,
                     {kf_scalar_sha3_224, kf_scalar_sha3_256, kf_scalar_sha3_384, kf_scalar_sha3_512}};
#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && !defined(KECCAK_FAST_NO_BMI)
#if defined(__clang__)
  if (__builtin_cpu_supports("bmi")) {
#else
  if (__builtin_cpu_supports("bmi") && __builtin_cpu_supports("bmi2")) {
#endif
    rows[nr++] = (row){"scalar+bmi",
                       kf_bmi_batch,
                       kf_bmi_batch12,
                       kf_bmi_chain,
                       kf_bmi_chain12,
                       1,
                       {kf_bmi_sha3_224, kf_bmi_sha3_256, kf_bmi_sha3_384, kf_bmi_sha3_512}};
  }
#endif
#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && !defined(KECCAK_FAST_NO_AVX2)
  if (__builtin_cpu_supports("avx2")) {
    rows[nr++] =
        (row){"avx2 x4", kf_avx2_batch, kf_avx2_batch12, kf_avx2_chain, kf_avx2_chain12, 4, {NULL, NULL, NULL, NULL}};
  }
#endif
#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && !defined(KECCAK_FAST_NO_AVX512)
  if (__builtin_cpu_supports("avx512f")) {
    rows[nr++] = (row){"avx512 x8", kf_avx512_batch,         kf_avx512_batch12, kf_avx512_chain, kf_avx512_chain12,
                       8,           {NULL, NULL, NULL, NULL}};
  }
#endif
#if defined(__aarch64__) && !defined(KECCAK_FAST_NO_SHA3)
  if (kf_armsha3_available()) {
    rows[nr++] =
        (row){"arm-sha3 x2",           kf_armsha3_batch, kf_armsha3_batch12, kf_armsha3_chain, kf_armsha3_chain12, 2,
              {NULL, NULL, NULL, NULL}};
  }
#endif

  printf("sfinx WOTS chain microbenchmark\n");
  printf("# one subtree of chains, 256 steps, best of %u\n", reps);
  printf("# plain: the untweaked batch loop this replaced\n");
  printf("# glue:  the tweak over the batch API, rebuilding records each step\n");
  printf("# fused: the chain kernel\n\n");

  for (size_t h = 0; h < 4; h++) {
    sfinx_hash hash     = hashes[h];
    size_t     len      = sfinx_hash_len(hash);
    size_t     c        = len + 2;
    size_t     k        = _sfinx_kid_len(hash);
    size_t     tail_len = k + 1;
    size_t     reclen   = len + k + 2;
    size_t     count    = 256 * c;
    size_t     total    = count * 256;
    uint8_t   *x        = malloc(count * len);
    uint8_t   *seedx    = malloc(count * len);
    uint8_t   *tails    = malloc(count * tail_len);
    uint8_t   *recs     = malloc(count * reclen);
    uint8_t    kid[SFINX_HASH_LEN_MAX];

    if (!x || !seedx || !tails || !recs) {
      fprintf(stderr, "out of memory\n");
      return 1;
    }
    for (size_t i = 0; i < count * len; i++) {
      seedx[i] = (uint8_t)(i * 31 + 7);
    }
    _sfinx_kid(hash, (const uint8_t *)"\x01\x0a", 2, kid);
    for (size_t r = 0; r < count; r++) {
      memcpy(tails + r * tail_len, kid, k);
      tails[r * tail_len + k] = (uint8_t)(r % c);
      memcpy(recs + r * reclen + len, kid, k);
      recs[r * reclen + len + k] = (uint8_t)(r % c);
    }

    printf("%s, %zu chains x 256 steps\n", sizes[h], count);
    printf("  %-12s %10s %10s %10s\n", "backend", "plain", "glue", "fused");
    printf("  %-12s %10s %10s %10s\n", "", "Mh/s", "Mh/s", "Mh/s");

    for (int i = 0; i < nr; i++) {
      double best_plain = -1.0, best_glue = -1.0, best_fused = -1.0;

      kf_batch_perm     = rows[i].perm;
      kf_batch_perm12   = rows[i].perm12;
      kf_batch_lanes    = rows[i].lanes;
      kf_chain_kernel   = rows[i].chain;
      kf_chain_kernel12 = rows[i].chain12;
      kf_chain_lanes    = rows[i].lanes;
      if (rows[i].one[0] != NULL) {
        kf_sha3_224 = rows[i].one[0];
        kf_sha3_256 = rows[i].one[1];
        kf_sha3_384 = rows[i].one[2];
        kf_sha3_512 = rows[i].one[3];
      }

      for (unsigned rep = 0; rep < reps; rep++) {
        uint64_t t0;
        double   dt;

        memcpy(x, seedx, count * len);
        t0 = now_ns();
        for (uint32_t step = 0; step < 256u; step++) {
          _sfinx_hash_batch(hash, count, x, len, x, len);
        }
        dt = mhs(now_ns() - t0, total);
        if (best_plain < 0.0 || dt > best_plain) best_plain = dt;

        memcpy(x, seedx, count * len);
        t0 = now_ns();
        for (uint32_t step = 0; step < 256u; step++) {
          for (size_t r = 0; r < count; r++) {
            memcpy(recs + r * reclen, x + r * len, len);
            recs[r * reclen + len + k + 1] = (uint8_t)step;
          }
          _sfinx_hash_batch(hash, count, recs, reclen, x, len);
        }
        dt = mhs(now_ns() - t0, total);
        if (best_glue < 0.0 || dt > best_glue) best_glue = dt;

        memcpy(x, seedx, count * len);
        t0 = now_ns();
        _sfinx_chain_batch(hash, count, x, tails, tail_len, 0, 256);
        dt = mhs(now_ns() - t0, total);
        if (best_fused < 0.0 || dt > best_fused) best_fused = dt;
      }

      printf("  %-12s", rows[i].label);
      cell(best_plain);
      cell(best_glue);
      cell(best_fused);
      printf("\n");
    }
    printf("\n");

    free(x);
    free(seedx);
    free(tails);
    free(recs);
  }

  return 0;
}
