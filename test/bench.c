// Public-API benchmark for sfinx.
//
// Times tree key derivation, tree signing, verification, and single-key
// signing. test/Makefile builds this twice, with and without -pthread, so the
// worker pool can be compared against the sequential path.

#include <finwo/keccak-fast.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sfinx.h"

// Args {{{

typedef struct {
  sfinx_hash hash;
  size_t     path_len;
  unsigned   reps;
} bench_args;

typedef enum {
  ARGS_OK,
  ARGS_HELP,
  ARGS_ERR
} args_result;

static void usage(const char *argv0) {
  fprintf(stderr, "usage: %s [-L bits] [-p path_len] [-n reps]\n", argv0);
  fprintf(stderr, "  -L  hash size, 224/256/384/512 (default 256)\n");
  fprintf(stderr, "  -p  path length in bytes, at least 1 (default 32)\n");
  fprintf(stderr, "  -n  repetitions, the best is reported (default 3)\n");
}

static int parse_u32(const char *text, uint32_t *out) {
  char         *end   = NULL;
  unsigned long value = 0;
  if (!text || !*text) {
    return 0;
  }
  value = strtoul(text, &end, 10);
  if (!end || *end != '\0') {
    return 0;
  }
  *out = (uint32_t)value;
  return 1;
}

static args_result parse_args(int argc, char **argv, bench_args *out) {
  out->hash     = SFINX_HASH_DEFAULT;
  out->path_len = SFINX_PATH_LEN_DEFAULT;
  out->reps     = 3;

  for (int i = 1; i < argc; i++) {
    const char *flag   = argv[i];
    const char *value  = i + 1 < argc ? argv[i + 1] : NULL;
    uint32_t    parsed = 0;

    if (strcmp(flag, "-h") == 0 || strcmp(flag, "--help") == 0) {
      usage(argv[0]);
      return ARGS_HELP;
    }
    if (!parse_u32(value, &parsed)) {
      fprintf(stderr, "%s expects a number\n", flag);
      return ARGS_ERR;
    }
    if (strcmp(flag, "-L") == 0) {
      out->hash = (sfinx_hash)parsed;
    } else if (strcmp(flag, "-p") == 0) {
      out->path_len = parsed;
    } else if (strcmp(flag, "-n") == 0) {
      out->reps = parsed;
    } else {
      fprintf(stderr, "unknown flag: %s\n", flag);
      return ARGS_ERR;
    }
    i++;
  }

  if (sfinx_hash_len(out->hash) == 0) {
    fprintf(stderr, "unsupported hash size: %u\n", (unsigned)out->hash);
    return ARGS_ERR;
  }
  if (out->path_len == 0 || !sfinx_path_len_valid(out->path_len)) {
    fprintf(stderr, "invalid path length: %zu\n", out->path_len);
    return ARGS_ERR;
  }
  if (out->reps == 0) {
    fprintf(stderr, "reps must be at least 1\n");
    return ARGS_ERR;
  }
  return ARGS_OK;
}

// }}}

// Timing {{{

static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static double elapsed_ms(uint64_t start) {
  return (double)(now_ns() - start) / 1000000.0;
}

// }}}

// Main {{{

int main(int argc, char **argv) {
  bench_args  args;
  args_result parsed = parse_args(argc, argv, &args);
  if (parsed == ARGS_HELP) {
    return 0;
  }
  if (parsed == ARGS_ERR) {
    return 1;
  }

  size_t        len        = sfinx_hash_len(args.hash);
  size_t        sig_len    = sfinx_signature_len(args.hash, args.path_len);
  size_t        single_len = sfinx_signature_len(args.hash, 0);
  const uint8_t msg[]      = "sfinx benchmark";
  size_t        msg_len    = sizeof(msg) - 1;

  uint8_t  seed[32];
  uint8_t *path       = calloc(args.path_len + 1, 1);
  uint8_t *pub        = malloc(len);
  uint8_t *sig        = malloc(sig_len);
  uint8_t *single_sig = malloc(single_len);

  if (!path || !pub || !sig || !single_sig) {
    fprintf(stderr, "out of memory\n");
    free(path);
    free(pub);
    free(sig);
    free(single_sig);
    return 1;
  }
  for (size_t i = 0; i < sizeof(seed); i++) {
    seed[i] = (uint8_t)i;
  }

  double pubkey_ms = 0.0;
  double sign_ms   = 0.0;
  double verify_ms = 0.0;
  double single_ms = 0.0;
  size_t sig_got   = 0;
  int    ok        = 1;

  for (unsigned r = 0; r < args.reps && ok; r++) {
    size_t       got = 0;
    uint64_t     t0  = now_ns();
    sfinx_status rc  = sfinx_tree_public_key(args.hash, seed, sizeof(seed), pub, len, &got);
    double       dt  = elapsed_ms(t0);
    if (rc != SFINX_OK) {
      ok = 0;
    } else if (r == 0 || dt < pubkey_ms) {
      pubkey_ms = dt;
    }
  }

  for (unsigned r = 0; r < args.reps && ok; r++) {
    size_t       got = 0;
    uint64_t     t0  = now_ns();
    sfinx_status rc =
        sfinx_tree_sign(args.hash, seed, sizeof(seed), path, args.path_len, msg, msg_len, sig, sig_len, &got);
    double dt = elapsed_ms(t0);
    if (rc != SFINX_OK) {
      ok = 0;
    } else {
      sig_got = got;
      if (r == 0 || dt < sign_ms) {
        sign_ms = dt;
      }
    }
  }

  for (unsigned r = 0; r < args.reps && ok; r++) {
    uint64_t     t0 = now_ns();
    sfinx_status rc = sfinx_verify(pub, len, msg, msg_len, sig, sig_got);
    double       dt = elapsed_ms(t0);
    if (rc != SFINX_OK) {
      ok = 0;
    } else if (r == 0 || dt < verify_ms) {
      verify_ms = dt;
    }
  }

  for (unsigned r = 0; r < args.reps && ok; r++) {
    size_t       got = 0;
    uint64_t     t0  = now_ns();
    sfinx_status rc  = sfinx_single_sign(args.hash, seed, sizeof(seed), msg, msg_len, single_sig, single_len, &got);
    double       dt  = elapsed_ms(t0);
    if (rc != SFINX_OK) {
      ok = 0;
    } else if (r == 0 || dt < single_ms) {
      single_ms = dt;
    }
  }

  free(path);
  free(pub);
  free(sig);
  free(single_sig);

  if (!ok) {
    fprintf(stderr, "benchmark failed\n");
    return 1;
  }

#ifdef _REENTRANT
  const char *mode = "threaded";
#else
  const char *mode = "sequential";
#endif

  printf("sfinx benchmark\n");
  printf("# hash %zu bytes, path %zu, reps %u, %s\n", len, args.path_len, args.reps, mode);
  printf("# core %s, batch %s\n", kf_backend_name(), kf_batch_name());
  printf("\n");
  printf("%-12s %10s\n", "case", "best (ms)");
  printf("%-12s %10s\n", "------------", "----------");
  printf("%-12s %10.3f\n", "pubkey", pubkey_ms);
  printf("%-12s %10.3f\n", "sign", sign_ms);
  printf("%-12s %10.3f\n", "verify", verify_ms);
  printf("%-12s %10.3f\n", "single-sign", single_ms);
  return 0;
}

// }}}

// vim:fdm=marker:fdl=0
