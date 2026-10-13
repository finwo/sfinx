Benchmarks
==========

Operations per second, higher is better. Tree mode at path length 32, so one
signature covers 32 subtrees.

| host                      | cores | backend  |
| ------------------------- | ----- | -------- |
| AMD Ryzen 7 9800X3D       | 8/16  | avx512   |
| Intel Xeon D-1541         | 8/16  | avx2     |
| Cortex-A520 + A720        | 12    | arm-sha3 |

gcc 14.2.1, `-Wall -Wextra -O2`, best of 5 on the Ryzen, 3 on the Xeon, 2 on
the ARM. The Xeon shares its host with other services, so treat it as a floor.

Only keygen and signing use the worker pool. Verifying and single mode run on
one core either way, so they are listed once.

## SHA3-256, the default

| host          | keygen/s | sign/s | verify/s |
| ------------- | -------- | ------ | -------- |
| 9800X3D       |       18 |   0.56 |       40 |
| 9800X3D x16   |      186 |   4.72 |       40 |
| D-1541        |      2.0 |  0.063 |       12 |
| D-1541 x16    |       15 |   0.49 |       12 |
| A520/A720     |      1.1 |  0.034 |      8.0 |
| A520/A720 x12 |      7.0 |   0.21 |      8.0 |

## Every hash size

Single core, then the same host threaded.

| host          | hash     | keygen/s | sign/s | verify/s |
| ------------- | -------- | -------- | ------ | -------- |
| 9800X3D       | SHA3-224 |       20 |   0.63 |       43 |
| 9800X3D       | SHA3-256 |       18 |   0.56 |       40 |
| 9800X3D       | SHA3-384 |       12 |   0.38 |       26 |
| 9800X3D       | SHA3-512 |      9.4 |   0.29 |       20 |
| 9800X3D x16   | SHA3-224 |      208 |   5.38 |       43 |
| 9800X3D x16   | SHA3-256 |      186 |   4.72 |       40 |
| 9800X3D x16   | SHA3-384 |      125 |   3.14 |       25 |
| 9800X3D x16   | SHA3-512 |       96 |   2.30 |       20 |
| D-1541        | SHA3-224 |      2.3 |  0.071 |       13 |
| D-1541        | SHA3-256 |      2.0 |  0.063 |       12 |
| D-1541        | SHA3-384 |      1.4 |  0.043 |      7.8 |
| D-1541        | SHA3-512 |      1.0 |  0.032 |      6.2 |
| D-1541 x16    | SHA3-224 |       17 |   0.57 |       13 |
| D-1541 x16    | SHA3-256 |       15 |   0.49 |       12 |
| D-1541 x16    | SHA3-384 |       10 |   0.34 |      8.0 |
| D-1541 x16    | SHA3-512 |      7.2 |   0.25 |      6.2 |
| A520/A720     | SHA3-224 |      1.2 |  0.038 |      8.8 |
| A520/A720     | SHA3-256 |      1.1 |  0.034 |      8.0 |
| A520/A720     | SHA3-384 |     0.49 |  0.015 |      3.5 |
| A520/A720     | SHA3-512 |     0.55 |  0.017 |      4.1 |
| A520/A720 x12 | SHA3-224 |      7.7 |   0.23 |      8.8 |
| A520/A720 x12 | SHA3-256 |      7.0 |   0.21 |      8.0 |
| A520/A720 x12 | SHA3-384 |      4.9 |   0.14 |      5.2 |
| A520/A720 x12 | SHA3-512 |      3.8 |   0.11 |      4.1 |

## Single mode

One WOTS key, no tree, no path. Signs and verifies on one core.

| host      | SHA3-224 | SHA3-256 | SHA3-384 | SHA3-512 |
| --------- | -------- | -------- | -------- | -------- |
| 9800X3D   |     1395 |     1303 |     1055 |      626 |
| D-1541    |      453 |      424 |      315 |      197 |
| A520/A720 |      283 |      262 |      142 |      126 |

## Chains

`make --directory test bench-chain`, one subtree of chains advanced 256 steps,
in millions of hashes per second on the 9800X3D. Higher is better.

- `plain`: an untweaked chain over the batch API
- `glue`: the tweak over the batch API, rebuilding records each step
- `fused`: the chain kernel

| hash     | backend   | plain | glue  | fused |
| -------- | --------- | ----- | ----- | ----- |
| SHA3-224 | scalar    |  5.94 |  5.73 |  5.11 |
| SHA3-224 | avx2 x4   | 11.92 | 10.54 | 13.51 |
| SHA3-224 | avx512 x8 | 24.44 | 20.36 | 40.10 |
| SHA3-256 | scalar    |  5.92 |  5.67 |  5.12 |
| SHA3-256 | avx2 x4   | 11.60 | 10.22 | 13.53 |
| SHA3-256 | avx512 x8 | 24.05 | 19.73 | 40.44 |
| SHA3-384 | scalar    |  5.83 |  5.45 |  5.12 |
| SHA3-384 | avx2 x4   | 10.93 |  9.57 | 13.54 |
| SHA3-384 | avx512 x8 | 21.63 | 17.13 | 40.24 |
| SHA3-512 | scalar    |  5.70 |  5.59 |  5.12 |
| SHA3-512 | avx2 x4   | 10.50 | 10.03 | 13.59 |
| SHA3-512 | avx512 x8 | 20.24 | 18.76 | 40.91 |

A chain step is one permutation at every hash size, so the fused kernel holds
about 40 Mh/s on avx512 from SHA3-224 to SHA3-512 where an untweaked chain
falls from 24.4 to 20.2. Reaching the chain through the batch API instead costs
a transpose and a scalar absorb per step, which is the `glue` column.

Scalar has no lanes to fill, so it does not recover the larger block and sits
about 14% below an untweaked chain.

## Notes

Signing scales with path length: at path 32 each signature builds 32 subtrees,
and a shorter path is proportionally faster. Verifying does not, since it only
walks the path it is given.

Zen 5 has a full-width AVX-512 datapath. Intel parts that double-pump 512-bit
operations will sit closer to the avx2 numbers.
