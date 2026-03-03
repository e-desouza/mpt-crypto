# Performance Benchmarks

Benchmarks comparing optimized implementations against baseline approaches.
All measurements taken on a single core with `-O2` optimization.

## Summary

| Optimization | Speedup Range | Notes |
|--------------|---------------|-------|
| BSGS Decryption | 12-123x | Constant-time regardless of amount |
| Batch Scalar Inversion | 3-12x | Scales with batch size |
| Generator Cache | ~210,000x | Warm cache vs cold computation |

## 1. ElGamal Decryption: BSGS vs Brute-Force

The Baby-Step Giant-Step algorithm provides O(√n) decryption with **constant execution time**, eliminating timing side-channels.

| Amount | Brute-Force | BSGS | Speedup |
|--------|-------------|------|---------|
| 1,000 | 4 ms | 32 ms | 0.1x |
| 10,000 | 40 ms | 32 ms | **1.2x** |
| 100,000 | 399 ms | 32 ms | **12x** |
| 500,000 | 1,994 ms | 32 ms | **62x** |
| 1,000,000 | 3,990 ms | 32 ms | **123x** |

**Key observations:**
- BSGS runs in constant ~32ms regardless of encrypted amount
- Small amounts (< ~10K) have overhead due to fixed iteration count — this is intentional for constant-time security
- At max supported amount (1M), BSGS is **123x faster**
- Memory usage: ~80KB for lookup table

## 2. Scalar Inversion: Batch vs Individual

Montgomery's batch inversion computes n modular inverses using only 1 inversion + 3(n-1) multiplications.

| Batch Size | Individual | Batch | Speedup |
|------------|------------|-------|---------|
| 4 | 13 µs | 4 µs | **3.3x** |
| 8 | 27 µs | 5 µs | **5.4x** |
| 16 | 53 µs | 7 µs | **7.9x** |
| 32 | 106 µs | 10 µs | **10x** |
| 64 | 212 µs | 18 µs | **12x** |

**Key observations:**
- Speedup increases with batch size (amortizes single expensive inversion)
- Used in IPA verification where multiple scalar inverses are needed
- Theoretical speedup approaches n/3 for large n

## 3. Generator Cache: Cold vs Warm

NUMS (Nothing-Up-My-Sleeve) generators require hash-to-curve operations. Caching avoids recomputation.

| Generators | Cold (Compute) | Warm (Cached) | Speedup |
|------------|----------------|---------------|---------|
| 512 | 12.4 ms | 0.06 µs | **~210,000x** |

**Key observations:**
- First access computes and caches generators (~12ms for 512)
- Subsequent accesses return cached pointers (~60ns)
- Cache persists for process lifetime
- Call `secp256k1_mpt_free_generator_cache()` at shutdown to release memory

## Methodology

Benchmarks simulate original implementations:
- **Brute-force decryption**: Linear search computing G, 2G, 3G, ... until match
- **Individual inversion**: Separate `secp256k1_mpt_scalar_inverse()` calls
- **Cold cache**: Fresh computation via `secp256k1_mpt_free_generator_cache()` before measurement

Timing uses `clock_gettime(CLOCK_MONOTONIC)` with nanosecond precision.

## Running Benchmarks

```bash
cd build
ctest -R bench --output-on-failure
```

Or run the comparison benchmark directly (if compiled):
```bash
./bench_comparison
```

