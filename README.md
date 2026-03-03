# MPT-Crypto: Cryptographic Primitives for Confidential Assets

## Overview

**MPT-Crypto** is a specialized C library implementing the cryptographic building blocks for
**Confidential Multi-Purpose Tokens (MPT)** on the XRP Ledger. It provides implementations of homomorphic encryption, aggregated range proofs, and specialized zero-knowledge proofs.
The library is built on top of `libsecp256k1` for elliptic curve arithmetic and OpenSSL for hashing and randomness.

## Features

### 1. Confidential Balances (EC-ElGamal)

- **Additive Homomorphic Encryption:** Enables the ledger to aggregate encrypted balances (e.g., `Enc(A) + Enc(B) = Enc(A+B)`) without decryption.
- **Canonical Zero:** Deterministic encryption of zero balances to prevent ledger state bloat and ensure consistency.
- **Constant-Time Decryption (BSGS):** Uses Baby-Step Giant-Step algorithm for O(√n) decryption with fixed execution time, providing defense in depth against timing side-channels.

### 2. Range Proofs (Bulletproofs)

- **Aggregated Proofs:** Supports proving that $m$ values are within the range $[0, 2^{64})$ in a single proof with logarithmic size $\mathcal{O}(\log n)$.
- **Inner Product Argument (IPA):** Implements the standard Bulletproofs IPA for succinct verification.
- **Fiat-Shamir:** Secure non-interactive challenge generation with strict domain separation.

### 3. Zero-Knowledge Proofs (Sigma Protocols)

- **Plaintext Equality:** Proves two or more ciphertexts encrypt the same amount under different keys.
- **Batch Verification:** Efficiently verify multiple same-plaintext proofs in a single API call.
- **Linkage Proof:** Proves consistency between an ElGamal ciphertext (used for transfer) and a Pedersen Commitment (used for the range proof).
- **Proof of Knowledge (PoK):** Proves ownership of the secret key during account registration to prevent rogue key attacks.

### 4. Performance Optimizations

- **Generator Cache:** Lazy-initialized cache for NUMS (Nothing-Up-My-Sleeve) generators, avoiding repeated hash-to-curve operations during proof generation/verification.
- **Batch Scalar Inversion:** Montgomery's trick for computing multiple modular inverses with a single inversion operation, providing 3-13x speedup for IPA computations.

See [docs/PERF.md](docs/PERF.md) for detailed benchmarks.

## Security Considerations

### Constant-Time Decryption (Defense in Depth)

ElGamal decryption requires solving the discrete logarithm problem (DLP) for small values. A naive brute-force search leaks the encrypted amount through timing: decrypting amount=100 is faster than amount=1,000,000.

While decryption typically occurs client-side in trusted environments, this library implements **Baby-Step Giant-Step (BSGS)** as a defense-in-depth measure:

- **Fixed iteration count:** Always performs the same number of operations regardless of the encrypted value
- **Constant-time lookups:** Hash table operations use constant-time comparison to prevent cache-timing attacks
- **O(√n) complexity:** ~1000 iterations for amounts up to 1,000,000 (vs 1,000,000 for brute-force)

```c
// Initialize BSGS table once at startup (~80KB, ~4ms)
secp256k1_elgamal_bsgs_init(ctx);

// Decryption now runs in constant time (~30ms regardless of amount)
secp256k1_elgamal_decrypt(ctx, &amount, c1, c2, privkey);

// Cleanup at shutdown
secp256k1_elgamal_bsgs_free();
```

### Memory Cleanup

All secret scalars are securely wiped using `OPENSSL_cleanse()` after use.

## Building and Testing

### Prerequisites

Before building, ensure you have the following installed:

- **CMake** (version 3.10 or higher)
- **C Compiler** (GCC, Clang, or AppleClang)

On macOS with Homebrew:

```bash
brew install cmake
```

On Ubuntu/Debian:

```bash
sudo apt-get install cmake build-essential
```

### Dependency Setup

Set up Conan using [xrpld's BUILD.md](https://github.com/XRPLF/rippled/blob/develop/BUILD.md#steps)

### Build Instructions

Run following commands to build the library

1. Create build directory:

   ```bash
   mkdir build && cd build
   ```

2. Buld dependencies:

   ```bash
   conan install .. --build=missing -o "&:tests=True"
   ```

3. Run CMake:

   ```bash
   cmake .. \
      -DCMAKE_BUILD_TYPE=Release \
      -G Ninja \
      -DCMAKE_TOOLCHAIN_FILE:FILEPATH=build/generators/conan_toolchain.cmake
   ```

4. **Build the library and tests:**

   ```bash
   ninja
   ```

### Running Tests

After building, run the test suite using CTest from the build directory:

```bash
ctest --output-on-failure
```

Or run individual tests directly:

```bash
./tests/test_elgamal
./tests/test_bulletproof_agg
./tests/test_commitments
```

### Expected Results

The following tests should pass:

- `test_bulletproof_agg` - Aggregated Bulletproof range proofs
- `test_commitments` - Pedersen commitments
- `test_elgamal` - ElGamal encryption/decryption
- `test_elgamal_verify` - ElGamal verification
- `test_equality_proof` - Equality proofs
- `test_ipa` - Inner Product Argument (IPA) Core Logic
- `test_link_proof` - Linkage proofs
- `test_pok_sk` - Proof of knowledge of secret key
- `test_same_plaintext` - Same plaintext proofs
- `test_same_plaintext_multi` - Multi-recipient same plaintext proofs
- `test_same_plaintext_multi_shared_r` - Shared randomness variant

**Note:** `test_bulletproof.c` is excluded from the build because the aggregated implementation (bulletproof_aggregated.c) is fully general; verifying the m=1 case is now covered by test_bulletproof_agg.c.

## API Reference

### ElGamal Encryption

| Function | Description |
|----------|-------------|
| `secp256k1_elgamal_generate_keypair()` | Generate a new key pair |
| `secp256k1_elgamal_encrypt()` | Encrypt an amount |
| `secp256k1_elgamal_decrypt()` | Decrypt a ciphertext (constant-time with BSGS) |
| `secp256k1_elgamal_add()` | Homomorphically add two ciphertexts |
| `secp256k1_elgamal_subtract()` | Homomorphically subtract two ciphertexts |
| `secp256k1_elgamal_bsgs_init()` | Initialize BSGS lookup table (~80KB) |
| `secp256k1_elgamal_bsgs_free()` | Free BSGS table memory |

### Generator Cache

| Function | Description |
|----------|-------------|
| `secp256k1_mpt_get_cached_G_vec()` | Get cached G vector generators for Bulletproofs |
| `secp256k1_mpt_get_cached_H_vec()` | Get cached H vector generators for Bulletproofs |
| `secp256k1_mpt_get_cached_h_generator()` | Get cached single H generator for Pedersen |
| `secp256k1_mpt_free_generator_cache()` | Free all cached generators |

### Scalar Operations

| Function | Description |
|----------|-------------|
| `secp256k1_mpt_scalar_add()` | Add two scalars mod n |
| `secp256k1_mpt_scalar_mul()` | Multiply two scalars mod n |
| `secp256k1_mpt_scalar_inverse()` | Compute modular inverse |
| `secp256k1_mpt_scalar_batch_inverse()` | Batch inversion using Montgomery's trick |
| `secp256k1_mpt_scalar_negate()` | Negate a scalar mod n |

### Zero-Knowledge Proofs

| Function | Description |
|----------|-------------|
| `secp256k1_mpt_prove_same_plaintext()` | Prove two ciphertexts encrypt the same value |
| `secp256k1_mpt_verify_same_plaintext()` | Verify same-plaintext proof |
| `secp256k1_mpt_batch_verify_same_plaintext()` | Batch verify multiple proofs |
| `secp256k1_elgamal_pedersen_link_prove()` | Prove ElGamal-Pedersen linkage |
| `secp256k1_elgamal_pedersen_link_verify()` | Verify linkage proof |
| `secp256k1_mpt_pok_sk_prove()` | Prove knowledge of secret key |
| `secp256k1_mpt_pok_sk_verify()` | Verify PoK proof |
