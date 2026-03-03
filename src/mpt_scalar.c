/**
 * @file mpt_scalar.c
 * @brief Scalar Field Arithmetic Abstraction Layer.
 *
 * This module provides a safe, portable interface for performing arithmetic
 * in the scalar field of the secp256k1 curve (integers modulo \f$ n \f$, the
 * group order).
 *
 * @details
 * **Purpose:**
 * While `libsecp256k1` exposes point operations via its public API, it does not
 * typically expose low-level scalar arithmetic. However, protocols like
 * Bulletproofs and ElGamal require extensive scalar math (e.g., polynomial
 * evaluation, inner products) to be performed by the client.
 *
 * **Implementation:**
 * This file includes internal `libsecp256k1` headers (`scalar.h`,
 * `scalar_impl.h`) to access the optimized, constant-time scalar
 * implementations.
 *
 * **Operations:**
 * All operations are performed modulo the curve order \f$ n \f$:
 * - Addition: \f$ a + b \pmod{n} \f$
 * - Multiplication: \f$ a \cdot b \pmod{n} \f$
 * - Inversion: \f$ a^{-1} \pmod{n} \f$
 * - Negation: \f$ -a \pmod{n} \f$
 *
 * **Platform Specifics:**
 * Includes logic for 128-bit integer support (`int128.h`) required for
 * efficient computation on modern architectures (e.g., ARM64/Apple Silicon).
 *
 * @warning These functions operate on 32-byte big-endian scalars. Inputs must
 * be properly reduced or handled by `secp256k1_mpt_scalar_reduce32` before use
 * if they might exceed \f$ n \f$.
 */

#include "secp256k1_mpt.h"
#include <openssl/crypto.h>
#include <string.h>

/* Include low-level utilities first.
      On ARM64/Apple Silicon, the scalar math depends on 128-bit
      integer helpers defined in these headers. */
#include <private/int128.h>
#include <private/int128_impl.h>
#include <private/util.h>

/* Include the actual scalar implementations */
#include <private/scalar.h>
#include <private/scalar_impl.h>

/* --- Implementation --- */

void secp256k1_mpt_scalar_add(unsigned char *res, const unsigned char *a,
                              const unsigned char *b)
{
  secp256k1_scalar s_res, s_a, s_b;
  secp256k1_scalar_set_b32(&s_a, a, NULL);
  secp256k1_scalar_set_b32(&s_b, b, NULL);
  secp256k1_scalar_add(&s_res, &s_a, &s_b);
  secp256k1_scalar_get_b32(res, &s_res);

  /* SECURE CLEANUP */
  OPENSSL_cleanse(&s_a, sizeof(s_a));
  OPENSSL_cleanse(&s_b, sizeof(s_b));
  OPENSSL_cleanse(&s_res, sizeof(s_res));
}

void secp256k1_mpt_scalar_mul(unsigned char *res, const unsigned char *a,
                              const unsigned char *b)
{
  secp256k1_scalar s_res, s_a, s_b;
  secp256k1_scalar_set_b32(&s_a, a, NULL);
  secp256k1_scalar_set_b32(&s_b, b, NULL);
  secp256k1_scalar_mul(&s_res, &s_a, &s_b);
  secp256k1_scalar_get_b32(res, &s_res);

  /* SECURE CLEANUP */
  OPENSSL_cleanse(&s_a, sizeof(s_a));
  OPENSSL_cleanse(&s_b, sizeof(s_b));
  OPENSSL_cleanse(&s_res, sizeof(s_res));
}

void secp256k1_mpt_scalar_inverse(unsigned char *res, const unsigned char *in)
{
  secp256k1_scalar s;
  secp256k1_scalar_set_b32(&s, in, NULL);
  secp256k1_scalar_inverse(&s, &s);
  secp256k1_scalar_get_b32(res, &s);

  /* SECURE CLEANUP */
  OPENSSL_cleanse(&s, sizeof(s));
}

void secp256k1_mpt_scalar_negate(unsigned char *res, const unsigned char *in)
{
  secp256k1_scalar s;
  secp256k1_scalar_set_b32(&s, in, NULL);
  secp256k1_scalar_negate(&s, &s);
  secp256k1_scalar_get_b32(res, &s);

  /* SECURE CLEANUP */
  OPENSSL_cleanse(&s, sizeof(s));
}

void secp256k1_mpt_scalar_reduce32(unsigned char out32[32],
                                   const unsigned char in32[32])
{
  secp256k1_scalar s;
  secp256k1_scalar_set_b32(&s, in32, NULL);
  secp256k1_scalar_get_b32(out32, &s);

  /* SECURE CLEANUP */
  OPENSSL_cleanse(&s, sizeof(s));
}

/**
 * @brief Batch inversion using Montgomery's trick.
 *
 * Computes the multiplicative inverse of n scalars using only 1 inversion
 * and 3*(n-1) multiplications, instead of n inversions.
 *
 * Algorithm:
 * 1. Compute prefix products: p[i] = in[0] * in[1] * ... * in[i]
 * 2. Invert the final product: inv_all = p[n-1]^{-1}
 * 3. Compute inverses in reverse: out[i] = inv_all * p[i-1], then update
 *    inv_all *= in[i]
 *
 * @param out    Output array of n 32-byte inverse scalars
 * @param in     Input array of n 32-byte scalars (must be non-zero)
 * @param n      Number of scalars to invert
 * @return 1 on success, 0 on failure (if any input is zero)
 */
int secp256k1_mpt_scalar_batch_inverse(unsigned char *out,
                                       const unsigned char *in, size_t n)
{
  if (n == 0)
    return 1;

  if (n == 1)
  {
    secp256k1_mpt_scalar_inverse(out, in);
    return 1;
  }

  /* Allocate prefix products */
  secp256k1_scalar *s_prefix =
      (secp256k1_scalar *)malloc(n * sizeof(secp256k1_scalar));
  secp256k1_scalar *s_in =
      (secp256k1_scalar *)malloc(n * sizeof(secp256k1_scalar));
  if (!s_prefix || !s_in)
  {
    free(s_prefix);
    free(s_in);
    return 0;
  }

  int ok = 0;
  secp256k1_scalar inv_all, tmp;

  /* Parse all inputs and check for zeros */
  for (size_t i = 0; i < n; i++)
  {
    int overflow;
    secp256k1_scalar_set_b32(&s_in[i], in + i * 32, &overflow);
    if (secp256k1_scalar_is_zero(&s_in[i]))
      goto cleanup; /* Zero input - cannot invert */
  }

  /* Step 1: Compute prefix products */
  s_prefix[0] = s_in[0];
  for (size_t i = 1; i < n; i++)
  {
    secp256k1_scalar_mul(&s_prefix[i], &s_prefix[i - 1], &s_in[i]);
  }

  /* Step 2: Invert the final product */
  secp256k1_scalar_inverse(&inv_all, &s_prefix[n - 1]);

  /* Step 3: Compute individual inverses in reverse */
  for (size_t i = n - 1; i > 0; i--)
  {
    /* out[i] = inv_all * prefix[i-1] */
    secp256k1_scalar_mul(&tmp, &inv_all, &s_prefix[i - 1]);
    secp256k1_scalar_get_b32(out + i * 32, &tmp);

    /* inv_all = inv_all * in[i] */
    secp256k1_scalar_mul(&inv_all, &inv_all, &s_in[i]);
  }

  /* out[0] = inv_all (which is now in[0]^{-1}) */
  secp256k1_scalar_get_b32(out, &inv_all);

  ok = 1;

cleanup:
  /* SECURE CLEANUP */
  OPENSSL_cleanse(s_prefix, n * sizeof(secp256k1_scalar));
  OPENSSL_cleanse(s_in, n * sizeof(secp256k1_scalar));
  OPENSSL_cleanse(&inv_all, sizeof(inv_all));
  OPENSSL_cleanse(&tmp, sizeof(tmp));
  free(s_prefix);
  free(s_in);
  return ok;
}
