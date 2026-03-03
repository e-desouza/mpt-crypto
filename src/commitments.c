/**
 * @file commitments.c
 * @brief Pedersen Commitments and NUMS Generator Derivation.
 *
 * This module implements the core commitment scheme used in Confidential MPTs.
 * It provides functions to generate Pedersen commitments of the form
 * \f$ C = v \cdot G + r \cdot H \f$, where \f$ G \f$ and \f$ H \f$ are
 * independent generators of the secp256k1 curve.
 *
 * @details
 * **NUMS Generators:**
 * To ensure the binding property of the commitments (i.e., that a user cannot
 * open a commitment to two different values), the discrete logarithm of \f$ H
 * \f$ with respect to \f$ G \f$ must be unknown.
 *
 * This implementation uses a "Nothing-Up-My-Sleeve" (NUMS) construction:
 * - Generators are derived deterministically using SHA-256 hash-to-curve.
 * - The domain separation tag is `"MPT_BULLETPROOF_V1_NUMS"`.
 * - This guarantees that no backdoors exist in the system parameters.
 *
 * **Commitment Logic:**
 * The commitment function handles the edge case where the amount \f$ v = 0 \f$.
 * Since the point at infinity (identity) cannot be serialized in standard
 * compressed form, the term \f$ 0 \cdot G \f$ is handled logically, resulting
 * in \f$ C = r \cdot H \f$.
 *
 * @see [Spec (ConfidentialMPT_20260201.pdf) Section 3.3.5] Linking ElGamal
 * Ciphertexts and Pedersen Commitments
 */
#include "secp256k1_mpt.h"
#include <openssl/crypto.h> // For OPENSSL_cleanse
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>

/* --- Generator Cache for Bulletproofs Optimization --- */

/**
 * Maximum number of generators to cache per vector (G and H).
 * For 64*m aggregation with m up to 16, we need 1024 generators.
 * Adjust as needed for your use case.
 */
#define MPT_GEN_CACHE_MAX_SIZE 1024

typedef struct
{
  secp256k1_pubkey *G_vec;
  secp256k1_pubkey *H_vec;
  secp256k1_pubkey H_single; /* The standard H for Pedersen commitments */
  size_t G_cached;
  size_t H_cached;
  int H_single_valid;
  int initialized;
} mpt_generator_cache_t;

/* Global generator cache (lazy-initialized, thread-safe reads after init) */
static mpt_generator_cache_t g_gen_cache = {
    .G_vec = NULL,
    .H_vec = NULL,
    .G_cached = 0,
    .H_cached = 0,
    .H_single_valid = 0,
    .initialized = 0};

/**
 * @brief Initialize or expand the generator cache.
 *
 * This ensures at least `n` generators are cached for both G and H vectors.
 * Thread-safety: This function is NOT thread-safe; call during initialization.
 *
 * @param ctx    secp256k1 context
 * @param n      Minimum number of generators needed
 * @return 1 on success, 0 on failure
 */
static int ensure_generator_cache(const secp256k1_context *ctx, size_t n)
{
  if (n > MPT_GEN_CACHE_MAX_SIZE)
    return 0; /* Exceeds max cache size */

  /* Cache the single H generator if not done */
  if (!g_gen_cache.H_single_valid)
  {
    if (!secp256k1_mpt_hash_to_point_nums(ctx, &g_gen_cache.H_single,
                                          (const unsigned char *)"H", 1, 0))
      return 0;
    g_gen_cache.H_single_valid = 1;
  }

  /* Expand G vector if needed */
  if (g_gen_cache.G_cached < n)
  {
    secp256k1_pubkey *new_G = (secp256k1_pubkey *)realloc(
        g_gen_cache.G_vec, n * sizeof(secp256k1_pubkey));
    if (!new_G)
      return 0;
    g_gen_cache.G_vec = new_G;

    for (size_t i = g_gen_cache.G_cached; i < n; i++)
    {
      if (!secp256k1_mpt_hash_to_point_nums(ctx, &g_gen_cache.G_vec[i],
                                            (const unsigned char *)"G", 1,
                                            (uint32_t)i))
        return 0;
    }
    g_gen_cache.G_cached = n;
  }

  /* Expand H vector if needed */
  if (g_gen_cache.H_cached < n)
  {
    secp256k1_pubkey *new_H = (secp256k1_pubkey *)realloc(
        g_gen_cache.H_vec, n * sizeof(secp256k1_pubkey));
    if (!new_H)
      return 0;
    g_gen_cache.H_vec = new_H;

    for (size_t i = g_gen_cache.H_cached; i < n; i++)
    {
      /* Note: H vector for Bulletproofs uses "H" label with index starting at 1
       * to distinguish from the single H generator at index 0 */
      if (!secp256k1_mpt_hash_to_point_nums(ctx, &g_gen_cache.H_vec[i],
                                            (const unsigned char *)"H", 1,
                                            (uint32_t)(i + 1)))
        return 0;
    }
    g_gen_cache.H_cached = n;
  }

  g_gen_cache.initialized = 1;
  return 1;
}

/**
 * @brief Get cached G vector generators.
 *
 * Returns a pointer to the cached generators (do not free).
 * Automatically expands cache if needed.
 *
 * @param ctx    secp256k1 context
 * @param n      Number of generators needed
 * @return Pointer to G_vec or NULL on failure
 */
const secp256k1_pubkey *secp256k1_mpt_get_cached_G_vec(
    const secp256k1_context *ctx, size_t n)
{
  if (!ensure_generator_cache(ctx, n))
    return NULL;
  return g_gen_cache.G_vec;
}

/**
 * @brief Get cached H vector generators.
 */
const secp256k1_pubkey *secp256k1_mpt_get_cached_H_vec(
    const secp256k1_context *ctx, size_t n)
{
  if (!ensure_generator_cache(ctx, n))
    return NULL;
  return g_gen_cache.H_vec;
}

/**
 * @brief Get the cached single H generator (for Pedersen commitments).
 */
int secp256k1_mpt_get_cached_h_generator(const secp256k1_context *ctx,
                                         secp256k1_pubkey *h)
{
  if (!ensure_generator_cache(ctx, 0))
    return 0;
  *h = g_gen_cache.H_single;
  return 1;
}

/**
 * @brief Free all cached generators.
 *
 * Call this during shutdown to release memory.
 */
void secp256k1_mpt_free_generator_cache(void)
{
  free(g_gen_cache.G_vec);
  free(g_gen_cache.H_vec);
  g_gen_cache.G_vec = NULL;
  g_gen_cache.H_vec = NULL;
  g_gen_cache.G_cached = 0;
  g_gen_cache.H_cached = 0;
  g_gen_cache.H_single_valid = 0;
  g_gen_cache.initialized = 0;
}

/* --- Internal Helpers --- */

/**
 * @brief Deterministically derives a NUMS (Nothing-Up-My-Sleeve) generator
 * point.
 * * Uses SHA-256 try-and-increment to find a valid x-coordinate. This ensures
 * the discrete logarithm of the resulting point is unknown, which is a core
 * security requirement for Bulletproof binding and vector commitments.
 *
 * @param ctx       secp256k1 context (VERIFY flag required).
 * @param out       The derived public key generator.
 * @param label     Domain/vector label (e.g., "G" or "H").
 * @param label_len Length of the label string.
 * @param index     Vector index (enforced Big-Endian).
 * @return 1 on success, 0 on failure.
 */
int secp256k1_mpt_hash_to_point_nums(const secp256k1_context *ctx,
                                     secp256k1_pubkey *out,
                                     const unsigned char *label,
                                     size_t label_len, uint32_t index)
{
  unsigned char hash[32];
  unsigned char compressed[33];
  uint32_t ctr = 0;

  unsigned char idx_be[4] = {
      (unsigned char)(index >> 24), (unsigned char)(index >> 16),
      (unsigned char)(index >> 8), (unsigned char)(index & 0xFF)};

  /* Try-and-increment loop */
  while (ctr < 0xFFFFFFFFu)
  {
    unsigned char ctr_be[4] = {
        (unsigned char)(ctr >> 24), (unsigned char)(ctr >> 16),
        (unsigned char)(ctr >> 8), (unsigned char)(ctr & 0xFF)};

    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, "MPT_BULLETPROOF_V1_NUMS", 23); // Domain Sep
    SHA256_Update(&sha, "secp256k1", 9);                // Curve Label

    if (label && label_len > 0)
    {
      SHA256_Update(&sha, label, label_len);
    }

    SHA256_Update(&sha, idx_be, 4);
    SHA256_Update(&sha, ctr_be, 4);
    SHA256_Final(hash, &sha);

    /* Construct compressed point candidate */
    compressed[0] =
        0x02; /* Force even Y (standard convention for unique points) */
    memcpy(&compressed[1], hash, 32);

    /* Check validity on curve */
    if (secp256k1_ec_pubkey_parse(ctx, out, compressed, 33) == 1)
    {
      return 1;
    }
    ctr++;
  }
  return 0; // Extremely unlikely to reach here
}

/**
 * @brief Derives the secondary base point (H) for Pedersen commitments.
 * * This derives a NUMS point using the label "H" at index 0. This H is
 * used alongside the standard generator G to form the commitment
 * C = v*G + r*H. Using a NUMS point ensures that the discrete logarithm
 * of H with respect to G is unknown.
 *
 * @param ctx  secp256k1 context.
 * @param h    The resulting H generator public key.
 * @return 1 on success, 0 on failure.
 */
int secp256k1_mpt_get_h_generator(const secp256k1_context *ctx,
                                  secp256k1_pubkey *h)
{
  return secp256k1_mpt_hash_to_point_nums(ctx, h, (const unsigned char *)"H", 1,
                                          0);
}

/**
 * @brief Generates a vector of N independent NUMS generators.
 * * Used to populate the G_i and H_i vectors for Bulletproofs. Each point
 * is derived deterministically from the provided label and its index.
 *
 * @param ctx       secp256k1 context.
 * @param vec       Array to store the resulting generators.
 * @param n         Number of generators to derive.
 * @param label     The label string ("G" or "H").
 * @param label_len Length of the label string.
 * @return 1 on success, 0 on failure.
 */
int secp256k1_mpt_get_generator_vector(const secp256k1_context *ctx,
                                       secp256k1_pubkey *vec, size_t n,
                                       const unsigned char *label,
                                       size_t label_len)
{
  for (uint32_t i = 0; i < (uint32_t)n; i++)
  {
    if (!secp256k1_mpt_hash_to_point_nums(ctx, &vec[i], label, label_len, i))
    {
      return 0;
    }
  }
  return 1;
}

/* --- Public API --- */

/**
 * @brief Creates a Pedersen Commitment C = amount*G + rho*H.
 * * @param ctx         secp256k1 context.
 * @param commitment  Output commitment public key.
 * @param amount      The value to commit to.
 * @param rho         The blinding factor (randomness).
 * @return 1 on success, 0 on failure.
 */
int secp256k1_mpt_pedersen_commit(const secp256k1_context *ctx,
                                  secp256k1_pubkey *commitment, uint64_t amount,
                                  const unsigned char *rho)
{
  secp256k1_pubkey mG, rH, H;
  unsigned char m_scalar[32] = {0};
  int ok = 0;

  /* 0. Input Check */
  if (!secp256k1_ec_seckey_verify(ctx, rho))
    return 0;

  /* 1. Calculate rho*H (Blinding Term) */
  /* We do this first so we can use it directly if amount is 0 */
  if (!secp256k1_mpt_get_h_generator(ctx, &H))
    return 0;

  rH = H;
  if (!secp256k1_ec_pubkey_tweak_mul(ctx, &rH, rho))
    return 0;

  /* 2. Handle Zero Amount Case */
  if (amount == 0)
  {
    /* If m=0, C = 0*G + r*H = r*H */
    *commitment = rH;
    return 1;
  }

  /* 3. Calculate m*G (Value Term) */
  /* Convert uint64 amount to big-endian scalar */
  for (int i = 0; i < 8; i++)
  {
    m_scalar[31 - i] = (amount >> (i * 8)) & 0xFF;
  }

  /* This check passes now because we handled amount==0 above */
  if (!secp256k1_ec_pubkey_create(ctx, &mG, m_scalar))
    goto cleanup;

  /* 4. Combine: C = mG + rH */
  const secp256k1_pubkey *points[2] = {&mG, &rH};
  if (!secp256k1_ec_pubkey_combine(ctx, commitment, points, 2))
    goto cleanup;

  ok = 1;

cleanup:
  /* Securely clear the amount scalar from stack */
  OPENSSL_cleanse(m_scalar, 32);
  return ok;
}
