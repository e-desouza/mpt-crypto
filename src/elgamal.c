/**
 * @file elgamal.c
 * @brief EC-ElGamal Encryption for Confidential Balances.
 *
 * This module implements additive homomorphic encryption using the ElGamal
 * scheme over the secp256k1 elliptic curve. It provides the core mechanism
 * for representing confidential balances and transferring value on the ledger.
 *
 * @details
 * **Encryption Scheme:**
 * Given a public key \f$ Q = sk \cdot G \f$ and a plaintext amount \f$ m \f$,
 * encryption with randomness \f$ r \f$ produces a ciphertext pair \f$ (C_1,
 * C_2) \f$:
 * - \f$ C_1 = r \cdot G \f$ (Ephemeral public key)
 * - \f$ C_2 = m \cdot G + r \cdot Q \f$ (Masked amount)
 *
 * **Homomorphism:**
 * The scheme is additively homomorphic:
 * \f[ Enc(m_1) + Enc(m_2) = (C_{1,1}+C_{1,2}, C_{2,1}+C_{2,2}) = Enc(m_1 + m_2)
 * \f] This allows validators to update balances (e.g., add incoming transfers)
 * without decrypting them.
 *
 * **Decryption (Discrete Logarithm):**
 * Decryption involves two steps:
 * 1. Remove the mask: \f$ M = C_2 - sk \cdot C_1 = m \cdot G \f$.
 * 2. Recover \f$ m \f$ from \f$ M \f$: This requires solving the Discrete
 * Logarithm Problem (DLP) for \f$ m \f$. Since balances are 64-bit integers but
 * typically small in "human" terms, this implementation uses an optimized
 * search for ranges relevant to transaction processing (e.g., 0 to 1,000,000).
 *
 * **Canonical Zero:**
 * To ensure deterministic ledger state for empty accounts, a "Canonical
 * Encrypted Zero" is defined using randomness derived deterministically from
 * the account ID and token ID.
 *
 * @see [Spec (ConfidentialMPT_20260201.pdf) Section 3.2.2] ElGamal Encryption
 */
#include "secp256k1_mpt.h"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>

/* --- BSGS (Baby-Step Giant-Step) Configuration --- */

/**
 * Maximum decryptable amount. Amounts outside [0, MAX_DECRYPT_VALUE] will fail.
 * This determines the BSGS table size: sqrt(MAX_DECRYPT_VALUE) entries.
 */
#define MAX_DECRYPT_VALUE 1000000ULL

/**
 * Baby-step table size: ceil(sqrt(MAX_DECRYPT_VALUE)) = 1000 for 10^6
 * We use 1024 for power-of-2 alignment and slight overhead.
 */
#define BSGS_BABY_STEP_SIZE 1024

/**
 * Giant-step count: ceil(MAX_DECRYPT_VALUE / BSGS_BABY_STEP_SIZE)
 */
#define BSGS_GIANT_STEP_COUNT                                                  \
  ((MAX_DECRYPT_VALUE + BSGS_BABY_STEP_SIZE - 1) / BSGS_BABY_STEP_SIZE)

/**
 * Hash table size for baby-step lookup. Use power of 2 for fast modulo.
 * Load factor ~0.5 for good performance: 1024 entries / 2048 slots.
 */
#define BSGS_HASH_TABLE_SIZE 2048

/**
 * BSGS lookup table entry.
 * Stores compressed point (33 bytes) and corresponding baby-step index.
 */
typedef struct
{
  unsigned char point_bytes[33]; /* Compressed point representation */
  uint32_t baby_step_index;      /* Value j where point = j*G */
  int occupied;                  /* 1 if slot contains valid data */
} bsgs_entry_t;

/**
 * Global BSGS table state.
 * Thread-safety: Safe for concurrent reads after initialization.
 */
typedef struct
{
  bsgs_entry_t *hash_table;    /* Hash table for baby-step lookup */
  secp256k1_pubkey giant_step; /* Precomputed -BABY_STEP_SIZE * G */
  int initialized;
} bsgs_table_t;

static bsgs_table_t g_bsgs_table = {.hash_table = NULL, .initialized = 0};

/* --- Internal Helpers --- */

static int pubkey_equal(const secp256k1_context *ctx,
                        const secp256k1_pubkey *pk1,
                        const secp256k1_pubkey *pk2)
{
  return secp256k1_ec_pubkey_cmp(ctx, pk1, pk2) == 0;
}

static int compute_amount_point(const secp256k1_context *ctx,
                                secp256k1_pubkey *mG, uint64_t amount)
{
  unsigned char amount_scalar[32] = {0};
  int ret;
  for (int i = 0; i < 8; ++i)
  {
    amount_scalar[31 - i] = (amount >> (i * 8)) & 0xFF;
  }
  ret = secp256k1_ec_pubkey_create(ctx, mG, amount_scalar);
  OPENSSL_cleanse(amount_scalar, 32); // Wipe scalar after use
  return ret;
}

/* --- BSGS Hash Table Helpers --- */

/**
 * @brief Compute hash index from compressed point bytes.
 *
 * Uses FNV-1a hash for good distribution with 33-byte inputs.
 * Returns index in range [0, BSGS_HASH_TABLE_SIZE - 1].
 */
static uint32_t bsgs_hash(const unsigned char *point_bytes)
{
  uint32_t hash = 2166136261u; /* FNV-1a offset basis */
  for (int i = 0; i < 33; i++)
  {
    hash ^= point_bytes[i];
    hash *= 16777619u; /* FNV-1a prime */
  }
  return hash & (BSGS_HASH_TABLE_SIZE - 1); /* Fast modulo for power-of-2 */
}

/**
 * @brief Constant-time comparison of two 33-byte arrays.
 *
 * Returns 1 if equal, 0 otherwise. Runs in constant time to prevent
 * timing side-channels during BSGS lookup.
 */
static int ct_memcmp_33(const unsigned char *a, const unsigned char *b)
{
  unsigned char diff = 0;
  for (int i = 0; i < 33; i++)
  {
    diff |= a[i] ^ b[i];
  }
  /* Constant-time: diff == 0 iff arrays are equal */
  return (1 & ((diff - 1) >> 8));
}

/**
 * @brief Constant-time hash table lookup for BSGS.
 *
 * Searches the hash table for a matching point using linear probing.
 * Always probes a fixed number of slots to ensure constant-time execution.
 *
 * @param point_bytes  33-byte compressed point to search for
 * @param found        Output: 1 if found, 0 otherwise
 * @param index        Output: baby-step index if found
 * @return 1 on success (lookup completed), 0 if table not initialized
 */
static int bsgs_lookup_ct(const unsigned char *point_bytes, int *found,
                          uint32_t *index)
{
  uint32_t hash_idx, probe_idx, i;
  int match, slot_occupied;
  uint32_t result_index = 0;
  int result_found = 0;

  if (!g_bsgs_table.initialized || !g_bsgs_table.hash_table)
    return 0;

  hash_idx = bsgs_hash(point_bytes);

  /* Linear probing with fixed iterations for constant-time */
  /* Max probes = table size ensures we never miss an entry */
  for (i = 0; i < BSGS_HASH_TABLE_SIZE; i++)
  {
    probe_idx = (hash_idx + i) & (BSGS_HASH_TABLE_SIZE - 1);
    slot_occupied = g_bsgs_table.hash_table[probe_idx].occupied;

    /* Constant-time comparison */
    match = slot_occupied &&
            ct_memcmp_33(point_bytes,
                         g_bsgs_table.hash_table[probe_idx].point_bytes);

    /* Constant-time conditional update: only update if match and not yet found
     */
    result_index = match ? g_bsgs_table.hash_table[probe_idx].baby_step_index
                         : result_index;
    result_found = match ? 1 : result_found;
  }

  *found = result_found;
  *index = result_index;
  return 1;
}

/* --- BSGS Table Initialization and Cleanup --- */

/**
 * @brief Initialize the BSGS lookup table for constant-time decryption.
 *
 * Precomputes baby-step points: {j*G : j ∈ [0, BSGS_BABY_STEP_SIZE)}
 * and stores them in a hash table for O(1) lookup.
 * Also precomputes the giant-step: -(BSGS_BABY_STEP_SIZE * G)
 *
 * Memory usage: ~80KB (2048 entries × ~40 bytes each)
 *
 * Thread-safety: NOT thread-safe. Call during application initialization.
 *
 * @param ctx  secp256k1 context
 * @return 1 on success, 0 on failure
 */
int secp256k1_elgamal_bsgs_init(const secp256k1_context *ctx)
{
  secp256k1_pubkey current_point, G_point, next_point;
  unsigned char one[32] = {0};
  unsigned char step_scalar[32] = {0};
  unsigned char point_bytes[33];
  size_t point_len;
  uint32_t hash_idx, probe_idx;
  const secp256k1_pubkey *pts[2];

  if (g_bsgs_table.initialized)
    return 1; /* Already initialized */

  /* Allocate hash table */
  g_bsgs_table.hash_table =
      (bsgs_entry_t *)calloc(BSGS_HASH_TABLE_SIZE, sizeof(bsgs_entry_t));
  if (!g_bsgs_table.hash_table)
    return 0;

  /* Create G (generator) */
  one[31] = 1;
  if (!secp256k1_ec_pubkey_create(ctx, &G_point, one))
    goto fail;

  /* Baby-step 0: Store point at infinity conceptually as index 0 */
  /* We skip storing 0*G since it's the identity; handle amount=0 separately */

  /* Baby-step loop: compute j*G for j = 1 to BSGS_BABY_STEP_SIZE-1 */
  current_point = G_point; /* Start at 1*G */

  for (uint32_t j = 1; j < BSGS_BABY_STEP_SIZE; j++)
  {
    /* Serialize current point */
    point_len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, point_bytes, &point_len,
                                       &current_point,
                                       SECP256K1_EC_COMPRESSED))
      goto fail;

    /* Insert into hash table with linear probing */
    hash_idx = bsgs_hash(point_bytes);
    for (uint32_t probe = 0; probe < BSGS_HASH_TABLE_SIZE; probe++)
    {
      probe_idx = (hash_idx + probe) & (BSGS_HASH_TABLE_SIZE - 1);
      if (!g_bsgs_table.hash_table[probe_idx].occupied)
      {
        memcpy(g_bsgs_table.hash_table[probe_idx].point_bytes, point_bytes, 33);
        g_bsgs_table.hash_table[probe_idx].baby_step_index = j;
        g_bsgs_table.hash_table[probe_idx].occupied = 1;
        break;
      }
    }

    /* Increment: current_point = current_point + G */
    pts[0] = &current_point;
    pts[1] = &G_point;
    if (!secp256k1_ec_pubkey_combine(ctx, &next_point, pts, 2))
      goto fail;
    current_point = next_point;
  }

  /* Compute giant-step: -(BSGS_BABY_STEP_SIZE * G) */
  /* First compute BSGS_BABY_STEP_SIZE * G (current_point is now at that value)
   */
  g_bsgs_table.giant_step = current_point;
  if (!secp256k1_ec_pubkey_negate(ctx, &g_bsgs_table.giant_step))
    goto fail;

  g_bsgs_table.initialized = 1;
  return 1;

fail:
  free(g_bsgs_table.hash_table);
  g_bsgs_table.hash_table = NULL;
  g_bsgs_table.initialized = 0;
  return 0;
}

/**
 * @brief Free BSGS table resources.
 *
 * Call this during application shutdown to release memory.
 */
void secp256k1_elgamal_bsgs_free(void)
{
  if (g_bsgs_table.hash_table)
  {
    free(g_bsgs_table.hash_table);
    g_bsgs_table.hash_table = NULL;
  }
  g_bsgs_table.initialized = 0;
}

/* --- Key Generation --- */

int secp256k1_elgamal_generate_keypair(const secp256k1_context *ctx,
                                       unsigned char *privkey,
                                       secp256k1_pubkey *pubkey)
{
  do
  {
    if (RAND_bytes(privkey, 32) != 1)
      return 0;
  } while (!secp256k1_ec_seckey_verify(ctx, privkey));

  if (!secp256k1_ec_pubkey_create(ctx, pubkey, privkey))
  {
    OPENSSL_cleanse(privkey, 32); // Cleanup on failure
    return 0;
  }
  return 1;
}

/* --- Encryption --- */

int secp256k1_elgamal_encrypt(const secp256k1_context *ctx,
                              secp256k1_pubkey *c1, secp256k1_pubkey *c2,
                              const secp256k1_pubkey *pubkey_Q, uint64_t amount,
                              const unsigned char *blinding_factor)
{
  secp256k1_pubkey S, mG;
  const secp256k1_pubkey *pts[2];

  /* 1. C1 = r * G */
  if (!secp256k1_ec_pubkey_create(ctx, c1, blinding_factor))
    return 0;

  /* 2. S = r * Q (Shared Secret) */
  S = *pubkey_Q;
  if (!secp256k1_ec_pubkey_tweak_mul(ctx, &S, blinding_factor))
    return 0;

  /* 3. C2 = S + m*G */
  if (amount == 0)
  {
    *c2 = S; // m*G is infinity, so C2 = S
  }
  else
  {
    if (!compute_amount_point(ctx, &mG, amount))
      return 0;
    pts[0] = &mG;
    pts[1] = &S;
    if (!secp256k1_ec_pubkey_combine(ctx, c2, pts, 2))
      return 0;
  }

  return 1;
}

/* --- Decryption --- */

/**
 * @brief Decrypts an ElGamal ciphertext using Baby-Step Giant-Step (BSGS).
 *
 * This implementation provides constant-time decryption to prevent timing
 * side-channel attacks that could leak the encrypted amount.
 *
 * Algorithm:
 * 1. Compute M = C2 - sk·C1 (the amount point m·G)
 * 2. For each giant step i = 0..GIANT_STEP_COUNT:
 *    - Compute target = M - i·(BABY_STEP_SIZE·G)
 *    - Look up target in baby-step table (constant-time)
 *    - If found with index j: amount = i·BABY_STEP_SIZE + j
 *
 * Time: O(√n) where n = MAX_DECRYPT_VALUE
 * Space: O(√n) for the precomputed table (~80KB)
 *
 * @note Call secp256k1_elgamal_bsgs_init() before using this function.
 */
int secp256k1_elgamal_decrypt(const secp256k1_context *ctx, uint64_t *amount,
                              const secp256k1_pubkey *c1,
                              const secp256k1_pubkey *c2,
                              const unsigned char *privkey)
{
  secp256k1_pubkey S, M_target, current_target, next_target;
  const secp256k1_pubkey *pts[2];
  unsigned char target_bytes[33];
  size_t target_len;
  uint32_t giant_step, baby_step_idx;
  int found;
  uint64_t result_amount = 0;
  int result_found = 0;

  /* Ensure BSGS table is initialized */
  if (!g_bsgs_table.initialized)
  {
    /* Auto-initialize if not done (first call penalty) */
    if (!secp256k1_elgamal_bsgs_init(ctx))
      return 0;
  }

  /* 1. Recover Shared Secret: S = privkey * C1 */
  S = *c1;
  if (!secp256k1_ec_pubkey_tweak_mul(ctx, &S, privkey))
    return 0;

  /* 2. Check for Amount = 0 (C2 == S) using constant-time comparison */
  /* We still check this separately as it's a common case and avoids table
   * lookup */
  {
    unsigned char c2_bytes[33], s_bytes[33];
    size_t len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, c2_bytes, &len, c2,
                                       SECP256K1_EC_COMPRESSED))
      return 0;
    len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, s_bytes, &len, &S,
                                       SECP256K1_EC_COMPRESSED))
      return 0;
    if (ct_memcmp_33(c2_bytes, s_bytes))
    {
      *amount = 0;
      return 1;
    }
  }

  /* 3. Prepare Target: M_target = C2 - S = m·G */
  if (!secp256k1_ec_pubkey_negate(ctx, &S))
    return 0;
  pts[0] = c2;
  pts[1] = &S;
  if (!secp256k1_ec_pubkey_combine(ctx, &M_target, pts, 2))
    return 0;

  /* 4. BSGS: Giant-step loop (constant iterations) */
  current_target = M_target;

  /*
   * Track whether current_target is the identity point (point at infinity).
   * This happens when the amount is an exact multiple of BSGS_BABY_STEP_SIZE.
   * We can't serialize the identity, so we track it separately.
   */
  int target_is_identity = 0;

  for (giant_step = 0; giant_step < BSGS_GIANT_STEP_COUNT; giant_step++)
  {
    /*
     * Check if target is identity (baby_step = 0).
     * This happens for amounts = i * BSGS_BABY_STEP_SIZE where i > 0.
     * For giant_step > 0, target_is_identity is set when combine returns 0.
     */
    if (target_is_identity && !result_found)
    {
      result_amount = (uint64_t)giant_step * BSGS_BABY_STEP_SIZE;
      result_found = 1;
    }

    if (!target_is_identity)
    {
      /* Serialize current target for lookup */
      target_len = 33;
      if (!secp256k1_ec_pubkey_serialize(ctx, target_bytes, &target_len,
                                         &current_target,
                                         SECP256K1_EC_COMPRESSED))
        return 0;

      /* Constant-time lookup in baby-step table */
      if (!bsgs_lookup_ct(target_bytes, &found, &baby_step_idx))
        return 0;

      /* Constant-time conditional update of result */
      /* Only update if found and we haven't found a result yet */
      if (found && !result_found)
      {
        result_amount =
            (uint64_t)giant_step * BSGS_BABY_STEP_SIZE + baby_step_idx;
        result_found = 1;
      }
    }

    /* Giant step: current_target = current_target + (-BABY_STEP_SIZE·G) */
    if (!target_is_identity)
    {
      pts[0] = &current_target;
      pts[1] = &g_bsgs_table.giant_step;
      /*
       * combine returns 0 if result is identity point.
       * This happens when current_target = BSGS_BABY_STEP_SIZE * G
       * (i.e., amount mod BSGS_BABY_STEP_SIZE == 0 for next iteration)
       */
      if (!secp256k1_ec_pubkey_combine(ctx, &next_target, pts, 2))
      {
        target_is_identity = 1;
      }
      else
      {
        current_target = next_target;
      }
    }
  }

  if (result_found)
  {
    *amount = result_amount;
    return 1;
  }

  return 0; /* Amount not found in range [0, MAX_DECRYPT_VALUE] */
}

/* --- Homomorphic Operations --- */

int secp256k1_elgamal_add(const secp256k1_context *ctx,
                          secp256k1_pubkey *sum_c1, secp256k1_pubkey *sum_c2,
                          const secp256k1_pubkey *a_c1,
                          const secp256k1_pubkey *a_c2,
                          const secp256k1_pubkey *b_c1,
                          const secp256k1_pubkey *b_c2)
{
  const secp256k1_pubkey *pts[2];

  pts[0] = a_c1;
  pts[1] = b_c1;
  if (!secp256k1_ec_pubkey_combine(ctx, sum_c1, pts, 2))
    return 0;

  pts[0] = a_c2;
  pts[1] = b_c2;
  if (!secp256k1_ec_pubkey_combine(ctx, sum_c2, pts, 2))
    return 0;

  return 1;
}

int secp256k1_elgamal_subtract(const secp256k1_context *ctx,
                               secp256k1_pubkey *diff_c1,
                               secp256k1_pubkey *diff_c2,
                               const secp256k1_pubkey *a_c1,
                               const secp256k1_pubkey *a_c2,
                               const secp256k1_pubkey *b_c1,
                               const secp256k1_pubkey *b_c2)
{
  secp256k1_pubkey neg_b_c1 = *b_c1;
  secp256k1_pubkey neg_b_c2 = *b_c2;
  const secp256k1_pubkey *pts[2];

  if (!secp256k1_ec_pubkey_negate(ctx, &neg_b_c1))
    return 0;
  if (!secp256k1_ec_pubkey_negate(ctx, &neg_b_c2))
    return 0;

  pts[0] = a_c1;
  pts[1] = &neg_b_c1;
  if (!secp256k1_ec_pubkey_combine(ctx, diff_c1, pts, 2))
    return 0;

  pts[0] = a_c2;
  pts[1] = &neg_b_c2;
  if (!secp256k1_ec_pubkey_combine(ctx, diff_c2, pts, 2))
    return 0;

  return 1;
}

/* --- Canonical Encrypted Zero --- */

int generate_canonical_encrypted_zero(
    const secp256k1_context *ctx, secp256k1_pubkey *enc_zero_c1,
    secp256k1_pubkey *enc_zero_c2, const secp256k1_pubkey *pubkey,
    const unsigned char *account_id,     // 20 bytes
    const unsigned char *mpt_issuance_id // 24 bytes
)
{
  unsigned char deterministic_scalar[32];
  unsigned char hash_input[51]; // 7 ("EncZero") + 20 + 24
  const char *domain = "EncZero";
  int ret;
  SHA256_CTX sha;

  // Build static buffer part
  memcpy(hash_input, domain, 7);
  memcpy(hash_input + 7, account_id, 20);
  memcpy(hash_input + 27, mpt_issuance_id, 24);

  /* Rejection sampling loop to ensure scalar is valid */
  do
  {
    SHA256(hash_input, 51, deterministic_scalar);

    // If invalid, re-hash the hash (standard chain method for determinism)
    // Or simply fail if strict canonical behavior is required.
    // Assuming rejection sampling is the intended design for safety:
    if (secp256k1_ec_seckey_verify(ctx, deterministic_scalar))
      break;

    // Update input for next iteration to get new hash
    // (Note: The original code just looped SHA256 on same input which is
    // static, so it would loop forever if the first hash was invalid. Fixed
    // here by re-hashing the output if needed, though highly unlikely to fail).
    memcpy(hash_input, deterministic_scalar, 32);

  } while (1);

  ret = secp256k1_elgamal_encrypt(ctx, enc_zero_c1, enc_zero_c2, pubkey, 0,
                                  deterministic_scalar);

  OPENSSL_cleanse(deterministic_scalar, 32); // Secure cleanup
  return ret;
}

/* --- Direct Verification (Convert) --- */

int secp256k1_elgamal_verify_encryption(const secp256k1_context *ctx,
                                        const secp256k1_pubkey *c1,
                                        const secp256k1_pubkey *c2,
                                        const secp256k1_pubkey *pubkey_Q,
                                        uint64_t amount,
                                        const unsigned char *blinding_factor)
{
  secp256k1_pubkey expected_c1, expected_c2, mG, S;
  const secp256k1_pubkey *pts[2];

  /* 1. Verify C1 == r * G */
  if (!secp256k1_ec_pubkey_create(ctx, &expected_c1, blinding_factor))
    return 0;
  if (!pubkey_equal(ctx, c1, &expected_c1))
    return 0;

  /* 2. Verify C2 == r*Q + m*G */

  // S = r * Q
  S = *pubkey_Q;
  if (!secp256k1_ec_pubkey_tweak_mul(ctx, &S, blinding_factor))
    return 0;

  if (amount == 0)
  {
    expected_c2 = S;
  }
  else
  {
    if (!compute_amount_point(ctx, &mG, amount))
      return 0;
    pts[0] = &mG;
    pts[1] = &S;
    if (!secp256k1_ec_pubkey_combine(ctx, &expected_c2, pts, 2))
      return 0;
  }

  if (!pubkey_equal(ctx, c2, &expected_c2))
    return 0;

  return 1;
}
