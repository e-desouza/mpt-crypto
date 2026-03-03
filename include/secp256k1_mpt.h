#ifndef SECP256K1_MPT_H
#define SECP256K1_MPT_H

#include <secp256k1.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generates a new secp256k1 key pair.
 */
SECP256K1_API int
secp256k1_elgamal_generate_keypair(
    secp256k1_context const* ctx,
    unsigned char* privkey,
    secp256k1_pubkey* pubkey);

/**
 * @brief Encrypts a 64-bit amount using ElGamal.
 */
SECP256K1_API int
secp256k1_elgamal_encrypt(
    secp256k1_context const* ctx,
    secp256k1_pubkey* c1,
    secp256k1_pubkey* c2,
    secp256k1_pubkey const* pubkey_Q,
    uint64_t amount,
    unsigned char const* blinding_factor);

/**
 * @brief Decrypts an ElGamal ciphertext to recover the amount.
 */
SECP256K1_API int
secp256k1_elgamal_decrypt(
    secp256k1_context const* ctx,
    uint64_t* amount,
    secp256k1_pubkey const* c1,
    secp256k1_pubkey const* c2,
    unsigned char const* privkey);

/**
 * @brief Initializes the BSGS lookup table for constant-time decryption.
 *
 * This function precomputes the Baby-Step Giant-Step table used by
 * secp256k1_elgamal_decrypt(). Call this once during application
 * initialization for optimal decryption performance.
 *
 * Memory usage: ~80KB for MAX_AMOUNT = 1,000,000
 *
 * @note This function is automatically called on first decryption if not
 *       initialized, but explicit initialization avoids the first-call penalty.
 * @note NOT thread-safe. Call during single-threaded initialization phase.
 *
 * @param ctx  secp256k1 context
 * @return 1 on success, 0 on failure
 */
SECP256K1_API int
secp256k1_elgamal_bsgs_init(secp256k1_context const* ctx);

/**
 * @brief Frees the BSGS lookup table memory.
 *
 * Call this during application shutdown to release the ~80KB of memory
 * used by the BSGS table.
 */
SECP256K1_API void
secp256k1_elgamal_bsgs_free(void);

/**
 * @brief Homomorphically adds two ElGamal ciphertexts.
 */
SECP256K1_API int
secp256k1_elgamal_add(
    secp256k1_context const* ctx,
    secp256k1_pubkey* sum_c1,
    secp256k1_pubkey* sum_c2,
    secp256k1_pubkey const* a_c1,
    secp256k1_pubkey const* a_c2,
    secp256k1_pubkey const* b_c1,
    secp256k1_pubkey const* b_c2);

/**
 * @brief Homomorphically subtracts two ElGamal ciphertexts.
 */
SECP256K1_API int
secp256k1_elgamal_subtract(
    secp256k1_context const* ctx,
    secp256k1_pubkey* diff_c1,
    secp256k1_pubkey* diff_c2,
    secp256k1_pubkey const* a_c1,
    secp256k1_pubkey const* a_c2,
    secp256k1_pubkey const* b_c1,
    secp256k1_pubkey const* b_c2);

/**
 * @brief Generates the canonical encrypted zero for a given MPT token instance.
 *
 * This ciphertext represents a zero balance for a specific account's holding
 * of a token defined by its MPTokenIssuanceID.
 *
 * @param[in]   ctx             A pointer to a valid secp256k1 context.
 * @param[out]  enc_zero_c1     The C1 component of the canonical ciphertext.
 * @param[out]  enc_zero_c2     The C2 component of the canonical ciphertext.
 * @param[in]   pubkey          The ElGamal public key of the account holder.
 * @param[in]   account_id      A pointer to the 20-byte AccountID.
 * @param[in]   mpt_issuance_id A pointer to the 24-byte MPTokenIssuanceID.
 *
 * @return 1 on success, 0 on failure.
 */
SECP256K1_API int
generate_canonical_encrypted_zero(
    secp256k1_context const* ctx,
    secp256k1_pubkey* enc_zero_c1,
    secp256k1_pubkey* enc_zero_c2,
    secp256k1_pubkey const* pubkey,
    unsigned char const* account_id,      // 20 bytes
    unsigned char const* mpt_issuance_id  // 24 bytes
);

// ... (includes and previous ElGamal declarations) ...

/*
================================================================================
|                                                                              |
|           PROOF OF KNOWLEDGE OF PLAINTEXT AND RANDOMNESS                     |
|                (Chaum-Pedersen Equality Proof)                               |
================================================================================
*/

/**
 * @brief Generates a proof that an ElGamal ciphertext correctly encrypts a
 * known plaintext `m` and that the prover knows the randomness `r`.
 *
 * @param[in]   ctx             A pointer to a valid secp256k1 context object,
 * initialized for signing.
 * @param[out]  proof           A pointer to a 98-byte buffer to store the proof
 * (T1 [33 bytes] || T2 [33 bytes] || s [32 bytes]).
 * @param[in]   c1              The C1 component of the ciphertext (r*G).
 * @param[in]   c2              The C2 component of the ciphertext (m*G + r*Pk).
 * @param[in]   pk_recipient    The public key used for encryption.
 * @param[in]   amount          The known plaintext value `m`.
 * @param[in]   randomness_r    The 32-byte secret random scalar `r` used in encryption.
 * @param[in]   tx_context_id   A 32-byte unique identifier for the transaction context.
 *
 * @return 1 on success, 0 on failure.
 */
SECP256K1_API int
secp256k1_equality_plaintext_prove(
    secp256k1_context const* ctx,
    unsigned char* proof,  // Output: 98 bytes
    secp256k1_pubkey const* c1,
    secp256k1_pubkey const* c2,
    secp256k1_pubkey const* pk_recipient,
    uint64_t amount,
    unsigned char const* randomness_r,  // Secret input
    unsigned char const* tx_context_id  // 32 bytes
);

/**
 * @brief Verifies a proof of knowledge of plaintext and randomness.
 *
 * Checks if the proof correctly demonstrates that (C1, C2) encrypts `m`
 * under `pk_recipient`.
 *
 * @param[in]   ctx             A pointer to a valid secp256k1 context object,
 * initialized for verification.
 * @param[in]   proof           A pointer to the 98-byte proof to verify.
 * @param[in]   c1              The C1 component of the ciphertext.
 * @param[in]   c2              The C2 component of the ciphertext.
 * @param[in]   pk_recipient    The public key used for encryption.
 * @param[in]   amount          The known plaintext value `m`.
 * @param[in]   tx_context_id   A 32-byte unique identifier for the transaction context.
 *
 * @return 1 if the proof is valid, 0 otherwise.
 */
SECP256K1_API int
secp256k1_equality_plaintext_verify(
    secp256k1_context const* ctx,
    unsigned char const* proof,  // Input: 98 bytes
    secp256k1_pubkey const* c1,
    secp256k1_pubkey const* c2,
    secp256k1_pubkey const* pk_recipient,
    uint64_t amount,
    unsigned char const* tx_context_id  // 32 bytes
);

// ... (rest of header, #endif etc.)

/*
================================================================================
|                                                                              |
|           PROOF OF EQUALITY OF SECRET PLAINTEXTS                             |
|                (Multi-Statement Chaum-Pedersen)                              |
================================================================================
*/

/**
 * @brief Generates a proof that two ciphertexts (under different keys)
 * encrypt the same secret amount 'm'.
 *
 * @param[in]   ctx             A pointer to a valid secp256k1 context.
 * @param[out]  proof_out       A pointer to a 261-byte buffer to store the proof.
 * @param[in]   R1, S1, P1      The first ciphertext (R1, S1) and its public key (P1).
 * @param[in]   R2, S2, P2      The second ciphertext (R2, S2) and its public key (P2).
 * @param[in]   amount_m        The secret common uint64_t plaintext value 'm'.
 * @param[in]   randomness_r1   The 32-byte secret random scalar 'r1' for C1.
 * @param[in]   randomness_r2   The 32-byte secret random scalar 'r2' for C2.
 * @param[in]   tx_context_id   A 32-byte unique identifier for the transaction.
 *
 * @return 1 on success, 0 on failure.
 */
SECP256K1_API int
secp256k1_mpt_prove_same_plaintext(
    secp256k1_context const* ctx,
    unsigned char* proof_out,  // Output: 261 bytes
    secp256k1_pubkey const* R1,
    secp256k1_pubkey const* S1,
    secp256k1_pubkey const* P1,
    secp256k1_pubkey const* R2,
    secp256k1_pubkey const* S2,
    secp256k1_pubkey const* P2,
    uint64_t amount_m,
    unsigned char const* randomness_r1,
    unsigned char const* randomness_r2,
    unsigned char const* tx_context_id);

/**
 * @brief Verifies a proof that two ciphertexts encrypt the same secret amount.
 *
 * @param[in]   ctx             A pointer to a valid secp256k1 context.
 * @param[in]   proof           A pointer to the 261-byte proof to verify.
 * @param[in]   R1, S1, P1      The first ciphertext (R1, S1) and its public key (P1).
 * @param[in]   R2, S2, P2      The second ciphertext (R2, S2) and its public key (P2).
 * @param[in]   tx_context_id   A 32-byte unique identifier for the transaction.
 *
 * @return 1 if the proof is valid, 0 otherwise.
 */
SECP256K1_API int
secp256k1_mpt_verify_same_plaintext(
    secp256k1_context const* ctx,
    unsigned char const* proof,  // Input: 261 bytes
    secp256k1_pubkey const* R1,
    secp256k1_pubkey const* S1,
    secp256k1_pubkey const* P1,
    secp256k1_pubkey const* R2,
    secp256k1_pubkey const* S2,
    secp256k1_pubkey const* P2,
    unsigned char const* tx_context_id);

/**
 * @brief Batch verify multiple same-plaintext proofs.
 *
 * This is faster than individual verification when verifying multiple proofs.
 * Uses batch verification technique from BIP-340 for ~3x speedup on 4+ proofs.
 *
 * @param ctx               secp256k1 context
 * @param proofs            Array of proof pointers (each 261 bytes)
 * @param n_proofs          Number of proofs to verify
 * @param R1_array          Array of R1 point pointers
 * @param S1_array          Array of S1 point pointers
 * @param P1_array          Array of P1 public key pointers
 * @param R2_array          Array of R2 point pointers
 * @param S2_array          Array of S2 point pointers
 * @param P2_array          Array of P2 public key pointers
 * @param tx_context_ids    Array of context ID pointers (or NULL for all)
 * @return 1 if ALL proofs are valid, 0 if any proof is invalid
 */
SECP256K1_API int
secp256k1_mpt_batch_verify_same_plaintext(
    secp256k1_context const* ctx,
    unsigned char const* const* proofs,
    size_t n_proofs,
    secp256k1_pubkey const* const* R1_array,
    secp256k1_pubkey const* const* S1_array,
    secp256k1_pubkey const* const* P1_array,
    secp256k1_pubkey const* const* R2_array,
    secp256k1_pubkey const* const* S2_array,
    secp256k1_pubkey const* const* P2_array,
    unsigned char const* const* tx_context_ids);

/**
 * @brief Calculates the expected proof size for a given number of ciphertexts.
 */
SECP256K1_API size_t
secp256k1_mpt_prove_same_plaintext_multi_size(size_t n_ciphertexts);

/**
 * @brief Generates a proof that N ciphertexts encrypt the same secret amount 'm'.
 *
 * @param[in]   ctx             A pointer to a valid secp256k1 context.
 * @param[out]  proof_out       A pointer to a buffer to store the proof.
 * @param[in,out] proof_len     Input: buffer size. Output: actual proof size.
 * @param[in]   amount_m        The secret common uint64_t plaintext value 'm'.
 * @param[in]   n_ciphertexts   The number (N) of ciphertexts.
 * @param[in]   R_array         Array of N 'R' points (C1 components).
 * @param[in]   S_array         Array of N 'S' points (C2 components).
 * @param[in]   Pk_array        Array of N recipient public keys.
 * @param[in]   r_array         Array of N 32-byte secret scalars (randomness).
 * @param[in]   tx_context_id   32-byte unique transaction identifier.
 *
 * @return 1 on success, 0 on failure.
 */
SECP256K1_API int
secp256k1_mpt_prove_same_plaintext_multi(
    secp256k1_context const* ctx,
    unsigned char* proof_out,
    size_t* proof_len,
    uint64_t amount_m,
    size_t n_ciphertexts,
    secp256k1_pubkey const* R_array,
    secp256k1_pubkey const* S_array,
    secp256k1_pubkey const* Pk_array,
    unsigned char const* r_array,  // Flat array: r1 || r2 || ... (N * 32 bytes)
    unsigned char const* tx_context_id);

/**
 * @brief Verifies a proof that N ciphertexts encrypt the same secret amount.
 */
SECP256K1_API int
secp256k1_mpt_verify_same_plaintext_multi(
    secp256k1_context const* ctx,
    unsigned char const* proof,
    size_t proof_len,
    size_t n_ciphertexts,
    secp256k1_pubkey const* R_array,
    secp256k1_pubkey const* S_array,
    secp256k1_pubkey const* Pk_array,
    unsigned char const* tx_context_id);

/*
================================================================================
|                                                                              |
|           GENERATOR CACHE (for Bulletproof optimization)                     |
================================================================================
*/

/**
 * @brief Get cached G vector generators for Bulletproofs.
 *
 * Returns a pointer to pre-computed generators. This avoids repeated
 * NUMS point derivation during proof generation/verification.
 * The cache is automatically expanded as needed.
 *
 * @param ctx    secp256k1 context
 * @param n      Number of generators needed
 * @return Pointer to cached G_vec (do not free) or NULL on failure
 */
SECP256K1_API const secp256k1_pubkey*
secp256k1_mpt_get_cached_G_vec(secp256k1_context const* ctx, size_t n);

/**
 * @brief Get cached H vector generators for Bulletproofs.
 */
SECP256K1_API const secp256k1_pubkey*
secp256k1_mpt_get_cached_H_vec(secp256k1_context const* ctx, size_t n);

/**
 * @brief Get the cached single H generator (for Pedersen commitments).
 */
SECP256K1_API int
secp256k1_mpt_get_cached_h_generator(secp256k1_context const* ctx, secp256k1_pubkey* h);

/**
 * @brief Free all cached generators.
 *
 * Call this during application shutdown to release memory.
 */
SECP256K1_API void
secp256k1_mpt_free_generator_cache(void);

/**
 * @brief Computes a Pedersen Commitment: C = value*G + blinding_factor*Pk_base.
 *
 * This function creates the commitment point (C) that the Bulletproof proves
 * the range of. Pk_base is the dynamic secondary generator (H).
 *
 * @param[in]   ctx             A pointer to the context.
 * @param[out]  commitment_C    The resulting commitment point C.
 * @param[in]   value           The secret amount v (uint64_t).
 * @param[in]   blinding_factor The secret randomness r (32 bytes).
 * @param[in]   pk_base         The recipient's public key (used as the H generator).
 *
 * @return 1 on success, 0 on failure.
 */
SECP256K1_API int
secp256k1_bulletproof_create_commitment(
    secp256k1_context const* ctx,
    secp256k1_pubkey* commitment_C,
    uint64_t value,
    unsigned char const* blinding_factor,
    secp256k1_pubkey const* pk_base);

int
secp256k1_bulletproof_prove(
    secp256k1_context const* ctx,
    unsigned char* proof_out,
    size_t* proof_len,
    uint64_t value,
    unsigned char const* blinding_factor,
    secp256k1_pubkey const* pk_base,
    unsigned char const* context_id, /* <--- AND HERE */
    unsigned int proof_type);

int
secp256k1_bulletproof_verify(
    secp256k1_context const* ctx,
    secp256k1_pubkey const* G_vec,
    secp256k1_pubkey const* H_vec,
    unsigned char const* proof,
    size_t proof_len,
    secp256k1_pubkey const* commitment_C,
    secp256k1_pubkey const* pk_base, /* This is generator H */
    unsigned char const* context_id);
/**
 * @brief Proves the link between an ElGamal ciphertext and a Pedersen commitment.
 * * Formal Statement: Knowledge of (m, r, rho) such that:
 * C1 = r*G, C2 = m*G + r*Pk, and PCm = m*G + rho*H.
 * * @param ctx         Pointer to a secp256k1 context object.
 * @param proof       [OUT] Pointer to 195-byte buffer for the proof output.
 * @param c1          Pointer to the ElGamal C1 point (r*G).
 * @param c2          Pointer to the ElGamal C2 point (m*G + r*Pk).
 * @param pk          Pointer to the recipient's public key.
 * @param pcm         Pointer to the Pedersen Commitment (m*G + rho*H).
 * @param amount      The plaintext amount (m).
 * @param r           The 32-byte secret ElGamal blinding factor.
 * @param rho         The 32-byte secret Pedersen blinding factor.
 * @param context_id  32-byte unique transaction context identifier.
 * @return 1 on success, 0 on failure.
 */
int
secp256k1_elgamal_pedersen_link_prove(
    secp256k1_context const* ctx,
    unsigned char* proof,
    secp256k1_pubkey const* c1,
    secp256k1_pubkey const* c2,
    secp256k1_pubkey const* pk,
    secp256k1_pubkey const* pcm,
    uint64_t amount,
    unsigned char const* r,
    unsigned char const* rho,
    unsigned char const* context_id);

/**
 * @brief Verifies the link proof between ElGamal and Pedersen commitments.
 * * @return 1 if the proof is valid, 0 otherwise.
 */
int
secp256k1_elgamal_pedersen_link_verify(
    secp256k1_context const* ctx,
    unsigned char const* proof,
    secp256k1_pubkey const* c1,
    secp256k1_pubkey const* c2,
    secp256k1_pubkey const* pk,
    secp256k1_pubkey const* pcm,
    unsigned char const* context_id);

/**
 * Verifies that (c1, c2) is a valid ElGamal encryption of 'amount'
 * for 'pubkey_Q' using the revealed 'blinding_factor'.
 */
int
secp256k1_elgamal_verify_encryption(
    secp256k1_context const* ctx,
    secp256k1_pubkey const* c1,
    secp256k1_pubkey const* c2,
    secp256k1_pubkey const* pubkey_Q,
    uint64_t amount,
    unsigned char const* blinding_factor);

/** Proof of Knowledge of Secret Key for Registration */
int
secp256k1_mpt_pok_sk_prove(
    secp256k1_context const* ctx,
    unsigned char* proof, /* Expected size: 65 bytes */
    secp256k1_pubkey const* pk,
    unsigned char const* sk,
    unsigned char const* context_id);

int
secp256k1_mpt_pok_sk_verify(
    secp256k1_context const* ctx,
    unsigned char const* proof, /* Expected size: 65 bytes */
    secp256k1_pubkey const* pk,
    unsigned char const* context_id);

/**
 * Compute a Pedersen Commitment: PC = m*G + rho*H
 * Returns 1 on success, 0 on failure.
 */
int
secp256k1_mpt_pedersen_commit(
    secp256k1_context const* ctx,
    secp256k1_pubkey* commitment,
    uint64_t amount,
    unsigned char const* blinding_factor_rho /* 32 bytes */
);

/** Get the standardized H generator for Pedersen Commitments */
int
secp256k1_mpt_get_h_generator(secp256k1_context const* ctx, secp256k1_pubkey* h);

/**
 * @brief Generates a vector of N independent NUMS generators.
 */
int
secp256k1_mpt_get_generator_vector(
    secp256k1_context const* ctx,
    secp256k1_pubkey* vec,
    size_t n,
    unsigned char const* label,
    size_t label_len);

void
secp256k1_mpt_scalar_add(unsigned char* res, unsigned char const* a, unsigned char const* b);
void
secp256k1_mpt_scalar_mul(unsigned char* res, unsigned char const* a, unsigned char const* b);
void
secp256k1_mpt_scalar_inverse(unsigned char* res, unsigned char const* in);
void
secp256k1_mpt_scalar_negate(unsigned char* res, unsigned char const* in);
void
secp256k1_mpt_scalar_reduce32(unsigned char out32[32], unsigned char const in32[32]);

/**
 * @brief Batch inversion using Montgomery's trick.
 *
 * Computes the multiplicative inverse of n scalars using only 1 inversion
 * and 3*(n-1) multiplications, providing significant speedup for n > 2.
 *
 * @param out    Output array of n 32-byte inverse scalars
 * @param in     Input array of n 32-byte scalars (must be non-zero)
 * @param n      Number of scalars to invert
 * @return 1 on success, 0 on failure (if any input is zero)
 */
int
secp256k1_mpt_scalar_batch_inverse(unsigned char* out, unsigned char const* in, size_t n);

/**
 * Returns the size of the serialized proof for N recipients.
 * Size: (1 + N) * 33 bytes for points + 2 * 32 bytes for scalars.
 */
size_t
secp256k1_mpt_proof_equality_shared_r_size(size_t n);

/**
 * Generates a proof that multiple ciphertexts encrypt the same amount m
 * using the SAME shared randomness r.
 */
int
secp256k1_mpt_prove_equality_shared_r(
    secp256k1_context const* ctx,
    unsigned char* proof_out,
    uint64_t amount,
    unsigned char const* r_shared,
    size_t n,
    secp256k1_pubkey const* C1,
    secp256k1_pubkey const* C2_vec,
    secp256k1_pubkey const* Pk_vec,
    unsigned char const* context_id);

/**
 * Verifies the proof of equality with shared randomness.
 */
int
secp256k1_mpt_verify_equality_shared_r(
    secp256k1_context const* ctx,
    unsigned char const* proof,
    size_t n,
    secp256k1_pubkey const* C1,
    secp256k1_pubkey const* C2_vec,
    secp256k1_pubkey const* Pk_vec,
    unsigned char const* context_id);

int
secp256k1_bulletproof_prove_agg(
    secp256k1_context const* ctx,
    unsigned char* proof_out,
    size_t* proof_len,
    uint64_t const* values,
    unsigned char const* blindings_flat,
    size_t m,
    secp256k1_pubkey const* pk_base,
    unsigned char const* context_id);
int
secp256k1_bulletproof_verify_agg(
    secp256k1_context const* ctx,
    secp256k1_pubkey const* G_vec, /* length n = 64*m */
    secp256k1_pubkey const* H_vec, /* length n = 64*m */
    unsigned char const* proof,
    size_t proof_len,
    secp256k1_pubkey const* commitment_C_vec, /* length m */
    size_t m,
    secp256k1_pubkey const* pk_base,
    unsigned char const* context_id);

/**
 * Compute multi-scalar multiplication (MSM): r_out = sum_i(scalars[i] * points[i])
 *
 * @param[in]   ctx       secp256k1 context
 * @param[out]  r_out     The resulting point
 * @param[in]   points    Array of n points
 * @param[in]   scalars   Flat array of n 32-byte scalars
 * @param[in]   n         Number of (scalar, point) pairs
 *
 * @return 1 on success, 0 on failure (all scalars zero or invalid input).
 */
int secp256k1_bulletproof_ipa_msm(
    secp256k1_context const* ctx,
    secp256k1_pubkey* r_out,
    secp256k1_pubkey const* points,
    unsigned char const* scalars,
    size_t n);

#ifdef __cplusplus
}
#endif

#endif  // SECP256K1_MPT_H
