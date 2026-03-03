#include "secp256k1_mpt.h"
#include "test_utils.h"
#include <secp256k1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Test 1: Valid proof generation and verification.
 */
static void test_same_plaintext_valid(const secp256k1_context *ctx)
{
  unsigned char priv_1[32], priv_2[32];
  secp256k1_pubkey pub_1, pub_2;
  unsigned char r1[32], r2[32];
  unsigned char tx_context_id[32];
  uint64_t amount_m = 123456;

  secp256k1_pubkey R1, S1, R2, S2;
  unsigned char proof[261];

  printf("Running test: same plaintext proof (valid case)...\n");

  // 1. Setup: Generate keys and randomness
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, priv_1, &pub_1) == 1);
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, priv_2, &pub_2) == 1);

  // Use standardized helper (handles errors internally)
  random_scalar(ctx, r1);
  random_scalar(ctx, r2);
  random_scalar(ctx, tx_context_id);

  // 2. Encrypt the same amount
  EXPECT(secp256k1_elgamal_encrypt(ctx, &R1, &S1, &pub_1, amount_m, r1) == 1);
  EXPECT(secp256k1_elgamal_encrypt(ctx, &R2, &S2, &pub_2, amount_m, r2) == 1);

  printf("Generating proof...\n");
  // 3. Generate the proof
  EXPECT(secp256k1_mpt_prove_same_plaintext(ctx, proof, &R1, &S1, &pub_1, &R2,
                                            &S2, &pub_2, amount_m, r1, r2,
                                            tx_context_id) == 1);

  printf("Verifying proof...\n");
  // 4. Verify the proof
  EXPECT(secp256k1_mpt_verify_same_plaintext(ctx, proof, &R1, &S1, &pub_1, &R2,
                                             &S2, &pub_2, tx_context_id) == 1);

  printf("Test passed!\n");
}

/**
 * Test 2: Verifying a tampered proof (should fail).
 */
static void test_same_plaintext_tampered_proof(const secp256k1_context *ctx)
{
  unsigned char priv_1[32], priv_2[32];
  secp256k1_pubkey pub_1, pub_2;
  unsigned char r1[32], r2[32];
  unsigned char tx_context_id[32];
  uint64_t amount_m = 123456;
  secp256k1_pubkey R1, S1, R2, S2;
  unsigned char proof[261];

  printf("Running test: same plaintext proof (tampered proof)...\n");

  EXPECT(secp256k1_elgamal_generate_keypair(ctx, priv_1, &pub_1) == 1);
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, priv_2, &pub_2) == 1);

  random_scalar(ctx, r1);
  random_scalar(ctx, r2);
  random_scalar(ctx, tx_context_id);

  EXPECT(secp256k1_elgamal_encrypt(ctx, &R1, &S1, &pub_1, amount_m, r1) == 1);
  EXPECT(secp256k1_elgamal_encrypt(ctx, &R2, &S2, &pub_2, amount_m, r2) == 1);

  EXPECT(secp256k1_mpt_prove_same_plaintext(ctx, proof, &R1, &S1, &pub_1, &R2,
                                            &S2, &pub_2, amount_m, r1, r2,
                                            tx_context_id) == 1);

  // Tamper with the proof
  proof[42] ^= 0x01;

  // Verify should fail (return 0)
  int result = secp256k1_mpt_verify_same_plaintext(
      ctx, proof, &R1, &S1, &pub_1, &R2, &S2, &pub_2, tx_context_id);

  EXPECT(result == 0);

  printf("Test passed!\n");
}

/**
 * Test 3: Verifying with different-amount ciphertexts (should fail).
 */
static void test_same_plaintext_wrong_ciphertext(const secp256k1_context *ctx)
{
  unsigned char priv_1[32], priv_2[32];
  secp256k1_pubkey pub_1, pub_2;
  unsigned char r1[32], r2[32], r3[32];
  unsigned char tx_context_id[32];
  uint64_t amount_m1 = 123456;
  uint64_t amount_m2 = 777777;

  secp256k1_pubkey R1, S1, R2, S2;
  secp256k1_pubkey R3, S3;
  unsigned char proof[261];

  printf("Running test: same plaintext proof (wrong ciphertext)...\n");

  EXPECT(secp256k1_elgamal_generate_keypair(ctx, priv_1, &pub_1) == 1);
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, priv_2, &pub_2) == 1);

  random_scalar(ctx, r1);
  random_scalar(ctx, r2);
  random_scalar(ctx, r3);
  random_scalar(ctx, tx_context_id);

  EXPECT(secp256k1_elgamal_encrypt(ctx, &R1, &S1, &pub_1, amount_m1, r1) == 1);
  EXPECT(secp256k1_elgamal_encrypt(ctx, &R2, &S2, &pub_2, amount_m1, r2) == 1);
  EXPECT(secp256k1_elgamal_encrypt(ctx, &R3, &S3, &pub_2, amount_m2, r3) == 1);

  // Generate valid proof for m1
  EXPECT(secp256k1_mpt_prove_same_plaintext(ctx, proof, &R1, &S1, &pub_1, &R2,
                                            &S2, &pub_2, amount_m1, r1, r2,
                                            tx_context_id) == 1);

  // Verify against R3/S3 (which is m2) - Should fail
  int result = secp256k1_mpt_verify_same_plaintext(
      ctx, proof, &R1, &S1, &pub_1, &R3, &S3, &pub_2, tx_context_id);

  EXPECT(result == 0);

  printf("Test passed!\n");
}

/**
 * Test 4: Batch verification of multiple proofs.
 */
static void test_same_plaintext_batch_verify(const secp256k1_context *ctx)
{
  printf("Running test: batch verification of same plaintext proofs...\n");

  const size_t num_proofs = 8;

  /* Allocate arrays */
  unsigned char proofs[8][261];
  secp256k1_pubkey R1s[8], S1s[8], P1s[8];
  secp256k1_pubkey R2s[8], S2s[8], P2s[8];
  unsigned char context_id[32];

  random_scalar(ctx, context_id);

  /* Generate multiple valid proofs */
  for (size_t i = 0; i < num_proofs; i++) {
    unsigned char priv_1[32], priv_2[32];
    unsigned char r1[32], r2[32];
    uint64_t amount = 1000 + i * 100;

    EXPECT(secp256k1_elgamal_generate_keypair(ctx, priv_1, &P1s[i]) == 1);
    EXPECT(secp256k1_elgamal_generate_keypair(ctx, priv_2, &P2s[i]) == 1);

    random_scalar(ctx, r1);
    random_scalar(ctx, r2);

    EXPECT(secp256k1_elgamal_encrypt(ctx, &R1s[i], &S1s[i], &P1s[i], amount, r1) == 1);
    EXPECT(secp256k1_elgamal_encrypt(ctx, &R2s[i], &S2s[i], &P2s[i], amount, r2) == 1);

    EXPECT(secp256k1_mpt_prove_same_plaintext(ctx, proofs[i],
        &R1s[i], &S1s[i], &P1s[i],
        &R2s[i], &S2s[i], &P2s[i],
        amount, r1, r2, context_id) == 1);
  }

  /* Batch verify all proofs */
  const unsigned char *proof_ptrs[8];
  const secp256k1_pubkey *R1_ptrs[8], *S1_ptrs[8], *P1_ptrs[8];
  const secp256k1_pubkey *R2_ptrs[8], *S2_ptrs[8], *P2_ptrs[8];
  const unsigned char *context_ptrs[8];

  for (size_t i = 0; i < num_proofs; i++) {
    proof_ptrs[i] = proofs[i];
    R1_ptrs[i] = &R1s[i];
    S1_ptrs[i] = &S1s[i];
    P1_ptrs[i] = &P1s[i];
    R2_ptrs[i] = &R2s[i];
    S2_ptrs[i] = &S2s[i];
    P2_ptrs[i] = &P2s[i];
    context_ptrs[i] = context_id;  /* Same context for all */
  }

  int result = secp256k1_mpt_batch_verify_same_plaintext(ctx,
      proof_ptrs, num_proofs,
      R1_ptrs, S1_ptrs, P1_ptrs,
      R2_ptrs, S2_ptrs, P2_ptrs,
      context_ptrs);
  EXPECT(result == 1);
  printf("SUCCESS: Batch verification of %zu valid proofs passed.\n", num_proofs);

  /* Test with one tampered proof */
  unsigned char tampered_proof[261];
  memcpy(tampered_proof, proofs[3], 261);
  tampered_proof[100] ^= 0x01; /* Flip a bit */
  proof_ptrs[3] = tampered_proof;

  result = secp256k1_mpt_batch_verify_same_plaintext(ctx,
      proof_ptrs, num_proofs,
      R1_ptrs, S1_ptrs, P1_ptrs,
      R2_ptrs, S2_ptrs, P2_ptrs,
      context_ptrs);
  EXPECT(result == 0);
  printf("SUCCESS: Batch verification correctly rejected tampered proof.\n");

  printf("Test passed!\n");
}

int main(void)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  EXPECT(ctx != NULL);

  unsigned char seed[32];
  random_bytes(seed);
  EXPECT(secp256k1_context_randomize(ctx, seed) == 1);

  test_same_plaintext_valid(ctx);
  test_same_plaintext_tampered_proof(ctx);
  test_same_plaintext_wrong_ciphertext(ctx);
  test_same_plaintext_batch_verify(ctx);

  secp256k1_context_destroy(ctx);
  return 0;
}
