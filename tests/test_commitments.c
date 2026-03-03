#include "secp256k1_mpt.h"
#include "test_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- Tests --- */
void test_pedersen_commitment_basic()
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);

  uint64_t amount = 1000;
  unsigned char rho[32];
  secp256k1_pubkey pc1, pc2;
  unsigned char ser1[33], ser2[33];
  size_t len = 33;

  printf("DEBUG: Starting Pedersen Commitment basic tests...\n");

  // Generate valid random blinding factor
  random_scalar(ctx, rho);

  // 1. Test Consistency: PC(m, rho) should always produce the same result
  EXPECT(secp256k1_mpt_pedersen_commit(ctx, &pc1, amount, rho) == 1);
  EXPECT(secp256k1_mpt_pedersen_commit(ctx, &pc2, amount, rho) == 1);

  secp256k1_ec_pubkey_serialize(ctx, ser1, &len, &pc1, SECP256K1_EC_COMPRESSED);
  len = 33;
  secp256k1_ec_pubkey_serialize(ctx, ser2, &len, &pc2, SECP256K1_EC_COMPRESSED);

  EXPECT(memcmp(ser1, ser2, 33) == 0);
  printf("SUCCESS: Deterministic commitment verified.\n");

  // 2. Test Binding: Changing amount should change commitment
  EXPECT(secp256k1_mpt_pedersen_commit(ctx, &pc2, amount + 1, rho) == 1);
  len = 33;
  secp256k1_ec_pubkey_serialize(ctx, ser2, &len, &pc2, SECP256K1_EC_COMPRESSED);
  EXPECT(memcmp(ser1, ser2, 33) != 0);
  printf("SUCCESS: Binding property (amount) verified.\n");

  secp256k1_context_destroy(ctx);
}

void test_pedersen_zero_value()
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  unsigned char rho[32];
  secp256k1_pubkey commitment, expected;
  secp256k1_pubkey H;
  unsigned char ser1[33], ser2[33];
  size_t len = 33;

  printf("DEBUG: Starting Pedersen Zero Value test...\n");

  // Generate valid random blinding factor
  random_scalar(ctx, rho);

  // 1. Commit to 0
  EXPECT(secp256k1_mpt_pedersen_commit(ctx, &commitment, 0, rho) == 1);

  // 2. Manual Check: C should equal rho*H (since m*G is infinity)
  EXPECT(secp256k1_mpt_get_h_generator(ctx, &H));
  expected = H;
  EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &expected, rho));

  // 3. Compare
  secp256k1_ec_pubkey_serialize(ctx, ser1, &len, &commitment,
                                SECP256K1_EC_COMPRESSED);
  len = 33;
  secp256k1_ec_pubkey_serialize(ctx, ser2, &len, &expected,
                                SECP256K1_EC_COMPRESSED);

  EXPECT(memcmp(ser1, ser2, 33) == 0);
  printf("SUCCESS: Committing to 0 correctly resulted in rho*H.\n");

  secp256k1_context_destroy(ctx);
}

void test_pedersen_homomorphic_property()
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);

  uint64_t m1 = 500, m2 = 300;
  unsigned char r1[32], r2[32], r_sum[32];
  secp256k1_pubkey pc1, pc2, pc_sum_manual, pc_sum_computed;

  printf("DEBUG: Starting Pedersen Homomorphic property test...\n");

  // Generate valid random blinding factors
  random_scalar(ctx, r1);
  random_scalar(ctx, r2);

  // Compute PC1 = PC(m1, r1) and PC2 = PC(m2, r2)
  EXPECT(secp256k1_mpt_pedersen_commit(ctx, &pc1, m1, r1) == 1);
  EXPECT(secp256k1_mpt_pedersen_commit(ctx, &pc2, m2, r2) == 1);

  // Manual sum of points: PC1 + PC2
  const secp256k1_pubkey *points[2] = {&pc1, &pc2};
  EXPECT(secp256k1_ec_pubkey_combine(ctx, &pc_sum_manual, points, 2) == 1);

  // Compute scalar sum of blinding factors: r_sum = r1 + r2 (mod n)
  memcpy(r_sum, r1, 32);
  EXPECT(secp256k1_ec_seckey_tweak_add(ctx, r_sum, r2) == 1);

  // Compute PC(m1 + m2, r1 + r2)
  EXPECT(secp256k1_mpt_pedersen_commit(ctx, &pc_sum_computed, m1 + m2, r_sum) ==
         1);

  // Compare
  unsigned char ser1[33], ser2[33];
  size_t len = 33;
  secp256k1_ec_pubkey_serialize(ctx, ser1, &len, &pc_sum_manual,
                                SECP256K1_EC_COMPRESSED);
  len = 33;
  secp256k1_ec_pubkey_serialize(ctx, ser2, &len, &pc_sum_computed,
                                SECP256K1_EC_COMPRESSED);

  EXPECT(memcmp(ser1, ser2, 33) == 0);
  printf("SUCCESS: Homomorphic property (PC(m1,r1) + PC(m2,r2) == PC(m1+m2, "
         "r1+r2)) verified.\n");

  secp256k1_context_destroy(ctx);
}

void test_generator_cache()
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);

  printf("DEBUG: Starting Generator Cache tests...\n");

  /* Test cached G vector */
  const secp256k1_pubkey *G_vec_64 = secp256k1_mpt_get_cached_G_vec(ctx, 64);
  EXPECT(G_vec_64 != NULL);

  /* Second call should return same pointer (cached) */
  const secp256k1_pubkey *G_vec_64_again = secp256k1_mpt_get_cached_G_vec(ctx, 64);
  EXPECT(G_vec_64_again == G_vec_64);
  printf("SUCCESS: G vector cache returns same pointer.\n");

  /* Test cached H vector */
  const secp256k1_pubkey *H_vec_64 = secp256k1_mpt_get_cached_H_vec(ctx, 64);
  EXPECT(H_vec_64 != NULL);

  const secp256k1_pubkey *H_vec_64_again = secp256k1_mpt_get_cached_H_vec(ctx, 64);
  EXPECT(H_vec_64_again == H_vec_64);
  printf("SUCCESS: H vector cache returns same pointer.\n");

  /* Test cached h generator */
  secp256k1_pubkey h_gen, h_gen_again;
  EXPECT(secp256k1_mpt_get_cached_h_generator(ctx, &h_gen) == 1);
  EXPECT(secp256k1_mpt_get_cached_h_generator(ctx, &h_gen_again) == 1);

  /* Both calls should return the same generator value */
  unsigned char ser1[33], ser2[33];
  size_t len1 = 33, len2 = 33;
  secp256k1_ec_pubkey_serialize(ctx, ser1, &len1, &h_gen, SECP256K1_EC_COMPRESSED);
  secp256k1_ec_pubkey_serialize(ctx, ser2, &len2, &h_gen_again, SECP256K1_EC_COMPRESSED);
  EXPECT(memcmp(ser1, ser2, 33) == 0);
  printf("SUCCESS: h generator cache returns consistent value.\n");

  /* Test larger sizes */
  const secp256k1_pubkey *G_vec_128 = secp256k1_mpt_get_cached_G_vec(ctx, 128);
  EXPECT(G_vec_128 != NULL);

  const secp256k1_pubkey *H_vec_256 = secp256k1_mpt_get_cached_H_vec(ctx, 256);
  EXPECT(H_vec_256 != NULL);
  printf("SUCCESS: Larger generator vectors cached.\n");

  /* Free cache */
  secp256k1_mpt_free_generator_cache();
  printf("SUCCESS: Generator cache freed.\n");

  secp256k1_context_destroy(ctx);
}

void test_batch_scalar_inversion()
{
  printf("DEBUG: Starting Batch Scalar Inversion tests...\n");

  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);

  /* Test with n=8 scalars */
  size_t n = 8;
  unsigned char scalars[8 * 32];
  unsigned char inverses_batch[8 * 32];
  unsigned char inverses_individual[8 * 32];

  /* Generate random scalars */
  for (size_t i = 0; i < n; i++) {
    random_scalar(ctx, scalars + i * 32);
  }

  /* Compute batch inverses */
  int ok = secp256k1_mpt_scalar_batch_inverse(inverses_batch, scalars, n);
  EXPECT(ok == 1);

  /* Compute individual inverses for comparison */
  for (size_t i = 0; i < n; i++) {
    secp256k1_mpt_scalar_inverse(inverses_individual + i * 32, scalars + i * 32);
  }

  /* Verify they match */
  for (size_t i = 0; i < n; i++) {
    EXPECT(memcmp(inverses_batch + i * 32, inverses_individual + i * 32, 32) == 0);
  }
  printf("SUCCESS: Batch inversion matches individual inversion (n=8).\n");

  /* Test with larger n */
  size_t n_large = 64;
  unsigned char *scalars_large = malloc(n_large * 32);
  unsigned char *inverses_large = malloc(n_large * 32);
  unsigned char *verify = malloc(n_large * 32);

  for (size_t i = 0; i < n_large; i++) {
    random_scalar(ctx, scalars_large + i * 32);
  }

  ok = secp256k1_mpt_scalar_batch_inverse(inverses_large, scalars_large, n_large);
  EXPECT(ok == 1);

  /* Verify: scalar * inverse should equal 1 */
  for (size_t i = 0; i < n_large; i++) {
    secp256k1_mpt_scalar_mul(verify + i * 32,
                              scalars_large + i * 32,
                              inverses_large + i * 32);
    /* Check result is 1 (big-endian: 0x00...01) */
    unsigned char one[32] = {0};
    one[31] = 1;
    EXPECT(memcmp(verify + i * 32, one, 32) == 0);
  }
  printf("SUCCESS: Batch inversion verified (n=64): a * a^-1 = 1.\n");

  free(scalars_large);
  free(inverses_large);
  free(verify);
  secp256k1_context_destroy(ctx);
}

int main()
{
  test_pedersen_commitment_basic();
  test_pedersen_zero_value();
  test_pedersen_homomorphic_property();
  test_generator_cache();
  test_batch_scalar_inversion();
  printf("DEBUG: All Pedersen Commitment tests passed!\n");
  return 0;
}
