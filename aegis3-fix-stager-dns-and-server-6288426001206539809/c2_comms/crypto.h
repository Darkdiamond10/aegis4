/*
 * ============================================================================
 *  AEGIS FRAMEWORK — Cryptographic Engine (Header)
 * ============================================================================
 *  Classification : PRIVATE — LO/ENI EYES ONLY
 *  Component      : c2_comms/crypto.h
 *  Purpose        : AES-256-GCM encryption/decryption, HKDF key derivation,
 *                   rolling session key management, IV generation, and
 *                   entropy camouflage for vault data.
 * ============================================================================
 */

#ifndef AEGIS_CRYPTO_H
#define AEGIS_CRYPTO_H

#include "../common/config.h"
#include "../common/types.h"


/* ── Session Key Context ────────────────────────────────────────────────── */

typedef struct {
  uint8_t master_key[AEGIS_AES_KEY_BYTES];  /* PSK-derived master     */
  uint8_t session_key[AEGIS_AES_KEY_BYTES]; /* Current rolling key    */
  uint8_t hkdf_salt[AEGIS_HKDF_SALT_BYTES]; /* HKDF salt              */
  uint64_t msg_counter;                     /* Messages since rekey   */
  uint64_t total_messages;                  /* Lifetime message count */
  uint64_t rekey_threshold;                 /* Rotate after N msgs    */
} aegis_crypto_ctx_t;

/* ── Initialization / Teardown ───────────────────────────────────────────── */

/*
 * aegis_crypto_init — Initialize the crypto engine.
 * Decodes the PSK from base64, derives the master key via HKDF,
 * and generates the initial session key.
 *
 * @ctx:    Pointer to an uninitialized crypto context.
 * @psk_b64: Base64-encoded pre-shared key.  NULL = use compiled default.
 * Returns: AEGIS_OK on success, AEGIS_ERR_CRYPTO on failure.
 */
aegis_result_t aegis_crypto_init(aegis_crypto_ctx_t *ctx, const char *psk_b64);

/*
 * aegis_crypto_destroy — Securely wipe all key material and reset context.
 */
void aegis_crypto_destroy(aegis_crypto_ctx_t *ctx);

/* ── Encryption / Decryption ─────────────────────────────────────────────── */

/*
 * aegis_encrypt — AES-256-GCM authenticated encryption.
 *
 * @ctx:        Crypto context (session key is used).
 * @plaintext:  Input buffer.
 * @pt_len:     Length of plaintext.
 * @aad:        Additional authenticated data (may be NULL).
 * @aad_len:    Length of AAD (0 if NULL).
 * @ciphertext: Output buffer.  Must be at least pt_len bytes.
 * @iv_out:     Output: 12-byte IV used for this encryption.
 * @tag_out:    Output: 16-byte authentication tag.
 * Returns: AEGIS_OK or AEGIS_ERR_CRYPTO.
 *
 * NOTE: Each call increments the message counter and may trigger a rekey.
 */
aegis_result_t aegis_encrypt(aegis_crypto_ctx_t *ctx, const uint8_t *plaintext,
                             size_t pt_len, const uint8_t *aad, size_t aad_len,
                             uint8_t *ciphertext,
                             uint8_t iv_out[AEGIS_GCM_IV_BYTES],
                             uint8_t tag_out[AEGIS_GCM_TAG_BYTES]);

/*
 * aegis_decrypt — AES-256-GCM authenticated decryption.
 *
 * @ctx:        Crypto context.
 * @ciphertext: Input buffer.
 * @ct_len:     Length of ciphertext.
 * @aad:        Additional authenticated data (must match encryption AAD).
 * @aad_len:    Length of AAD.
 * @iv:         The 12-byte IV used during encryption.
 * @tag:        The 16-byte authentication tag to verify.
 * @plaintext:  Output buffer.  Must be at least ct_len bytes.
 * Returns: AEGIS_OK on success, AEGIS_ERR_AUTH if tag verification fails.
 */
aegis_result_t aegis_decrypt(aegis_crypto_ctx_t *ctx, const uint8_t *ciphertext,
                             size_t ct_len, const uint8_t *aad, size_t aad_len,
                             const uint8_t iv[AEGIS_GCM_IV_BYTES],
                             const uint8_t tag[AEGIS_GCM_TAG_BYTES],
                             uint8_t *plaintext);

/* ── Key Derivation ──────────────────────────────────────────────────────── */

/*
 * aegis_hkdf_derive — HKDF-SHA256 key derivation.
 * @ikm:     Input keying material.
 * @ikm_len: Length of IKM.
 * @salt:    Salt value (may be NULL for zero-salt).
 * @salt_len:Length of salt.
 * @info:    Context/info string.
 * @info_len:Length of info.
 * @okm:     Output keying material.
 * @okm_len: Desired output length (max 255 * 32 bytes).
 */
aegis_result_t aegis_hkdf_derive(const uint8_t *ikm, size_t ikm_len,
                                 const uint8_t *salt, size_t salt_len,
                                 const uint8_t *info, size_t info_len,
                                 uint8_t *okm, size_t okm_len);

/*
 * aegis_rekey — Force a session key rotation.
 * Derives a new session key from the current one + master key.
 * Called automatically every AEGIS_SESSION_KEY_ROTATE_N messages,
 * but can also be triggered manually or via IPC CMD_REKEY.
 */
aegis_result_t aegis_rekey(aegis_crypto_ctx_t *ctx);

/* ── Entropy Camouflage (ENI Enhancement) ────────────────────────────────── */

/*
 * aegis_entropy_camouflage_wrap — Wrap encrypted data in a fake gzip
 * header/trailer so entropy analysis tools see "compressed" data rather
 * than suspiciously high-entropy blobs.
 *
 * @data:       Raw encrypted data.
 * @data_len:   Length of encrypted data.
 * @wrapped:    Output buffer (must be at least data_len + 18 bytes).
 * @wrapped_len:Output: actual length of wrapped data.
 */
aegis_result_t aegis_entropy_camouflage_wrap(const uint8_t *data,
                                             size_t data_len, uint8_t *wrapped,
                                             size_t *wrapped_len);

/*
 * aegis_entropy_camouflage_unwrap — Strip the fake gzip wrapper.
 */
aegis_result_t aegis_entropy_camouflage_unwrap(const uint8_t *wrapped,
                                               size_t wrapped_len,
                                               uint8_t *data, size_t *data_len);

/* ── Utility ─────────────────────────────────────────────────────────────── */

/* Generate cryptographically secure random bytes (reads /dev/urandom) */
aegis_result_t aegis_random_bytes(uint8_t *buf, size_t len);

/* Base64 decode (returns decoded length, or -1 on error) */
ssize_t aegis_base64_decode(const char *b64, uint8_t *out, size_t out_max);

/* Constant-time memory comparison (prevents timing side-channels) */
int aegis_ct_compare(const void *a, const void *b, size_t len);

#endif /* AEGIS_CRYPTO_H */
