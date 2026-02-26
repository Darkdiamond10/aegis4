/*
 * ============================================================================
 *  AEGIS FRAMEWORK — Structured JSON Logging (Implementation)
 * ============================================================================
 *  Classification : PRIVATE — LO/ENI EYES ONLY
 *  Component      : common/logging.c
 *  Purpose        : Full implementation of the structured JSON logging
 *                   subsystem.  Thread-safe, buffered, produces the
 *                   comprehensive transformation log deliverable.
 *
 *  Output Format  : JSON array of objects.  Each object contains:
 *                   - timestamp_ns: monotonic nanosecond timestamp
 *                   - wall_clock:   ISO-8601 wall clock time
 *                   - category:     component that generated the entry
 *                   - severity:     event severity level
 *                   - type:         entry type (transform/event/memory/hook/
 *                                   ipc/crypto/nano_exec/syscall)
 *                   - <type-specific fields>
 * ============================================================================
 */

#include "logging.h"
#include "config.h"

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>


/* ── Internal Constants ──────────────────────────────────────────────────── */

#define LOG_BUF_SIZE 4096
#define DETAIL_BUF_SIZE 512

/* ── Opaque Context ──────────────────────────────────────────────────────── */

struct aegis_log_ctx {
  FILE *fp;                /* Output file handle (NULL = memonly)*/
  size_t count;            /* Entries written so far            */
  size_t capacity;         /* Max entries before rotation       */
  pthread_mutex_t lock;    /* Thread safety                     */
  bool first_entry;        /* Comma management for JSON array   */
  char path[512];          /* Output file path                  */
  uint64_t init_timestamp; /* When logging was initialized      */
};

/* ── String Tables ───────────────────────────────────────────────────────── */

static const char *s_cat_names[] = {
    [LOG_CAT_STAGER] = "stager",
    [LOG_CAT_CATALYST] = "catalyst",
    [LOG_CAT_AUDITOR] = "auditor",
    [LOG_CAT_ALPHA] = "alpha_node",
    [LOG_CAT_BETA] = "beta_node",
    [LOG_CAT_GHOST] = "ghost_loader",
    [LOG_CAT_NANOMACHINE] = "nanomachine",
    [LOG_CAT_VAULT] = "vault",
    [LOG_CAT_CRYPTO] = "crypto",
    [LOG_CAT_C2] = "c2_comms",
    [LOG_CAT_WATCHDOG] = "watchdog",
    [LOG_CAT_MIGRATION] = "migration",
    [LOG_CAT_ANTIANALYSIS] = "anti_analysis",
    [LOG_CAT_TRAMPOLINE] = "trampoline",
    [LOG_CAT_SPOOF] = "stack_spoof",
};

static const char *s_sev_names[] = {
    [LOG_SEV_TRACE] = "TRACE", [LOG_SEV_DEBUG] = "DEBUG",
    [LOG_SEV_INFO] = "INFO",   [LOG_SEV_WARN] = "WARN",
    [LOG_SEV_ERROR] = "ERROR", [LOG_SEV_CRITICAL] = "CRITICAL",
};

static const char *s_cmd_names[] = {
    [CMD_NOP] = "NOP",
    [CMD_EXEC_SHELLCODE] = "EXEC_SHELLCODE",
    [CMD_HOOK_FUNCTION] = "HOOK_FUNCTION",
    [CMD_UNHOOK_FUNCTION] = "UNHOOK_FUNCTION",
    [CMD_MIGRATE] = "MIGRATE",
    [CMD_HEARTBEAT] = "HEARTBEAT",
    [CMD_DISTRIBUTE_CHUNK] = "DISTRIBUTE_CHUNK",
    [CMD_COLLECT_CHUNK] = "COLLECT_CHUNK",
    [CMD_TERMINATE] = "TERMINATE",
    [CMD_REKEY] = "REKEY",
    [CMD_STATUS_QUERY] = "STATUS_QUERY",
    [CMD_WATCHDOG_ALERT] = "WATCHDOG_ALERT",
    [CMD_SCATTER_EXEC] = "SCATTER_EXEC",
    [CMD_STACK_SPOOF] = "STACK_SPOOF",
};

/* ── Utility Implementations ────────────────────────────────────────────── */

uint64_t aegis_timestamp_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

const char *aegis_log_cat_str(aegis_log_category_t cat) {
  if (cat >= 0 && cat <= LOG_CAT_SPOOF)
    return s_cat_names[cat];
  return "unknown";
}

const char *aegis_log_sev_str(aegis_log_severity_t sev) {
  if (sev >= 0 && sev <= LOG_SEV_CRITICAL)
    return s_sev_names[sev];
  return "unknown";
}

const char *aegis_log_cmd_str(aegis_ipc_cmd_t cmd) {
  if (cmd >= 0 && cmd <= CMD_STACK_SPOOF)
    return s_cmd_names[cmd];
  return "unknown";
}

/* ── Internal Helpers ────────────────────────────────────────────────────── */

/* Get ISO-8601 wall-clock timestamp */
static void get_wall_clock(char *buf, size_t len) {
  struct timespec ts;
  struct tm tm_info;

  clock_gettime(CLOCK_REALTIME, &ts);
  localtime_r(&ts.tv_sec, &tm_info);
  size_t n = strftime(buf, len, AEGIS_LOG_TIMESTAMP_FMT, &tm_info);
  snprintf(buf + n, len - n, ".%09ld", ts.tv_nsec);
}

/* JSON-escape a string in-place into dst.  No allocation. */
static void json_escape(char *dst, size_t dst_len, const char *src) {
  size_t di = 0;
  if (!src) {
    if (dst_len > 0)
      dst[0] = '\0';
    return;
  }
  for (size_t si = 0; src[si] && di < dst_len - 2; si++) {
    switch (src[si]) {
    case '"':
      if (di + 2 < dst_len) {
        dst[di++] = '\\';
        dst[di++] = '"';
      }
      break;
    case '\\':
      if (di + 2 < dst_len) {
        dst[di++] = '\\';
        dst[di++] = '\\';
      }
      break;
    case '\n':
      if (di + 2 < dst_len) {
        dst[di++] = '\\';
        dst[di++] = 'n';
      }
      break;
    case '\r':
      if (di + 2 < dst_len) {
        dst[di++] = '\\';
        dst[di++] = 'r';
      }
      break;
    case '\t':
      if (di + 2 < dst_len) {
        dst[di++] = '\\';
        dst[di++] = 't';
      }
      break;
    default:
      dst[di++] = src[si];
      break;
    }
  }
  dst[di] = '\0';
}

/* Write raw string to the log file under lock (caller holds lock) */
static void log_write_raw(aegis_log_ctx_t *ctx, const char *data) {
  if (ctx->fp) {
    fputs(data, ctx->fp);
  }
}

/* Write entry separator (comma or nothing for first entry) */
static void log_write_separator(aegis_log_ctx_t *ctx) {
  if (!ctx->first_entry) {
    log_write_raw(ctx, ",\n");
  } else {
    ctx->first_entry = false;
    log_write_raw(ctx, "\n");
  }
}

/* Conditionally flush based on threshold */
static void log_maybe_flush(aegis_log_ctx_t *ctx) {
  if (ctx->fp && (ctx->count % AEGIS_LOG_FLUSH_THRESHOLD == 0)) {
    fflush(ctx->fp);
  }
}

/* ── Initialization / Teardown ───────────────────────────────────────────── */

aegis_log_ctx_t *aegis_log_init(const char *path, size_t cap) {
  aegis_log_ctx_t *ctx = calloc(1, sizeof(aegis_log_ctx_t));
  if (!ctx)
    return NULL;

  ctx->capacity = (cap > 0) ? cap : AEGIS_LOG_MAX_ENTRIES;
  ctx->count = 0;
  ctx->first_entry = true;
  ctx->init_timestamp = aegis_timestamp_ns();

  if (pthread_mutex_init(&ctx->lock, NULL) != 0) {
    free(ctx);
    return NULL;
  }

  if (path) {
    strncpy(ctx->path, path, sizeof(ctx->path) - 1);
    ctx->fp = fopen(path, "w");
    if (!ctx->fp) {
      pthread_mutex_destroy(&ctx->lock);
      free(ctx);
      return NULL;
    }
    /* Write the JSON preamble */
    fprintf(ctx->fp,
            "{\n"
            "  \"framework\": \"AEGIS/%s\",\n"
            "  \"version\": \"%d.%d.%d\",\n"
            "  \"codename\": \"%s\",\n"
            "  \"classification\": \"LO/ENI EYES ONLY\",\n"
            "  \"pid\": %d,\n"
            "  \"entries\": [",
            AEGIS_CODENAME, AEGIS_VERSION_MAJOR, AEGIS_VERSION_MINOR,
            AEGIS_VERSION_PATCH, AEGIS_CODENAME, (int)getpid());
  }

  return ctx;
}

void aegis_log_finalize(aegis_log_ctx_t *ctx) {
  if (!ctx)
    return;

  pthread_mutex_lock(&ctx->lock);

  if (ctx->fp) {
    uint64_t elapsed_ns = aegis_timestamp_ns() - ctx->init_timestamp;
    double elapsed_s = (double)elapsed_ns / 1.0e9;

    fprintf(ctx->fp,
            "\n  ],\n"
            "  \"metadata\": {\n"
            "    \"total_entries\": %zu,\n"
            "    \"runtime_seconds\": %.6f,\n"
            "    \"runtime_ns\": %lu\n"
            "  }\n"
            "}\n",
            ctx->count, elapsed_s, (unsigned long)elapsed_ns);
    fflush(ctx->fp);
    fclose(ctx->fp);
    ctx->fp = NULL;
  }

  pthread_mutex_unlock(&ctx->lock);
  pthread_mutex_destroy(&ctx->lock);
  free(ctx);
}

size_t aegis_log_count(const aegis_log_ctx_t *ctx) {
  return ctx ? ctx->count : 0;
}

/* ── Core Logging Implementations ────────────────────────────────────────── */

void aegis_log_transform(aegis_log_ctx_t *ctx, aegis_log_category_t cat,
                         const char *action, const char *target,
                         const void *addr_from, const void *addr_to,
                         size_t bytes_affected, const char *fmt, ...) {
  if (!ctx)
    return;
  if (ctx->count >= ctx->capacity)
    return;

  char detail_buf[DETAIL_BUF_SIZE] = {0};
  if (fmt) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(detail_buf, sizeof(detail_buf), fmt, ap);
    va_end(ap);
  }

  char wall[64];
  get_wall_clock(wall, sizeof(wall));
  uint64_t ts = aegis_timestamp_ns();

  /* JSON-escape the variable strings */
  char esc_action[256], esc_target[512], esc_detail[1024];
  json_escape(esc_action, sizeof(esc_action), action);
  json_escape(esc_target, sizeof(esc_target), target);
  json_escape(esc_detail, sizeof(esc_detail), detail_buf);

  char buf[LOG_BUF_SIZE];
  int n =
      snprintf(buf, sizeof(buf),
               "    {\n"
               "      \"type\": \"transform\",\n"
               "      \"timestamp_ns\": %lu,\n"
               "      \"wall_clock\": \"%s\",\n"
               "      \"category\": \"%s\",\n"
               "      \"action\": \"%s\",\n"
               "      \"target\": \"%s\",\n"
               "      \"address_from\": \"0x%lx\",\n"
               "      \"address_to\": \"0x%lx\",\n"
               "      \"bytes_affected\": %zu,\n"
               "      \"details\": \"%s\"\n"
               "    }",
               (unsigned long)ts, wall, aegis_log_cat_str(cat), esc_action,
               esc_target, (unsigned long)(uintptr_t)addr_from,
               (unsigned long)(uintptr_t)addr_to, bytes_affected, esc_detail);
  (void)n;

  pthread_mutex_lock(&ctx->lock);
  log_write_separator(ctx);
  log_write_raw(ctx, buf);
  ctx->count++;
  log_maybe_flush(ctx);
  pthread_mutex_unlock(&ctx->lock);
}

void aegis_log_event(aegis_log_ctx_t *ctx, aegis_log_category_t cat,
                     aegis_log_severity_t sev, const char *fmt, ...) {
  if (!ctx)
    return;
  if (ctx->count >= ctx->capacity)
    return;

  char detail_buf[DETAIL_BUF_SIZE] = {0};
  if (fmt) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(detail_buf, sizeof(detail_buf), fmt, ap);
    va_end(ap);
  }

  char wall[64];
  get_wall_clock(wall, sizeof(wall));
  uint64_t ts = aegis_timestamp_ns();

  char esc_detail[1024];
  json_escape(esc_detail, sizeof(esc_detail), detail_buf);

  char buf[LOG_BUF_SIZE];
  snprintf(buf, sizeof(buf),
           "    {\n"
           "      \"type\": \"event\",\n"
           "      \"timestamp_ns\": %lu,\n"
           "      \"wall_clock\": \"%s\",\n"
           "      \"category\": \"%s\",\n"
           "      \"severity\": \"%s\",\n"
           "      \"message\": \"%s\"\n"
           "    }",
           (unsigned long)ts, wall, aegis_log_cat_str(cat),
           aegis_log_sev_str(sev), esc_detail);

  pthread_mutex_lock(&ctx->lock);
  log_write_separator(ctx);
  log_write_raw(ctx, buf);
  ctx->count++;
  log_maybe_flush(ctx);
  pthread_mutex_unlock(&ctx->lock);
}

void aegis_log_memory_map(aegis_log_ctx_t *ctx, const char *operation,
                          const void *addr, size_t length, int old_prot,
                          int new_prot, const char *purpose) {
  if (!ctx)
    return;
  if (ctx->count >= ctx->capacity)
    return;

  char wall[64];
  get_wall_clock(wall, sizeof(wall));
  uint64_t ts = aegis_timestamp_ns();

  char esc_op[64], esc_purpose[256];
  json_escape(esc_op, sizeof(esc_op), operation);
  json_escape(esc_purpose, sizeof(esc_purpose), purpose);

  /* Build human-readable protection strings */
  char old_prot_str[16] = "N/A", new_prot_str[16] = "N/A";
  if (old_prot >= 0) {
    snprintf(old_prot_str, sizeof(old_prot_str), "%s%s%s",
             (old_prot & 0x1) ? "R" : "-", (old_prot & 0x2) ? "W" : "-",
             (old_prot & 0x4) ? "X" : "-");
  }
  if (new_prot >= 0) {
    snprintf(new_prot_str, sizeof(new_prot_str), "%s%s%s",
             (new_prot & 0x1) ? "R" : "-", (new_prot & 0x2) ? "W" : "-",
             (new_prot & 0x4) ? "X" : "-");
  }

  char buf[LOG_BUF_SIZE];
  snprintf(buf, sizeof(buf),
           "    {\n"
           "      \"type\": \"memory_map\",\n"
           "      \"timestamp_ns\": %lu,\n"
           "      \"wall_clock\": \"%s\",\n"
           "      \"operation\": \"%s\",\n"
           "      \"address\": \"0x%lx\",\n"
           "      \"length\": %zu,\n"
           "      \"old_protection\": \"%s\",\n"
           "      \"new_protection\": \"%s\",\n"
           "      \"old_prot_raw\": %d,\n"
           "      \"new_prot_raw\": %d,\n"
           "      \"purpose\": \"%s\"\n"
           "    }",
           (unsigned long)ts, wall, esc_op, (unsigned long)(uintptr_t)addr,
           length, old_prot_str, new_prot_str, old_prot, new_prot, esc_purpose);

  pthread_mutex_lock(&ctx->lock);
  log_write_separator(ctx);
  log_write_raw(ctx, buf);
  ctx->count++;
  log_maybe_flush(ctx);
  pthread_mutex_unlock(&ctx->lock);
}

void aegis_log_hook(aegis_log_ctx_t *ctx, const char *library,
                    const char *function, const void *original_addr,
                    const void *hook_addr, const void *got_slot,
                    bool installed) {
  if (!ctx)
    return;
  if (ctx->count >= ctx->capacity)
    return;

  char wall[64];
  get_wall_clock(wall, sizeof(wall));
  uint64_t ts = aegis_timestamp_ns();

  char esc_lib[512], esc_func[256];
  json_escape(esc_lib, sizeof(esc_lib), library);
  json_escape(esc_func, sizeof(esc_func), function);

  char buf[LOG_BUF_SIZE];
  snprintf(buf, sizeof(buf),
           "    {\n"
           "      \"type\": \"hook\",\n"
           "      \"timestamp_ns\": %lu,\n"
           "      \"wall_clock\": \"%s\",\n"
           "      \"category\": \"auditor\",\n"
           "      \"library\": \"%s\",\n"
           "      \"function\": \"%s\",\n"
           "      \"original_address\": \"0x%lx\",\n"
           "      \"hook_address\": \"0x%lx\",\n"
           "      \"got_slot\": \"0x%lx\",\n"
           "      \"installed\": %s\n"
           "    }",
           (unsigned long)ts, wall, esc_lib, esc_func,
           (unsigned long)(uintptr_t)original_addr,
           (unsigned long)(uintptr_t)hook_addr,
           (unsigned long)(uintptr_t)got_slot, installed ? "true" : "false");

  pthread_mutex_lock(&ctx->lock);
  log_write_separator(ctx);
  log_write_raw(ctx, buf);
  ctx->count++;
  log_maybe_flush(ctx);
  pthread_mutex_unlock(&ctx->lock);
}

void aegis_log_ipc(aegis_log_ctx_t *ctx, aegis_ipc_cmd_t cmd, pid_t from_pid,
                   pid_t to_pid, size_t payload_size, const char *details) {
  if (!ctx)
    return;
  if (ctx->count >= ctx->capacity)
    return;

  char wall[64];
  get_wall_clock(wall, sizeof(wall));
  uint64_t ts = aegis_timestamp_ns();

  char esc_details[1024];
  json_escape(esc_details, sizeof(esc_details), details);

  char buf[LOG_BUF_SIZE];
  snprintf(buf, sizeof(buf),
           "    {\n"
           "      \"type\": \"ipc\",\n"
           "      \"timestamp_ns\": %lu,\n"
           "      \"wall_clock\": \"%s\",\n"
           "      \"command\": \"%s\",\n"
           "      \"command_id\": %d,\n"
           "      \"from_pid\": %d,\n"
           "      \"to_pid\": %d,\n"
           "      \"payload_size\": %zu,\n"
           "      \"details\": \"%s\"\n"
           "    }",
           (unsigned long)ts, wall, aegis_log_cmd_str(cmd), (int)cmd,
           (int)from_pid, (int)to_pid, payload_size, esc_details);

  pthread_mutex_lock(&ctx->lock);
  log_write_separator(ctx);
  log_write_raw(ctx, buf);
  ctx->count++;
  log_maybe_flush(ctx);
  pthread_mutex_unlock(&ctx->lock);
}

void aegis_log_crypto(aegis_log_ctx_t *ctx, const char *operation,
                      size_t data_size, const uint8_t *iv,
                      const char *details) {
  if (!ctx)
    return;
  if (ctx->count >= ctx->capacity)
    return;

  char wall[64];
  get_wall_clock(wall, sizeof(wall));
  uint64_t ts = aegis_timestamp_ns();

  char esc_op[64], esc_details[512];
  json_escape(esc_op, sizeof(esc_op), operation);
  json_escape(esc_details, sizeof(esc_details), details);

  /* Format IV as hex string if provided */
  char iv_hex[AEGIS_GCM_IV_BYTES * 2 + 1] = "null";
  if (iv) {
    for (int i = 0; i < AEGIS_GCM_IV_BYTES; i++)
      sprintf(iv_hex + i * 2, "%02x", iv[i]);
  }

  char buf[LOG_BUF_SIZE];
  snprintf(buf, sizeof(buf),
           "    {\n"
           "      \"type\": \"crypto\",\n"
           "      \"timestamp_ns\": %lu,\n"
           "      \"wall_clock\": \"%s\",\n"
           "      \"operation\": \"%s\",\n"
           "      \"data_size\": %zu,\n"
           "      \"iv\": \"%s\",\n"
           "      \"details\": \"%s\"\n"
           "    }",
           (unsigned long)ts, wall, esc_op, data_size, iv_hex, esc_details);

  pthread_mutex_lock(&ctx->lock);
  log_write_separator(ctx);
  log_write_raw(ctx, buf);
  ctx->count++;
  log_maybe_flush(ctx);
  pthread_mutex_unlock(&ctx->lock);
}

void aegis_log_nano_exec(aegis_log_ctx_t *ctx, uint32_t opcode,
                         uint64_t vault_offset, size_t chunk_size,
                         const void *exec_addr, uint64_t cycles_elapsed) {
  if (!ctx)
    return;
  if (ctx->count >= ctx->capacity)
    return;

  char wall[64];
  get_wall_clock(wall, sizeof(wall));
  uint64_t ts = aegis_timestamp_ns();

  char buf[LOG_BUF_SIZE];
  snprintf(buf, sizeof(buf),
           "    {\n"
           "      \"type\": \"nano_exec\",\n"
           "      \"timestamp_ns\": %lu,\n"
           "      \"wall_clock\": \"%s\",\n"
           "      \"category\": \"nanomachine\",\n"
           "      \"opcode\": \"0x%04x\",\n"
           "      \"vault_offset\": %lu,\n"
           "      \"chunk_size\": %zu,\n"
           "      \"exec_address\": \"0x%lx\",\n"
           "      \"cycles_elapsed\": %lu\n"
           "    }",
           (unsigned long)ts, wall, opcode, (unsigned long)vault_offset,
           chunk_size, (unsigned long)(uintptr_t)exec_addr,
           (unsigned long)cycles_elapsed);

  pthread_mutex_lock(&ctx->lock);
  log_write_separator(ctx);
  log_write_raw(ctx, buf);
  ctx->count++;
  log_maybe_flush(ctx);
  pthread_mutex_unlock(&ctx->lock);
}

void aegis_log_syscall(aegis_log_ctx_t *ctx, uint16_t syscall_nr,
                       const void *trampoline_addr, long result,
                       const char *details) {
  if (!ctx)
    return;
  if (ctx->count >= ctx->capacity)
    return;

  char wall[64];
  get_wall_clock(wall, sizeof(wall));
  uint64_t ts = aegis_timestamp_ns();

  char esc_details[512];
  json_escape(esc_details, sizeof(esc_details), details);

  char buf[LOG_BUF_SIZE];
  snprintf(buf, sizeof(buf),
           "    {\n"
           "      \"type\": \"syscall\",\n"
           "      \"timestamp_ns\": %lu,\n"
           "      \"wall_clock\": \"%s\",\n"
           "      \"category\": \"trampoline\",\n"
           "      \"syscall_nr\": %u,\n"
           "      \"trampoline_address\": \"0x%lx\",\n"
           "      \"result\": %ld,\n"
           "      \"details\": \"%s\"\n"
           "    }",
           (unsigned long)ts, wall, (unsigned int)syscall_nr,
           (unsigned long)(uintptr_t)trampoline_addr, result, esc_details);

  pthread_mutex_lock(&ctx->lock);
  log_write_separator(ctx);
  log_write_raw(ctx, buf);
  ctx->count++;
  log_maybe_flush(ctx);
  pthread_mutex_unlock(&ctx->lock);
}
