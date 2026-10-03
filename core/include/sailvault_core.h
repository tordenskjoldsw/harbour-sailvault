#ifndef SAILVAULT_CORE_H
#define SAILVAULT_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Static, NUL-terminated string. Valid for the process lifetime, never free it. */
const char *sailvault_core_version(void);

/* Fills buffer with length bytes from the OS CSPRNG. buffer must hold length bytes. */
bool sailvault_fill_random(uint8_t *buffer, size_t length);

#ifdef __cplusplus
}
#endif

#endif /* SAILVAULT_CORE_H */
