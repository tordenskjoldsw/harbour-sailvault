#ifndef SAILVAULT_CORE_H
#define SAILVAULT_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Static, NUL-terminated string. Valid for the process lifetime, never free it. */
const char *sailvault_core_version(void);

#ifdef __cplusplus
}
#endif

#endif /* SAILVAULT_CORE_H */
