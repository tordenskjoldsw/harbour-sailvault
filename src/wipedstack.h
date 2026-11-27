#ifndef WIPEDSTACK_H
#define WIPEDSTACK_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Runs function(argument) on a thread with a stack of its own, waits for it
 * and overwrites that stack before releasing it. Code that handles secrets
 * it cannot wipe itself, such as the strength estimator, leaves nothing on
 * a stack this way. Returns false, without having called function, when the
 * stack or the thread could not be set up. */
bool sv_run_on_wiped_stack(void (*function)(void *), void *argument);

#ifdef __cplusplus
}
#endif

#endif /* WIPEDSTACK_H */
