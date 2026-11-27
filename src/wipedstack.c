#define _GNU_SOURCE
#include "wipedstack.h"

#include <pthread.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* The password report used 8 KB in the estimator; the rest is room for the
 * core's walk over the groups. */
#define STACK_BYTES (512 * 1024)

typedef struct {
    void (*function)(void *);
    void *argument;
} Call;

static void *run(void *context)
{
    Call *call = context;
    call->function(call->argument);
    return NULL;
}

bool sv_run_on_wiped_stack(void (*function)(void *), void *argument)
{
    const size_t guard = (size_t)sysconf(_SC_PAGESIZE);
    const size_t mapped = guard + STACK_BYTES;
    Call call = { function, argument };
    pthread_attr_t attributes;
    pthread_t thread;
    char *memory;
    char *stack;
    bool started = false;

    memory = mmap(NULL, mapped, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (memory == MAP_FAILED)
        return false;
    /* The stack grows down; running off its end faults in the guard page
     * instead of writing into other memory. */
    stack = memory + guard;
    if (mprotect(memory, guard, PROT_NONE) == 0 && pthread_attr_init(&attributes) == 0) {
        if (pthread_attr_setstack(&attributes, stack, STACK_BYTES) == 0
            && pthread_create(&thread, &attributes, run, &call) == 0) {
            pthread_join(thread, NULL);
            started = true;
        }
        pthread_attr_destroy(&attributes);
    }
    explicit_bzero(stack, STACK_BYTES);
    munmap(memory, mapped);
    return started;
}
