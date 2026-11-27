/* Measures what rating passwords leaves in memory, on the device.
 *
 * Rates made-up passwords with the estimator as the app builds it, once
 * directly and once the way the password report does it: on a stack of its
 * own that is overwritten afterwards (src/wipedstack.c), with heap blocks
 * that are wiped when freed (src/estimator.c). After each run it looks for
 * fragments of the passwords in every writable page of the process and on
 * the dead part of its stack. The protected run must leave nothing. What
 * the direct run leaves depends on the compiler and the password, so a last
 * run leaves copies on purpose, on the stack and in a freed block, to show
 * that the search finds such things on this device. Built and run by
 * tools/run-residue-check.sh (security review 2026-11, F2). */
#define _GNU_SOURCE
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "estimator.h"
#include "wipedstack.h"

#define FRAGMENT 5
#define COUNT(table) (sizeof(table) / sizeof((table)[0]))

/* Read-only, so the search over writable pages does not find them here. */
static const char *const PASSWORDS[] = {
    "Xk9#mQ2$vL7!pR4zWq8&nB3",
    "correct horse battery staple",
    "P@ssw0rd-Tr0ub4dor",
    "MySecretPIN19861234",
    "zxcvbnmasdfghjklqwertyuiop",
    "Sommer2024!Dragon",
    "7f3a9c1e5b2d8046af19c37e",
    "1212121212121212121212121212",
};

static unsigned char snapshot[1 << 20];
static char lent[128];
static double total;

static int fragmentAt(const unsigned char *at, const unsigned char *end)
{
    size_t password;
    for (password = 0; password < COUNT(PASSWORDS); ++password) {
        const char *text = PASSWORDS[password];
        const size_t length = strlen(text);
        size_t start;
        for (start = 0; start + FRAGMENT <= length; ++start) {
            int matched = 0;
            while (at + matched < end && start + matched < length
                   && tolower(at[matched]) == tolower((unsigned char)text[start + matched]))
                ++matched;
            if (matched >= FRAGMENT)
                return matched;
        }
    }
    return 0;
}

static int fragments(const unsigned char *from, const unsigned char *to)
{
    int found = 0;
    const unsigned char *at;
    for (at = from; at + FRAGMENT <= to; ++at) {
        const int length = fragmentAt(at, to);
        if (length) {
            ++found;
            at += length;
        }
    }
    return found;
}

/* The caller's copy of each password is wiped after use, as in the core. */
static void rateAll(void *unused)
{
    size_t password;
    (void)unused;
    for (password = 0; password < COUNT(PASSWORDS); ++password) {
        strcpy(lent, PASSWORDS[password]);
        total += sv_estimate(lent);
        explicit_bzero(lent, sizeof lent);
    }
}

/* What code that wipes nothing would leave behind. */
__attribute__((noinline)) static void leaveCopies(void)
{
    volatile char onStack[128];
    char *onHeap = malloc(128);
    size_t index;
    for (index = 0; PASSWORDS[1][index]; ++index) {
        onStack[index] = PASSWORDS[1][index];
        if (onHeap)
            onHeap[32 + index] = PASSWORDS[1][index];
    }
    free(onHeap);
}

static unsigned long stackStart;
static size_t snapshotBytes;

static void findStack(void)
{
    FILE *maps = fopen("/proc/self/maps", "r");
    char line[512];
    unsigned long from;
    while (maps && fgets(line, sizeof line, maps))
        if (strstr(line, "[stack]") && sscanf(line, "%lx-", &from) == 1)
            stackStart = from;
    if (maps)
        fclose(maps);
}

/* Copies the dead part of the stack, below the frame this is used in. It is
 * a macro because a call would put its own frame over what a run left. */
#define SNAPSHOT_DEAD_STACK() \
    do { \
        volatile char here; \
        unsigned long from = stackStart; \
        snapshotBytes = (size_t)((const unsigned char *)&here - (const unsigned char *)from); \
        if (snapshotBytes > sizeof snapshot) { \
            from += snapshotBytes - sizeof snapshot; \
            snapshotBytes = sizeof snapshot; \
        } \
        memcpy(snapshot, (const void *)from, snapshotBytes); \
    } while (0)

/* Searches the snapshot of the dead stack and every other writable page. */
static int search(const char *run, int *stackFragments)
{
    FILE *maps;
    char line[512];
    unsigned long from, to;
    char permissions[8];
    const int inStack = fragments(snapshot, snapshot + snapshotBytes);
    int elsewhere = 0;

    explicit_bzero(snapshot, sizeof snapshot);
    maps = fopen("/proc/self/maps", "r");
    while (maps && fgets(line, sizeof line, maps)) {
        if (sscanf(line, "%lx-%lx %7s", &from, &to, permissions) != 3)
            continue;
        if (strncmp(permissions, "rw", 2) != 0 || strstr(line, "[stack]"))
            continue;
        elsewhere += fragments((const unsigned char *)from, (const unsigned char *)to);
    }
    if (maps)
        fclose(maps);
    printf("%-10s fragments of %d or more bytes: dead stack %d, other writable memory %d\n",
           run, FRAGMENT, inStack, elsewhere);
    if (stackFragments)
        *stackFragments = inStack;
    return inStack + elsewhere;
}

int main(void)
{
    int left, controlTotal, controlStack = 0;
    bool ran;

    findStack();
    /* Once before anything is rated, so stdio has its buffers already. */
    SNAPSHOT_DEAD_STACK();
    search("(setup)", NULL);

    rateAll(NULL);
    SNAPSHOT_DEAD_STACK();
    search("direct:", NULL);

    ran = sv_run_on_wiped_stack(rateAll, NULL);
    SNAPSHOT_DEAD_STACK();
    if (!ran) {
        printf("the wiped stack could not be set up\n");
        return 2;
    }
    left = search("protected:", NULL);

    leaveCopies();
    SNAPSHOT_DEAD_STACK();
    controlTotal = search("control:", &controlStack);

    printf("%zu passwords rated twice, %.0f bits in total\n", COUNT(PASSWORDS), total);
    if (controlStack == 0 || controlTotal == controlStack) {
        printf("FAIL: the search missed the copies left on purpose, so it proves nothing\n");
        return 2;
    }
    if (left) {
        printf("FAIL: the protected run left fragments\n");
        return 1;
    }
    printf("ok: the protected run left nothing, and the search finds what is left\n");
    return 0;
}
