/* Compiles the vendored strength estimator, unchanged, with heap blocks
 * that are overwritten when they are freed. zxcvbn-c wipes nothing itself,
 * and its blocks hold where the parts of a password start, how long they
 * are and how common each matched word is. It also uses the result of
 * malloc unchecked, so a failed allocation ends the process here. */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef union {
    size_t size;
    max_align_t alignment;
} BlockHeader;

static void *wipingMalloc(size_t size)
{
    BlockHeader *header = malloc(sizeof *header + size);
    if (!header)
        abort();
    header->size = size;
    return header + 1;
}

static void wipingFree(void *block)
{
    BlockHeader *header;
    if (!block)
        return;
    header = (BlockHeader *)block - 1;
    explicit_bzero(header, sizeof *header + header->size);
    free(header);
}

#define malloc wipingMalloc
#define free wipingFree
#include "zxcvbn.c"
