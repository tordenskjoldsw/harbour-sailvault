/* libFuzzer target for the strength estimator as the app builds and calls
 * it: zero-terminated text of at most 1024 bytes, which is what the core
 * lends for 256 characters. Run by tools/check-estimator.sh. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "estimator.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char text[1025];
    const size_t length = size > sizeof text - 1 ? sizeof text - 1 : size;
    size_t index;
    double bits;

    for (index = 0; index < length; ++index)
        text[index] = data[index] ? (char)data[index] : 'x';
    text[length] = '\0';
    bits = sv_estimate(text);
    /* Not a number, or negative. */
    if (!(bits >= 0.0))
        abort();
    return 0;
}
