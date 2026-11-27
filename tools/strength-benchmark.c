/* Times the password strength estimator on made-up passwords: a mix like a
 * real database for the report over all entries, and long passwords for the
 * rating while typing. Built and run by tools/run-strength-benchmark.sh. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <zxcvbn.h>

#define ENTRIES 1000
#define MAX_LENGTH 256

static uint32_t state = 0x5a11fa57u;

static uint32_t next(uint32_t bound)
{
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state % bound;
}

static void randomChars(char *out, int length, const char *alphabet)
{
    const uint32_t size = (uint32_t)strlen(alphabet);
    int i;
    for (i = 0; i < length; ++i)
        out[i] = alphabet[next(size)];
    out[length] = '\0';
}

static const char ALNUM[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static const char PRINTABLE[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&()*+,-./:;<=>?@[]^_{|}~";
static const char *const WORDS[] = {
    "summer", "dragon", "monkey", "coffee", "garden", "silver", "window", "planet",
    "harbour", "sailing", "orange", "castle", "winter", "purple", "rocket", "bridge",
};
#define WORD_COUNT (sizeof WORDS / sizeof WORDS[0])

/* 40 % generated without symbols, 20 % with symbols, 20 % a word with
 * digits, 10 % a PIN, 10 % a passphrase of four or five words. */
static void makePassword(char *out, int index)
{
    const int kind = index % 10;
    if (kind < 4) {
        randomChars(out, 16 + (int)next(9), ALNUM);
    } else if (kind < 6) {
        randomChars(out, 12 + (int)next(9), PRINTABLE);
    } else if (kind < 8) {
        sprintf(out, "%s%u!", WORDS[next(WORD_COUNT)], 1950 + next(80));
    } else if (kind < 9) {
        randomChars(out, 4 + (int)next(3), "0123456789");
    } else {
        const int words = 4 + (int)next(2);
        int i;
        out[0] = '\0';
        for (i = 0; i < words; ++i) {
            if (i > 0)
                strcat(out, " ");
            strcat(out, WORDS[next(WORD_COUNT)]);
        }
    }
}

static double nowMs(void)
{
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    return time.tv_sec * 1000.0 + time.tv_nsec / 1e6;
}

int main(void)
{
    static const int LENGTHS[] = { 16, 32, 64, 100, 128, 256 };
    char password[MAX_LENGTH + 1];
    double total = 0, slowest = 0, bits = 0;
    size_t i;
    int entry;

    for (entry = 0; entry < ENTRIES; ++entry) {
        double start, elapsed;
        makePassword(password, entry);
        start = nowMs();
        bits += ZxcvbnMatch(password, NULL, NULL);
        elapsed = nowMs() - start;
        total += elapsed;
        if (elapsed > slowest)
            slowest = elapsed;
    }
    printf("%d entries: %.0f ms in total, %.2f ms on average, %.1f ms the slowest (mean %.0f bits)\n",
           ENTRIES, total, total / ENTRIES, slowest, bits / ENTRIES);

    for (i = 0; i < sizeof LENGTHS / sizeof LENGTHS[0]; ++i) {
        double start, elapsed;
        randomChars(password, LENGTHS[i], PRINTABLE);
        start = nowMs();
        ZxcvbnMatch(password, NULL, NULL);
        elapsed = nowMs() - start;
        printf("one random password of %3d characters: %.1f ms\n", LENGTHS[i], elapsed);
    }
    for (i = 0; i < sizeof LENGTHS / sizeof LENGTHS[0]; ++i) {
        double start, elapsed;
        memset(password, 'a', (size_t)LENGTHS[i]);
        password[LENGTHS[i]] = '\0';
        start = nowMs();
        ZxcvbnMatch(password, NULL, NULL);
        elapsed = nowMs() - start;
        printf("one repeated character, %3d times: %.1f ms\n", LENGTHS[i], elapsed);
    }
    return 0;
}
