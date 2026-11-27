/* Checks the generated dictionary of zxcvbn-c (third_party/zxcvbn/dict-src.h)
 * against the bounds the estimator relies on without checking them itself:
 * every index it can form while walking the word tree must be inside its
 * table, and the list of possible next characters must fit its buffer. Run
 * by tools/check-estimator.sh. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dict-src.h"

#define COUNT(table) (sizeof(table) / sizeof((table)[0]))

static long failures, nodesVisited, words;
static int deepest;

static void fail(const char *what, unsigned long where)
{
    if (failures++ < 20)
        printf("FAIL %s at %lu\n", what, where);
}

/* The walk of DoDictMatch in zxcvbn.c over every path of the tree. */
static void walk(unsigned int node, long ordinal, int depth)
{
    const uint32_t data = DictNodes[node];
    const unsigned int pattern = data & ((1u << BITS_CHILD_PATT_INDEX) - 1);
    const unsigned int base = (data >> BITS_CHILD_PATT_INDEX) & ((1u << BITS_CHILD_MAP_INDEX) - 1);
    const unsigned char *map;
    int children = 0, bit;
    int child;

    ++nodesVisited;
    if (depth > deepest)
        deepest = depth;
    if (pattern >= COUNT(ChildMap) / SizeChildMapEntry) {
        fail("child map index", node);
        return;
    }
    map = ChildMap + pattern * SizeChildMapEntry;
    for (bit = 0; bit < SizeChildMapEntry * 8; ++bit)
        if (map[bit / 8] & (1 << (bit % 8)))
            ++children;
    if (children && base + (unsigned int)children > COUNT(ChildLocs)) {
        fail("child location index", node);
        return;
    }
    for (child = 0; child < children; ++child) {
        long childOrdinal = ordinal;
        unsigned int location;
        int earlier;
        for (earlier = 0; earlier < child; ++earlier) {
            const unsigned int sibling = ChildLocs[base + earlier];
            if (sibling >= COUNT(EndCountSml)) {
                fail("end count index", node);
                return;
            }
            childOrdinal += EndCountSml[sibling];
            if (sibling < NumLargeCounts)
                childOrdinal += EndCountLge[sibling] * 256;
        }
        location = ChildLocs[base + child];
        if (location >= COUNT(DictNodes) || (location >> 3) >= COUNT(WordEndBits)) {
            fail("node index", node);
            continue;
        }
        if (WordEndBits[location >> 3] & (1 << (location & 7))) {
            if (childOrdinal < 0 || childOrdinal >= (long)COUNT(Ranks))
                fail("rank index", location);
            else if (Ranks[childOrdinal] == 0)
                fail("rank of zero, whose logarithm is taken", location);
            ++words;
            ++childOrdinal;
        }
        walk(location, childOrdinal, depth + 1);
    }
}

int main(void)
{
    size_t entry;
    int mostChildren = 0, highestBit = -1;

    if (NumLargeCounts > COUNT(EndCountLge))
        fail("large end counts", NumLargeCounts);
    for (entry = 0; entry < COUNT(ChildMap) / SizeChildMapEntry; ++entry) {
        int children = 0, bit;
        for (bit = 0; bit < SizeChildMapEntry * 8; ++bit) {
            if (ChildMap[entry * SizeChildMapEntry + bit / 8] & (1 << (bit % 8))) {
                ++children;
                if (bit > highestBit)
                    highestBit = bit;
            }
        }
        if (children > mostChildren)
            mostChildren = children;
    }
    /* ListPossibleChars writes one byte per child and a terminating zero
     * into PossChars[CHARSET_SIZE], and reads CharSet at each set bit. */
    if (mostChildren + 1 > CHARSET_SIZE)
        fail("possible characters exceed the buffer", (unsigned long)mostChildren);
    if (highestBit >= (int)strlen(CharSet))
        fail("character set index", (unsigned long)highestBit);

    walk(ROOT_NODE_LOC, 1, 0);
    printf("%ld nodes visited, %ld words, depth %d; most children %d of %d, highest character %d of %zu\n",
           nodesVisited, words, deepest, mostChildren, CHARSET_SIZE - 1, highestBit,
           strlen(CharSet) - 1);
    if (failures) {
        printf("%ld failures\n", failures);
        return 1;
    }
    return 0;
}
