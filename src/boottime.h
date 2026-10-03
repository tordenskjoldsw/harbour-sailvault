#ifndef BOOTTIME_H
#define BOOTTIME_H

#include <ctime>

// Milliseconds since boot, including time spent in suspend. Qt timers use
// CLOCK_MONOTONIC, which stops while the phone sleeps, so security deadlines
// are measured with this clock instead.
inline long long bootTimeMs()
{
    timespec now;
    clock_gettime(CLOCK_BOOTTIME, &now);
    return static_cast<long long>(now.tv_sec) * 1000 + now.tv_nsec / 1000000;
}

#endif // BOOTTIME_H
