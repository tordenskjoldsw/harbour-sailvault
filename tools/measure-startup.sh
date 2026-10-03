#!/usr/bin/env bash
# Measures launch-to-first-frame of the installed app on the configured sfdk device.
# The first run is reported separately; the summary covers the remaining runs.
#
# Usage: tools/measure-startup.sh [runs]
set -euo pipefail

runs=${1:-11}
sfdk=${SFDK:-"$HOME/SailfishOS/bin/sfdk"}

# The device shell is BusyBox without millisecond date, so both timestamps use
# CLOCK_BOOTTIME: /proc/uptime before the launch, the app's trace line after it.
"$sfdk" device exec -- sh -c "
    pkill -x harbour-sailvau
    sleep 2
    i=1
    while [ \$i -le $runs ]; do
        read up rest < /proc/uptime
        /usr/bin/harbour-sailvault --startup-trace >/tmp/sailvault-trace.txt 2>&1 &
        pid=\$!
        sleep 4
        frame=\$(grep -a -o 'first-frame-boottime-ms=[0-9]*' /tmp/sailvault-trace.txt | cut -d= -f2)
        echo \"\$up \$frame\"
        kill \$pid 2>/dev/null
        sleep 3
        i=\$((i + 1))
    done
    rm -f /tmp/sailvault-trace.txt
" | gawk '
    NF == 2 {
        ms = $2 - int($1 * 1000 + 0.5)
        printf "run %2d: %4d ms\n", NR, ms
        if (NR > 1) { values[++n] = ms; sum += ms }
        else first = ms
    }
    END {
        if (n == 0) { print "no measurements" > "/dev/stderr"; exit 1 }
        asort(values)
        median = (n % 2) ? values[(n + 1) / 2] : (values[n / 2] + values[n / 2 + 1]) / 2
        printf "first run: %d ms\n", first
        printf "runs 2-%d: median %d ms, min %d ms, max %d ms, mean %d ms\n",
            n + 1, median, values[1], values[n], sum / n
    }'
