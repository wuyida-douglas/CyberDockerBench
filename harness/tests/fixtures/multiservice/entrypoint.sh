#!/bin/sh
set -eu
if [ ! -f /var/lib/pilot/counter ]; then
    printf '42\n' > /var/lib/pilot/counter
fi
if [ ! -f /opt/pilot/setting.txt ]; then
    printf 'vulnerable\n' > /opt/pilot/setting.txt
fi
if [ ! -f /var/lib/pilot-anonymous/token ]; then
    cp /opt/pilot/seed-anonymous /var/lib/pilot-anonymous/token
fi
exec python3 /opt/pilot/server.py
