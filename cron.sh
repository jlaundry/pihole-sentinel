#!/bin/bash

cd /opt/pihole-sentinel
source .env/bin/activate

if [ -f "/tmp/pihole-sentinel.lock" ]; then
    echo "Lockfile exists, bailing out"
else
    touch /tmp/pihole-sentinel.lock
    sleep 10 # Allow FTL to finish writing
    cp /etc/pihole/pihole-FTL.db /tmp/pihole-FTL.db && python /opt/pihole-sentinel/pihole-to-sentinel.py
    rm /tmp/pihole-sentinel.lock
fi
