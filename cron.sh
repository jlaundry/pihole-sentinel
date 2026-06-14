#!/bin/bash

cd /opt/pihole-sentinel
source .env/bin/activate

export DATA_COLLECTION_ENDPOINT="https://example.westus2-1.ingest.monitor.azure.com"
export LOGS_DCR_RULE_ID="dcr-00000000000000000000000000000000"
export LOGS_DCR_STREAM_NAME="Custom-ASimDnsActivityLogs"

# If using a Managed Identity with Azure Arc, the following may be required:
export IMDS_ENDPOINT="http://localhost:40342"
export IDENTITY_ENDPOINT="http://localhost:40342/metadata/identity/oauth2/token"

if [ -f "/tmp/pihole-sentinel.lock" ]; then
    echo "Lockfile exists, bailing out"
else
    touch /tmp/pihole-sentinel.lock
    sleep 10 # Allow FTL to finish writing (happens at the top of the minute)
    python /opt/pihole-sentinel/pihole-sentinel.py
    rm /tmp/pihole-sentinel.lock
fi
