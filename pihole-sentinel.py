
import logging
logging.basicConfig(level=logging.WARNING)

from datetime import datetime, timezone
import os
import socket
import sqlite3

from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient


DEVICE_HOSTNAME = socket.gethostname()
DEVICE_IP6 = socket.getaddrinfo("www.google.com", 443, socket.AF_INET6)[0][4][0]

DCE_ENDPOINT = os.environ['DATA_COLLECTION_ENDPOINT']
DCR_RULE_ID = os.environ['LOGS_DCR_RULE_ID']
DCR_STREAM_NAME = os.environ['LOGS_DCR_STREAM_NAME']

CREDENTIAL = DefaultAzureCredential()


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

QUERY_TYPES = {
    1: "A",
    2: "AAAA",
    3: "ANY",
    4: "SRV",
    5: "SOA",
    6: "PTR",
    7: "TXT",
    8: "NAPTR",
    9: "MX",
    10: "DS",
    11: "RRSIG",
    12: "DNSKEY",
    13: "NS",
    14: "OTHER",
    15: "SVCB",
    16: "HTTPS",
}

# https://docs.pi-hole.net/database/query-database/#supported-status-types
QUERY_STATUS = {
    0: "Failure: Unknown status (not yet known)",
    1: "Failure: Domain contained in gravity database",
    2: "Success: Forwarded",
    3: "Success: Replied from cache",
    4: "Failure: Domain matched by a regex denylist filter",
    5: "Failure: Domain contained in exact denylist",
    6: "Failure: By upstream server (known blocking page IP address)",
    7: "Failure: By upstream server (0.0.0.0 or ::)",
    8: "Failure: By upstream server (NXDOMAIN with RA bit unset)",
    9: "Failure: Domain contained in gravity database (deep CNAME inspection)",
    10: "Failure: Domain matched by a regex denylist filter (deep CNAME inspection)",
    11: "Failure: Domain contained in exact denylist (deep CNAME inspection)",
    12: "Success: Retried query",
    13: "Success: Retried but ignored query (this may happen during ongoing DNSSEC validation)",
    14: "Success: Already forwarded, not forwarding again",
    15: "Failure: Database is busy",
    16: "Failure: Special domain",
    17: "Success: Replied from stale cache",
    18: "Failure: By upstream server (EDE 15)"
}

# https://docs.pi-hole.net/database/query-database/#supported-reply-types
# https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
REPLY_CODES = {
    0:  (4095, "NA"),     # Unknown (no reply so far)
    1:  (0, "NoError"),   # NODATA
    2:  (3, "NXDomain"),  # NXDOMAIN
    3:  (0, "NoError"),   # CNAME
    4:  (0, "NoError"),   # IP
    5:  (0, "NoError"),   # DOMAIN
    6:  (0, "NoError"),   # RRNAME
    7:  (2, "ServFail"),  # SERVFAIL
    8:  (5, "Refused"),   # REFUSED
    9:  (4, "NotImp"),    # NOTIMP
    10: (4094, "NA"),     # OTHER
    11: (4093, "NA"),     # DNSSEC
    12: (5, "Refused"),   # NONE
    13: (4091, "NA"),     # BLOB
}

last_filename = '.pihole-latest'
LAST_ID = 0

try:
    with open(last_filename, 'r') as of:
        LAST_ID = int(of.read())
except FileNotFoundError:
    pass
except ValueError:
    pass

now = datetime.now().isoformat()
logging.warning(f"Starting at {now} from queries.id={LAST_ID}")

def update_latest(rowid, force=False):
    global LAST_ID
    if rowid < LAST_ID + 100 and not force:
        return

    logging.info(f"Writing LAST_ID {rowid}")
    with open(last_filename, 'w') as of:
        of.write(str(rowid))
    LAST_ID = rowid


con = sqlite3.connect("file:/etc/pihole/pihole-FTL.db?mode=ro", uri=True)

logs = []

con.row_factory = dict_factory
cur = con.cursor()
for row in cur.execute('SELECT * FROM queries WHERE id >:id ORDER BY id', {"id": LAST_ID}):
    (event_result, event_message) = QUERY_STATUS.get(row['status'], "Unknown: Unknown").split(": ")
    (rcode_value, rcode_text) = REPLY_CODES.get(row['reply_type'], (4090, "NA"))
    timestamp = datetime.fromtimestamp(row['timestamp'], timezone.utc).isoformat().replace("+00:00", "Z")

    record = {
        "TimeGenerated": timestamp,
        "EventCount": 1,
        "EventStartTime": timestamp,
        "EventEndTime": timestamp,
        
        "EventOriginalUid": str(row['id']),
        "EventType": "Query",
        "EventResult": event_result,
        "EventMessage": event_message,
        "EventResultDetails": rcode_text,
        "EventProduct": "Pi-hole",
        "EventVendor": "Pi-hole",
        "EventSchema": "Dns",
        "EventSchemaVersion": "0.1.7",
        "Dvc": DEVICE_HOSTNAME,
        "DvcIpAddr": DEVICE_IP6,
        "DvcHostname": DEVICE_HOSTNAME,

        "SrcIpAddr": row['client'],
        "DnsQuery": row['domain'],
        "DnsQueryTypeName": QUERY_TYPES.get(row['type']),
        "DnsResponseCode": rcode_value,
    }
    logs.append(record)
con.close()

try:
    if len(logs) > 0:
        logs_ingestion_client = LogsIngestionClient(DCE_ENDPOINT, CREDENTIAL)
        logs_ingestion_client.upload(rule_id=DCR_RULE_ID, stream_name=DCR_STREAM_NAME, logs=logs)
        latest_id = int(logs[-1]['EventOriginalUid'])
        update_latest(latest_id, force=True)
        logging.warning(f"Uploaded {len(logs)} logs, up to queries.id={latest_id}")
    else:
        logging.warning("No new logs to upload.")
except HttpResponseError as e:
    logging.error(f"Upload failed: {e}")
