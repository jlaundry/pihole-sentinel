
import logging
logging.basicConfig(level=logging.INFO)

from datetime import datetime
import socket
import sqlite3

from azure_log_analytics import LogAnalytics
from local_settings import AZURE_WORKSPACE_ID, AZURE_SECRET_KEY

DEVICE_HOSTNAME = socket.gethostname()
DEVICE_IP6 = socket.getaddrinfo("www.google.com", 443, socket.AF_INET6)[0][4][0]

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

QUERY_STATUS = {
    0: "Failure: Unknown status (not yet known)",
    1: "Failure: Domain contained in gravity database",
    2: "Success: Forwarded",
    3: "Success: Known, replied to from cache",
    4: "Failure: Domain matched by a regex blacklist filter",
    5: "Failure: Domain contained in exact blacklist",
    6: "Failure: By upstream server (known blocking page IP address)",
    7: "Failure: By upstream server (0.0.0.0 or ::)",
    8: "Failure: By upstream server (NXDOMAIN with RA bit unset)",
    9: "Failure: Domain contained in gravity database",
    10: "Failure: Domain matched by a regex blacklist filter",
    11: "Failure: Domain contained in exact blacklist",
    12: "Success: Retried query",
    13: "Success: Retried but ignored query (this may happen during ongoing DNSSEC validation)",
    14: "Success: Already forwarded, not forwarding again",
}

sentinel = LogAnalytics(AZURE_WORKSPACE_ID, AZURE_SECRET_KEY)

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
logging.info(f"Starting at {now} from queries.id={LAST_ID}")

def update_latest(rowid, force=False):
    global LAST_ID
    if rowid < LAST_ID + 100 and not force:
        return

    logging.info(f"Writing LAST_ID {rowid}")
    with open(last_filename, 'w') as of:
        of.write(str(rowid))
    LAST_ID = rowid


#con = sqlite3.connect('/etc/pihole/pihole-FTL.db')
con = sqlite3.connect('/tmp/pihole-FTL.db')
con.row_factory = dict_factory
cur = con.cursor()

for row in cur.execute('SELECT * FROM queries WHERE id >:id ORDER BY id', {"id": LAST_ID}):

    record = {
        "TimeGenerated": datetime.utcfromtimestamp(row['timestamp']).isoformat() + "Z",

        "EventCount": 1,
        "EventOriginalUid": str(row['id']),
        "EventType": "lookup",
        "EventResult": QUERY_STATUS.get(row['status']).split(":")[0],
        "EventResultDetails": QUERY_TYPES.get(row['type']),
        "EventProduct": "Pi Hole",
        "EventVendor": "Pi Hole",
        "EventSchemaVersion": "0.1.1",
        "Dvc": DEVICE_HOSTNAME,
        "DvcIpAddr": DEVICE_IP6,
        "DvcHostname": DEVICE_HOSTNAME,

        "SrcIpAddr": row['client'],
        "DnsQuery": row['domain'],
        "DnsQueryTypeName": QUERY_TYPES.get(row['type']),
        "DnsResponseCodeName": "NA",
    }

    log_type = "Normalized"
    logging.debug(record)
    sentinel.post(log_type, record)
    update_latest(row['id'])

con.close()
update_latest(row['id'], force=True)

