
import logging
logging.basicConfig(level=logging.DEBUG)

import base64
from datetime import datetime
import hashlib
import hmac
import json
import socket
import sqlite3

import requests

from .local_settings import AZURE_CUSTOMER_ID, AZURE_SHARED_KEY

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

session = requests.Session()

def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    """Returns authorization header which will be used when sending data into Azure Log Analytics"""

    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding='utf-8')
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = f"SharedKey {customer_id}:{encoded_hash}"
    logging.debug(authorization)
    return authorization


def post_data(customer_id, shared_key, body, log_type):
    """Sends payload to Azure Log Analytics Workspace

    Keyword arguments:
    customer_id -- Workspace ID obtained from Advanced Settings
    shared_key -- Authorization header, created using build_signature
    body -- payload to send to Azure Log Analytics
    log_type -- Azure Log Analytics table name
    """

    body = json.dumps(body)

    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)

    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    logging.debug(headers)
    logging.debug(body)
    response = session.post(uri, data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        logging.debug(f"Accepted payload: {body}")
    else:
        logging.error(f"Unable to Write ({response.status_code}): {response.text}")
        raise Exception(f"Unable to Write ({response.status_code}): {response.text}")


last_filename = '.pihole-latest'
LAST_ID = 0

try:
    with open(last_filename, 'r') as of:
        LAST_ID = int(of.read())
except FileNotFoundError:
    pass
except ValueError:
    pass

def update_latest(rowid, force=False):
    global LAST_ID
    if rowid < LAST_ID + 100 and not force:
        return

    print(f"Writing LAST_ID {rowid}")
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

    logging.debug(record)
    post_data(AZURE_CUSTOMER_ID, AZURE_SHARED_KEY, record, "Normalized")
    update_latest(row['id'])

con.close()
update_latest(row['id'], force=True)
