
import logging
logging.basicConfig(level=logging.INFO)

import base64
from datetime import datetime
import json
import hashlib
import hmac
import requests


class LogAnalytics():

    def __init__(self, workspace_id, shared_key):
        self._session = requests.Session()
        self._workspace_id = workspace_id
        self._shared_key = shared_key

    # Adapted from https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api?tabs=python, licensed under the BY-NC-ND 4.0 license. © 2021 Microsoft.
    def _build_signature(self, date, content_length, method, content_type, resource):
        x_headers = 'x-ms-date:' + date
        string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
        bytes_to_hash = bytes(string_to_hash, encoding='utf-8')
        decoded_key = base64.b64decode(self._shared_key)
        encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
        authorization = f"SharedKey {self._workspace_id}:{encoded_hash}"
        logging.debug(authorization)
        return authorization

    # Adapted from https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api?tabs=python, licensed under the BY-NC-ND 4.0 license. © 2021 Microsoft.
    def _post_data(self, log_type, body, timestamp=None):

        body = json.dumps(body)

        method = 'POST'
        content_type = 'application/json'
        resource = '/api/logs'
    
        if timestamp is None:
            rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        else:
            rfc1123date = timestamp.strftime('%a, %d %b %Y %H:%M:%S GMT')

        content_length = len(body)
        signature = self._build_signature(rfc1123date, content_length, method, content_type, resource)

        uri = 'https://' + self._workspace_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

        headers = {
            'content-type': content_type,
            'Authorization': signature,
            'Log-Type': log_type,
            'x-ms-date': rfc1123date
        }

        logging.debug(headers)
        logging.debug(body)
        response = self._session.post(uri, data=body, headers=headers)

        if (response.status_code >= 200 and response.status_code <= 299):
            logging.debug(f"Accepted payload: {body}")
        else:
            raise Exception(f"Exception from Log Analytics ({response.status_code}): {response.text}")

    def post(self, log_type, body, timestamp=None):
        return self._post_data(log_type, body, timestamp)

