
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

    def _build_signature(self, customer_id, shared_key, date, content_length, method, content_type, resource):
        x_headers = 'x-ms-date:' + date
        string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
        bytes_to_hash = bytes(string_to_hash, encoding='utf-8')
        decoded_key = base64.b64decode(shared_key)
        encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
        authorization = f"SharedKey {customer_id}:{encoded_hash}"
        logging.debug(authorization)
        return authorization

    def _post_data(self, customer_id, shared_key, body, log_type):

        body = json.dumps(body)

        method = 'POST'
        content_type = 'application/json'
        resource = '/api/logs'
        rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        content_length = len(body)
        signature = self._build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)

        uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

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
            logging.error(f"Unable to Write ({response.status_code}): {response.text}")
            raise Exception(f"Unable to Write ({response.status_code}): {response.text}")

    def post(self, body, log_type):
        return self._post_data(self._workspace_id, self._shared_key, body, log_type)

