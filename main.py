#!/usr/bin/env python
#coding:utf-8
import os
import datetime
import urllib
import urlparse
import hashlib
import hmac
import base64
import json

import pytz
import requests
import requests.auth


class ScalrApiSession(requests.Session):
    def __init__(self, api_url, key_id, key_secret, *args, **kwargs):
        super(ScalrApiSession, self).__init__(*args, **kwargs)
        self.api_url = api_url
        self.key_id = key_id
        self.key_secret = key_secret
        self.logger = logging.getLogger("api[{0}]".format(self.api_url))

    def prepare_request(self, request):
        if not request.url.startswith(self.api_url):
            request.url = "".join([self.api_url, request.url])
        request = super(ScalrApiSession, self).prepare_request(request)

        now = datetime.datetime.now(tz=pytz.timezone('US/Eastern'))
        date_header = now.isoformat()

        url = urlparse.urlparse(request.url)

        # TODO - Spec isn't clear on whether the sorting should happen prior or after encoding
        if url.query:
            pairs = urlparse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True)
            pairs = [map(urllib.quote, pair) for pair in pairs]
            pairs.sort(key=lambda pair: pair[0])
            canon_qs = "&".join("=".join(pair) for pair in pairs)
        else:
            canon_qs = ""

        # Authorize
        sts = "\n".join([
            request.method,
            date_header,
            url.path,
            canon_qs,
            request.body if request.body is not None else ""
        ])

        sig = " ".join([
            "V1-HMAC-SHA256",
            base64.b64encode(hmac.new(str(self.key_secret), sts, hashlib.sha256).digest())
        ])

        request.headers.update({
            "X-Scalr-Key-Id": self.key_id,
            "X-Scalr-Signature": sig,
            "X-Scalr-Date": date_header,
            "X-Scalr-Debug": "1"
        })

        self.logger.debug("URL: %s", request.url)
        self.logger.debug("StringToSign: %s", repr(sts))
        self.logger.debug("Signature: %s", repr(sig))

        return request

    def request(self, *args, **kwargs):
        res = super(ScalrApiSession, self).request(*args, **kwargs)
        res.raise_for_status()
        self.logger.debug(res.text)
        return res

    def list(self, path):
        data = []
        while path is not None:
            body = self.get(path).json()
            data.extend(body["data"])
            path = body["pagination"]["next"]
        return data


def main(credentials_file):
    with open(credentials_file) as f:
        creds = json.load(f)
        api_url, api_key_id, api_key_secret, env_id, basic_auth_username, basic_auth_password = \
                [creds[k] for k in ["api_url", "api_key_id", "api_key_secret", "env_id", "basic_auth_username", "basic_auth_password"]]

    s = ScalrApiSession(api_url, api_key_id, api_key_secret)
    s.auth = requests.auth.HTTPBasicAuth(basic_auth_username, basic_auth_password)

    for path in ["/api/user/v1/os/?family=ubuntu", "/api/user/v1/{0}/roles/".format(env_id), "/api/user/v1/{0}/images/".format(env_id)]:
        print "\n\n\n"
        try:
            print "Accessing list endpoint: {0}".format(path)
            l = s.list(path)

            print "Found {0} records like:".format(len(l))
            print json.dumps(l[0], indent=4)
            print

            # Remove the parameters if they exist, then compute the detail URL
            detail_url = "".join([getattr(urlparse.urlparse(path), k) for k in ["scheme", "netloc", "path"]])
            detail_url += str(l[-1]["id"])
            print "Accessing detail endpoint: {0}".format(detail_url)

            body = s.get(detail_url).json()
            print json.dumps(body, indent=4)
        except requests.exceptions.HTTPError as e:
            print "ERROR!", e.response.status_code, e.response.text
            continue

    # Register an Image (not implemented yet)
    # s.post("/api/user/v1/{0}/images".format(env_id), data={})


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.WARNING)

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("credentials", help="Path to credentials file")

    ns = parser.parse_args()
    main(ns.credentials)

