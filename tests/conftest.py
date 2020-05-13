import base64
import gzip
import json

import os
import sys
import re

import pytest
import logging
import requests
import vcr
from urllib.parse import urlparse, urlunparse

from json import encoder

encoder.FLOAT_REPR = lambda o: format(o, ".8f")

currentdir = os.path.dirname(__file__)
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

import nessus as n
import schedule_scans as s

import traceback


# TODO: CLEAN ME
def scrub_response(response):
    """Helper to scub secrets from a vcr request body"""
    try:
        data = json.loads(response["body"]["string"])
        response["body"]["string"] = json.dumps(
            scrub_json(data), separators=(",", ":")
        ).encode()
    except Exception as e:
        pass

    body = response["body"]["string"].decode()

    nessus6 = re.search(
        r"""([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})""", body
    )

    if nessus6:
        response["body"]["string"] = b"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
    else:
        ip = re.sub(r"([0-9]{1,3}\.){3}[0-9]{1,3}", "1.2.3.4", body)
        response["body"]["string"] = ip.encode()

    cl = ["Content-Length", "content-length"]
    for i in cl:
        if i in response["headers"]:
            response["headers"][i] = [str(len(response["body"]["string"]))]

    return response


# TODO: CLEAN ME
def scrub_request(request):
    """Helper to scub secrets from a vcr request body"""

    try:
        data = json.loads(request.body)
    except Exception as e:
        data = None

    if data:
        request.body = json.dumps(scrub_json(data), separators=(",", ":")).encode()

    url = urlparse(request.uri)

    if url.port == 8834:
        url = url._replace(netloc="localhost:8834")
        request.uri = urlunparse(url)

    return request


def scrub_json(data):
    """Helper to remove secret values from JSON"""
    parameters = [
        ("/nessus/secret_key",),
        ("/nessus/access_key",),
        ("/nessus/username",),
        ("/nessus/password",),
        ("/nessus/public_base_url", "https://localhost:8834"),
    ]
    if "Parameter" in data:
        data["Parameter"][
            "ARN"
        ] = "arn:aws:ssm:us-east-1:000000000000:parameter/nessus/access_key"
        data["Parameter"]["LastModifiedDate"] = 0

        for parameter in parameters:
            if data["Parameter"]["Name"] == parameter[0]:
                data["Parameter"]["Value"] = (
                    parameter[1] if len(parameter) > 1 else parameter[0]
                )

    secrets = [
        ("token", "token"),
        ("username", "/nessus/username"),
        ("password", "/nessus/password"),
    ]

    for secret in secrets:
        if secret[0] in data:
            data[secret[0]] = secret[1]

    return data


# VCR debugging
# logging.basicConfig()  # you need to initialize logging, otherwise you will not see anything from vcrpy
# vcr_log = logging.getLogger("vcr")
# vcr_log.setLevel(logging.DEBUG)

# Standardise vcr config
vcr.default_vcr = vcr.VCR(
    record_mode="once",
    match_on=["uri", "method", "body"],
    cassette_library_dir="tests/fixtures/cassettes",
    path_transformer=vcr.VCR.ensure_suffix(".yaml"),
    filter_headers=[
        "Authorization",
        "X-Amz-Security-Token",
        "X-Amz-Date",
        "X-Amz-Target",
        "X-ApiKeys",
        "X-API-Token",
        "X-Cookie",
    ],
    decode_compressed_response=True,
    before_record_response=scrub_response,
    before_record_request=scrub_request,
)
vcr.use_cassette = vcr.default_vcr.use_cassette


@pytest.fixture(autouse=True)
def clean_cache():
    """Clear the lru_caches"""
    n.api_credentials.cache_clear()
    n.get_param_from_ssm.cache_clear()
    n.get_token.cache_clear()
    n.get_x_api_token.cache_clear()
    n.manager_credentials.cache_clear()
    n.password.cache_clear()
    n.username.cache_clear()
    s.find_scan_policy.cache_clear()
    s.create_scan_policy.cache_clear()


# Helper functions for working with the `!!binary` strings in VCR cassettes
def un_b64_gzip_json(data):
    """Take a b64ed gziped, json str and return a python object"""
    return json.loads(gzip.decompress(base64.decodebytes(data.encode())))


def enc_json_gzip_b64(data):
    """Take a python object then convert to JSON, GZIP, and base64 encode. Returns a str"""
    return base64.encodebytes(gzip.compress(json.dumps(data).encode())).decode()


@pytest.fixture
def scan_id():
    return 1301


@pytest.fixture
def policy():
    """ID of testing policy
    The data formats returned by `find` and `create` are different.
    """

    policy = s.find_scan_policy("testing_scan")
    if policy:
        return policy

    s.create_scan_policy("tests/fixtures/test_scan_template.json")

    return s.find_scan_policy("testing_scan")
