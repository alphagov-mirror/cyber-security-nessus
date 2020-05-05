import base64
import gzip
import json
from pprint import pprint as p
import os
import sys

import pytest
import logging
import requests
import vcr

from json import encoder

encoder.FLOAT_REPR = lambda o: format(o, ".8f")

currentdir = os.path.dirname(__file__)
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

import nessus as n
import schedule_scans as s

def scrub_body(response):
    """Helper to scub secrets from a vcr request body"""
    try:
        data = json.loads(response["body"]["string"])
        response["body"]["string"] = json.dumps(
            scrub_json(data), separators=(",", ":")
        ).encode()
        response["content-length"] = [str(len(respones["body"]["string"]))]
        return response
    except:
        return response


def scrub_json(data):
    """Helper to remove secret values from JSON"""
    parameters = [
        "/nessus/secret_key",
        "/nessus/access_key",
        "/nessus/username",
        "/nessus/password",
        "/nessus/public_base_url",
    ]
    if "Parameter" in data:
        data["Parameter"][
            "ARN"
        ] = "arn:aws:ssm:us-east-1:000000000000:parameter/nessus/access_key"
        data["Parameter"]["LastModifiedDate"] = 0
        for parameter in parameters:
            if data["Parameter"]["Name"] == parameter:
                data["Parameter"]["Value"] = parameter

    secrets = [
        "token",
        "username",
        "password",
    ]

    for secret in secrets:
        if secret in data:
            data[secret] = secret

    return data

# VCR debugging
# logging.basicConfig()  # you need to initialize logging, otherwise you will not see anything from vcrpy
# vcr_log = logging.getLogger("vcr")
# vcr_log.setLevel(logging.DEBUG)

# Standardise vcr config
vcr.default_vcr = vcr.VCR(
    record_mode="append",
    match_on=["uri", "method", "body"],
    cassette_library_dir="tests/fixtures/cassettes",
    path_transformer=vcr.VCR.ensure_suffix(".yaml"),
    filter_headers=[
        "Authorization",
        "X-Amz-Security-Token",
        "X-Amz-Date",
        "X-Amz-Target",
        "X-ApiKeys",
    ],
    decode_compressed_response=True,
    before_record_response=scrub_body,
    before_record_request=scrub_body,
)
vcr.use_cassette = vcr.default_vcr.use_cassette


@pytest.fixture
def clean_cache():
    """Clear the lru_caches"""
    n.get_param_from_ssm.cache_clear()
    n.username.cache_clear()
    n.password.cache_clear()
    n.api_credentials.cache_clear()
    n.get_x_api_token.cache_clear()
    s.set_policy.cache_clear()



# Helper functions for working with the `!!binary` strings in VCR cassettes
def un_b64_gzip_json(data):
    """Take a b64ed gziped, json str and return a python object"""
    return json.loads(gzip.decompress(base64.decodebytes(data.encode())))


def enc_json_gzip_b64(data):
    """Take a python object then convert to JSON, GZIP, and base64 encode. Returns a str"""
    return base64.encodebytes(gzip.compress(json.dumps(data).encode())).decode()
