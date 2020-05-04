import base64
import gzip
import json
import os
import sys

import pytest
import vcr

currentdir = os.path.dirname(__file__)
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

import nessus as n


vcr.default_vcr = vcr.VCR(
    record_mode="once",
    match_on=["uri", "method", "body"],
    cassette_library_dir="tests/fixtures/cassettes",
    path_transformer=vcr.VCR.ensure_suffix(".yaml"),
)
vcr.use_cassette = vcr.default_vcr.use_cassette


@pytest.fixture
def clean_cache():
    """Clear the lru_caches"""
    n.get_param_from_ssm.cache_clear()
    n.username.cache_clear()
    n.password.cache_clear()
    n.api_credentials.cache_clear()
    n.get_x_api_token()


# Helper functions for working with the `!!binary` strings in VCR cassettes
def un_b64_gzip_json(data):
    """Take a b64ed gziped, json str and return a python object"""
    return json.loads(gzip.decompress(base64.decodebytes(data.encode())))


def enc_json_gzip_b64(data):
    """Take a python object then convert to JSON, GZIP, and base64 encode. Returns a str"""
    return base64.encodebytes(gzip.compress(json.dumps(data).encode())).decode()
