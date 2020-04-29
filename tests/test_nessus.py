import inspect
import logging
import os
import sys
from pprint import pprint as p
from unittest.mock import call
import hashlib

import pytest
import requests
import vcr

currentdir = os.path.dirname(__file__)
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

import nessus as n

## Uncomment to DEBUG VCR
#
# logging.basicConfig()  # you need to initialize logging, otherwise you will not see anything from vcrpy
# vcr_log = logging.getLogger("vcr")
# vcr_log.setLevel(logging.DEBUG)

my_vcr = vcr.VCR(
    record_mode="none",
    match_on=["uri", "method", "body"],
    cassette_library_dir="tests/fixtures/cassettes",
    path_transformer=vcr.VCR.ensure_suffix(".yaml"),
)


def test_process_csv(mocker):
    """The process csv function should forward each csv row
    separately. Rows may contain newline(\n) characters and there
    should be handled appropriately.

    """

    csv = """1,1,1,"1
1"
2,2,2,"2
2"
"""
    mocker.patch("nessus.send_to_cloudwatch")
    n.process_csv(csv)

    expected = [call(["1", "1", "1", "1\n1"]), call(["2", "2", "2", "2\n2"])]

    assert n.send_to_cloudwatch.call_args_list == expected


@my_vcr.use_cassette()
def test_get_param_from_ssm():
    param = n.get_param_from_ssm("access_key")
    assert param == "fakeparam"


@my_vcr.use_cassette()
def test_create_custom_headers():
    result = n.create_custom_headers()
    expected = {"X-ApiKeys": "accessKey=ACCESS_KEY; secretKey=SECRET_KEY"}
    assert result == expected


@pytest.fixture
def nessus_headers():
    return {"X-ApiKeys": "accessKey=FOO; secretKey=BAR"}


@pytest.fixture
def nessus_host():
    return "https://localhost:8834"


@my_vcr.use_cassette()
def test_prepare_export(nessus_host, nessus_headers):
    result = n.prepare_export(nessus_headers, nessus_host, id=5)
    expected = {"token": "TOKEN", "file": 1111111}
    assert result == expected


@my_vcr.use_cassette(record_mode="once")
def test_download_report(nessus_host):
    result = n.download_report({"token": "TOKEN"}, nessus_host)
    checksum = hashlib.sha256(result.encode()).hexdigest()
    expected = "eea68287cb85c63c0a68de31b8e73d4d7718b2c991747523c5c8ef2d9b5936ea"
    assert checksum == expected
