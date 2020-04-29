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
import process_scans as ps

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
    mocker.patch("process_scans.process_csv")
    ps.process_csv(csv)

    expected = [call('1,1,1,"1\n1"\n2,2,2,"2\n2"\n')]

    assert ps.process_csv.call_args_list == expected


@my_vcr.use_cassette()
def test_get_param_from_ssm():
    param = n.get_param_from_ssm("access_key")
    assert param == "ACCESS_KEY"


@my_vcr.use_cassette()
def test_api_credentials():
    result = n.api_credentials()
    expected = {"X-ApiKeys": "accessKey=ACCESS_KEY; secretKey=SECRET_KEY"}
    assert result == expected


@my_vcr.use_cassette()
def test_prepare_export():
    result = n.prepare_export(id=5)
    expected = {"token": "TOKEN", "file": 1111111}
    assert result == expected


@my_vcr.use_cassette(record_mode="once")
def test_download_report():
    result = n.download_report({"token": "TOKEN"})
    checksum = hashlib.sha256(result.encode()).hexdigest()
    expected = "f187c548fa8e20b44530def0e5cd7f3a35c739cb09a3868ae70d82bd65d23560"
    assert checksum == expected
