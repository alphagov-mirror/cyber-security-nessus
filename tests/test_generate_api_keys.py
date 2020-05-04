import sys
import os

import vcr

currentdir = os.path.dirname(__file__)
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

import generate_api_keys as gak


my_vcr = vcr.VCR(
    record_mode="none",
    match_on=["uri", "method", "body"],
    cassette_library_dir="tests/fixtures/cassettes",
    path_transformer=vcr.VCR.ensure_suffix(".yaml"),
)


@my_vcr.use_cassette()
def test_get_ec2_param():
    param = "PublicIpAddress"
    result = gak.get_ec2_param(param)
    expected = "127.0.0.1"
    assert result == expected


@my_vcr.use_cassette()
def test_get_status_checks():
    result = gak.get_status_checks()
    expected = True
    assert result == expected
