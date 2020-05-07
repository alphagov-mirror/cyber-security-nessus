import sys
import os

import vcr

currentdir = os.path.dirname(__file__)
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

import generate_api_keys as gak


@vcr.use_cassette
def test_get_ec2_param():
    param = "PublicIpAddress"
    result = gak.get_ec2_param(param)
    expected = "127.0.0.1"
    assert result == expected


@vcr.use_cassette
def test_get_status_checks():
    result = gak.get_status_checks()
    expected = True
    assert result == expected


def test_put_keys():
    with vcr.use_cassette("tests/fixtures/cassettes/test_put_keys.yaml") as cass:
        gak.put_keys()
        response = '{"Tier":"Standard","Version":25}'
        assert cass.responses[9]["body"]["string"].decode("utf-8") == response
        assert cass.responses[9]["status"]["code"] == 200
        assert cass.responses[10]["body"]["string"].decode("utf-8") == response
        assert cass.responses[10]["status"]["code"] == 200


def test_put_param():
    with vcr.use_cassette("tests/fixtures/cassettes/test_put_param.yaml") as cass:
        access_key = "ACCESS_KEY"
        gak.put_param(access_key, type="access_key")
        response = '{"Tier":"Standard","Version":25}'
        assert cass.responses[0]["body"]["string"].decode("utf-8") == response
        assert cass.responses[0]["status"]["code"] == 200
