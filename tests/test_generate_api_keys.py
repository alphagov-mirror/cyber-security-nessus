import sys
import os

import vcr

currentdir = os.path.dirname(__file__)
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

import generate_api_keys as gen_keys
import re


@vcr.use_cassette
def test_get_ec2_param():
    param = "PublicIpAddress"
    result = gen_keys.get_ec2_param(param)
    assert re.match(r"([0-9]{1,3}\.){3}[0-9]{1,3}", result)


@vcr.use_cassette
def test_get_status_checks():
    result = gen_keys.get_status_checks()
    expected = True
    assert result == expected


# @vcr.use_cassette
# def test_put_keys(clean_cache):
#     result = gen_keys.put_keys()
#     response = '{"Tier":"Standard","Version":25}'
#     assert result == response



# def test_put_param():
#     with vcr.use_cassette("tests/fixtures/cassettes/test_put_param.yaml") as cass:
#         access_key = "ACCESS_KEY"
#         gen_keys.put_param(access_key, type="access_key")
#         response = '{"Tier":"Standard","Version":25}'
#         assert cass.responses[0]["body"]["string"].decode("utf-8") == response
#         assert cass.responses[0]["status"]["code"] == 200

# def test_put_param():
#     with vcr.use_cassette("tests/fixtures/cassettes/test_put_param.yaml") as cass:
#         access_key = "ACCESS_KEY"
#         gen_keys.put_param(access_key, type="access_key")
#         response = '{"Tier":"Standard","Version":25}'
#         assert cass.responses[0]["body"]["string"].decode("utf-8") == response
#         assert cass.responses[0]["status"]["code"] == 200

# @vcr.use_cassette
# def test_get_nessus_status():
#     result = gen_keys.get_nessus_status()
#     expected = {"code":200,"progress":None,"status":"ready"}
#     assert result == expected
