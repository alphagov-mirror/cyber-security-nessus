# import inspect
# import logging
import os
import sys
import json
import re
import hashlib

import vcr

currentdir = os.path.dirname(__file__)
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

import nessus as n


@vcr.use_cassette
def test_get_param_from_ssm():
    param = n.get_param_from_ssm("access_key")
    assert param


@vcr.use_cassette
def test_api_credentials():
    result = n.api_credentials()
    assert "X-ApiKeys" in result
    assert "accessKey=" in result["X-ApiKeys"]
    assert "secretKey=" in result["X-ApiKeys"]


@vcr.use_cassette
def test_base_url():
    result = n.base_url()
    assert "https://" in result
    assert "8834" in result


# @vcr.use_cassette
# def test_prepare_export(scan_id):
#     result = n.prepare_export(id=scan_id)
#     assert "token" in result
#     assert "file" in result


@vcr.use_cassette
def test_get():
    result = n.get("/server/status")
    expected = {"code": 200, "progress": None, "status": "ready"}
    assert result == expected


@vcr.use_cassette
def test_get_token():
    result = n.get_token()
    assert "X-Cookie" in result
    assert "token=" in result["X-Cookie"]


@vcr.use_cassette
def test_get_x_api_token():
    result = n.get_x_api_token()
    assert re.match(
        r"([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})", result
    )


@vcr.use_cassette
def test_manager_credentials():
    result = n.manager_credentials()
    assert re.match(
        r"([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})",
        result["X-API-Token"],
    )
    assert re.match(r"token=.*", result["X-Cookie"])


@vcr.use_cassette
def test_list_policies():
    result = n.list_policies()
    assert "policies" in result


@vcr.use_cassette
def test_list_scans():
    result = n.list_scans()
    assert "folders" in result
    assert "scans" in result


@vcr.use_cassette
def test_policy_details(policy):
    result = n.policy_details(policy["id"])
    assert "settings" in result


@vcr.use_cassette
def test_create_scan(policy):
    scan = {
        "settings": {
            "enabled": 1,
            "name": "NAME",
            "policy_id": policy["id"],
            "rrules": "FREQ=WEEKLY;INTERVAL=000;BYDAY=MO",
            "starttime": "20200428T133000",
            "text_targets": "WWW.TEST.COM",
            "timezone": "Europe/London",
        },
        "uuid": "939a2145-95e3-0c3f-f1cc-761db860e4eed37b6eee77f9e101",
    }
    expected = {
        "enabled": 1,
        "name": "NAME",
        "policy_id": policy["id"],
        "rrules": "FREQ=WEEKLY;INTERVAL=000;BYDAY=MO",
        "starttime": "20200428T133000",
        "custom_targets": "WWW.TEST.COM",
        "timezone": "Europe/London",
    }
    new_scan = n.create_scan(scan)
    for setting, value in expected.items():
        assert new_scan["scan"][setting] == value


# @vcr.use_cassette
# def test_update_scan(clean_cache, scan_id, policy_id):
#     scan = {
#         "settings": {
#             "agent_group_id": [],
#             "enabled": 1,
#             "name": "NAME1",
#             "policy_id": policy_id,
#             "rrules": "FREQ=WEEKLY;INTERVAL=000;BYDAY=MO",
#             "starttime": "20200428T111000",
#             "text_targets": "WWW.TESTOTHER.COM",
#             "timezone": "Europe/London",
#         },
#         "uuid": "939a2145-95e3-0c3f-f1cc-761db860e4eed37b6eee77f9e101",
#     }

#     updated_scan = n.update_scan(scan, scan_id)

#     expected = {
#         "enabled": 1,
#         "name": "NAME1",
#         "policy_id": policy_id,
#         "rrules": "FREQ=WEEKLY;INTERVAL=000;BYDAY=MO",
#         "starttime": "20200428T111000",
#         "custom_targets": "WWW.TESTOTHER.COM",
#         "timezone": "Europe/London",
#     }
#     for setting, value in expected.items():
#         assert updated_scan[setting] == value


# @vcr.use_cassette
# def test_download_report():
#     result = n.download_report('token')
#     checksum = hashlib.sha256(result.encode()).hexdigest()
#     expected = "11ee62d6261141e99e0a9ccae253e6d2008dff26e172cb73da0646b53ae941eb"
#     assert checksum == expected


@vcr.use_cassette
def test_list_policy_templates():
    result = n.list_policy_templates()
    assert "templates" in result


# @vcr.use_cassette
# def test_describe_scan():
#     result = n.describe_scan(1308)
#     assert "history" in result
#     assert "info" in result
