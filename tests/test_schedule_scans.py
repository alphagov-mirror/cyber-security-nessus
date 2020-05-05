import os
import sys

import pytest
import vcr

currentdir = os.path.dirname(__file__)
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

import schedule_scans as s


@vcr.use_cassette
def test_advanced_dynamic_policy_template_uuid(clean_cache):
    """Should return the `uuid` of the template with the name `Advanced Dynamic Scan`"""
    result = s.advanced_dynamic_policy_template_uuid()
    expected = "939a2145-95e3-0c3f-f1cc-761db860e4eed37b6eee77f9e101"
    assert result == expected


def test_load_scan_config():
    """Check we can load the config file"""
    result = s.load_scan_config()
    assert len(result) > 0


@pytest.fixture
def scan_template():
    """A dummy confid entry for a scan"""
    return {
        "name": "NAME",
        "enabled": "TRUE",
        "rrules.freq": "WEEKLY",
        "rrules.interval": "000",
        "rrules.byday": "MO",
        "starttime": "20200428T133000",
        "text_targets": "WWW.TEST.COM",
    }


def test_load_scan_config_objects(scan_template):
    """Check that all config objects have the required keys"""
    config = s.load_scan_config()

    for site in config.values():
        for key in scan_template.keys():
            assert key in site
            assert site[key]


@vcr.use_cassette
def test_create_scan_config(scan_template, clean_cache):
    """Created scans should have this format"""
    result = s.create_scan_config(scan_template)
    expected = {
        "settings": {
            "agent_group_id": [],
            "enabled": "TRUE",
            "name": "NAME",
            "policy_id": 10,
            "rrules": "FREQ=WEEKLY;INTERVAL=000;BYDAY=MO",
            "starttime": "20200428T133000",
            "text_targets": "WWW.TEST.COM",
            "timezone": "Europe/London",
        },
        "uuid": "939a2145-95e3-0c3f-f1cc-761db860e4eed37b6eee77f9e101",
    }
    assert result == expected


@vcr.use_cassette
def test_create_gds_scan_policy(clean_cache):
    """A newly created policy will have a high ID"""
    result = s.create_gds_scan_policy()
    expected = 80
    assert result == expected


@vcr.use_cassette
def test_set_policy(clean_cache):
    """An existing policy has a low ID"""
    result = s.set_policy()
    expected = 10
    assert result == expected


@vcr.use_cassette
def test_set_policy_no_policies(clean_cache):
    """A newly created policy will have a high ID"""
    result = s.set_policy()
    expected = 84
    assert result == expected
