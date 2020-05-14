import os
import sys

import pytest
import vcr

currentdir = os.path.dirname(__file__)
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

import schedule_scans as schedule

# from test_nessus import policy


@vcr.use_cassette
def test_find_scan_policy(policy):
    found_policy = schedule.find_scan_policy(policy["name"])
    assert "id" in found_policy
    assert found_policy["name"] == policy["name"]


@vcr.use_cassette
def test_create_scan_policy():
    policy = schedule.create_scan_policy("tests/fixtures/test_scan_template.json")
    assert "policy_id" in policy


@vcr.use_cassette
def test_gds_scan_policy_id():
    policy_id = schedule.gds_scan_policy_id()
    assert policy_id > 0


@vcr.use_cassette
def test_advanced_dynamic_policy_template_uuid(clean_cache):
    """Should return the `uuid` of the template with the name `Advanced Dynamic Scan`"""
    result = schedule.advanced_dynamic_policy_template_uuid()
    # This seems static across installs
    expected = "939a2145-95e3-0c3f-f1cc-761db860e4eed37b6eee77f9e101"
    assert result == expected


def test_load_scan_config():
    """Check we can load the config file"""
    result = schedule.load_scan_config()
    assert len(result) > 0


@pytest.fixture
def scan_template():
    """A dummy confid entry for a scan"""
    return {
        "name": "NAME",
        "enabled": 1,
        "rrules.freq": "WEEKLY",
        "rrules.interval": "000",
        "rrules.byday": "MO",
        "starttime": "20200428T133000",
        "text_targets": "WWW.TEST.COM",
    }


def test_load_scan_config_objects(scan_template):
    """Check that all config objects have the required keys"""
    config = schedule.load_scan_config()

    for site in config.values():
        for key in scan_template.keys():
            assert key in site
            assert site[key]


@vcr.use_cassette
def test_create_scan_config(scan_template, clean_cache, policy):
    """Created scans should have this format"""
    result = schedule.create_scan_config(scan_template, policy["id"])
    expected = {
        "settings": {
            "agent_group_id": [],
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
    assert result == expected


@pytest.fixture
def config_scan(config):
    return list(config.values())[0]


@pytest.fixture
def config():
    return {
        "test_scan_1": {
            "name": "weekly scan",
            "enabled": 1,
            "rrules.freq": "WEEKLY",
            "rrules.interval": "3",
            "rrules.byday": "MO",
            "starttime": "20200428T133000",
            "text_targets": "localhost",
        },
        "test_scan_2": {
            "name": "daily scan",
            "enabled": 1,
            "rrules.freq": "DAILY",
            "rrules.interval": "3",
            "rrules.byday": "TU",
            "starttime": "20200428T113000",
            "text_targets": "localhost",
        },
    }


def test_config_rrules(config):
    config = list(config.values())[0]
    rrules = f"FREQ={config['rrules.freq']};INTERVAL={config['rrules.interval']};BYDAY={config['rrules.byday']}"
    assert schedule.config_rrules(config) == rrules


def test_get_config_by_name(config):
    config = schedule.get_config_by_name(config, "daily scan")
    assert config["name"] == "daily scan"


def test_get_config_names(config):
    names = schedule.get_config_names(config)
    assert names == [
        "weekly scan",
        "daily scan",
    ]


def test_get_scans_from_toml(config):
    assert schedule.get_scans_from_toml(config) == list(config.values())


@vcr.use_cassette
def test_create_all_scans(config, policy):
    scans = schedule.create_all_scans(config, policy["id"])
    assert len(scans) == 2


@vcr.use_cassette
def test_create_scheduled_scan(config_scan, policy):
    scan = schedule.create_scan(config_scan, policy["id"])
    assert scan["scan"]["name"] == config_scan["name"]


def test_compare_rrules(config_scan):
    assert schedule.compare_rrules(config_scan, schedule.config_rrules(config_scan))
    assert not schedule.compare_rrules(
        config_scan, schedule.config_rrules(config_scan) + "foo"
    )


def test_check_remaining_rules(config):
    config = list(config.values())
    assert not schedule.check_remaining_rules(config[0], config[1])
    assert schedule.check_remaining_rules(config[0], config[0])


# @vcr.use_cassette
# @vcr.use_cassette
# def test_create_gds_scan_policy(clean_cache, policy_id):
#     """A newly created policy will have a high ID"""
#     result = schedule.create_gds_scan_policy()
#     assert result == policy_id


# @vcr.use_cassette
# def test_set_policy(clean_cache):
#     """An existing policy has a low ID"""
#     result = schedule.set_policy()
#     expected = 10
#     assert result == expected


# @vcr.use_cassette
# def test_set_policy_no_policies(clean_cache):
#     """A newly created policy will have a high ID"""
#     result = schedule.set_policy()
#     expected = 84
#     assert result == expected


# @vcr.use_cassette
# def test_compare_targets(clean_cache, scan_id):
#     """ are compare targets function works as intended"""
#     toml_scan = {"name": "The nightmare before nessus", "text_targets": "www.gov.uk"}
#     assert schedule.compare_targets(toml_scan, scan_id)
