import json
from functools import lru_cache

import toml


import nessus as ness_func


@lru_cache(maxsize=1)
def find_scan_policy(name="standard_scan"):
    """Find policy ID from policy Name"""
    for policy in ness_func.list_policies()["policies"]:
        if policy["name"] == name:
            return policy


@lru_cache(maxsize=1)
def create_scan_policy(policy_file="scan_config/standard_scan_template.json"):
    with open(policy_file, "r") as f:
        policy = json.load(f)

    policy["uuid"] = advanced_dynamic_policy_template_uuid()

    return ness_func.create_policy(policy)


def gds_scan_policy_id():
    """Find or Create the GDS scan policy and return it's ID"""
    return find_scan_policy()["id"] or create_scan_policy()["policy_id"]


@lru_cache(maxsize=1)
def advanced_dynamic_policy_template_uuid():
    """Find the UUID of the builtin `Advanced Dynamic Scan` template"""
    return next(
        template["uuid"]
        for template in ness_func.list_policy_templates()["templates"]
        if template["title"] == "Advanced Dynamic Scan"
    )


def config_rrules(scan):
    return f"FREQ={scan['rrules.freq']};INTERVAL={scan['rrules.interval']};BYDAY={scan['rrules.byday']}"


def create_scan_config(scan, policy_id):
    return {
        "uuid": advanced_dynamic_policy_template_uuid(),
        "settings": {
            "name": scan["name"],
            "enabled": scan["enabled"],
            "rrules": config_rrules(scan),
            "policy_id": policy_id,
            "starttime": scan["starttime"],
            "timezone": "Europe/London",
            "text_targets": scan["text_targets"],
            "agent_group_id": [],
        },
    }


def create_all_scans(config, policy_id):
    return [
        ness_func.create_scan(create_scan_config(scan, policy_id))
        for scan in config.values()
    ]


def create_scan(toml_scan, policy_id):
    return ness_func.create_scan(create_scan_config(toml_scan, policy_id))


def get_config_by_name(config, name):
    for toml_scan in config.values():
        if toml_scan["name"] == name:
            return toml_scan


def get_config_names(config):
    return [toml_scan["name"] for toml_scan in config.values()]


def get_scans_from_toml(config):
    return list(config.values())


def load_scan_config():
    with open("scan_config/scan.toml", "r") as f:
        return toml.load(f)


def compare_rrules(scan, nessus_scan_rrules):
    return nessus_scan_rrules == config_rrules(scan)


def check_remaining_rules(nessus_scan, toml_scan):
    """Check all remaining rules match. If all match return True, else return early with False"""
    keys = ["enabled", "starttime", "text_targets"]
    return all(nessus_scan[key] == toml_scan[key] for key in keys)


def compare_targets(toml_scan, id):
    scan = ness_func.describe_scan(id)
    try:
        scan_targets = scan["info"]["targets"].split(",")
        toml_targets = toml_scan["text_targets"].split(",")
    except KeyError:
        return False

    return all(item in scan_targets for item in toml_targets)


def update_gds_scans(toml_scan, id):
    scan = create_scan_config(toml_scan)
    ness_func.update_scan(scan, id)


def update_scans(config, nessus_scans):
    nessus_scan_names = [scan["name"] for scan in nessus_scans]
    toml_scans = get_scans_from_toml(config)
    for toml_scan in toml_scans:
        if toml_scan["name"] not in nessus_scan_names:
            print("New scan config found, creating...")
            create_scan(toml_scan, gds_scan_policy_id())
            continue

        print(f"Scan {toml_scan['name']} already exists checking for changed config.")
        nessus_scan = [
            scan for scan in nessus_scans if scan["name"] == toml_scan["name"]
        ][0]
        compare_scans = [
            compare_rrules(toml_scan, nessus_scan["rrules"]),
            compare_targets(toml_scan, nessus_scan["id"]),
            check_remaining_rules(nessus_scan, toml_scan),
        ]
        if all(compare_scans):
            print("Scan already exists, skipping...")
        else:
            id = nessus_scan["id"]
            update_gds_scans(toml_scan, id)


def check_scan():
    scan_list = ness_func.list_scans()

    config = load_scan_config()
    nessus_scans = scan_list["scans"]
    if not nessus_scans:
        create_all_scans(config, gds_scan_policy_id())
    else:
        update_scans(config, nessus_scans)


def main():
    print("Scheduling scans...")
    check_scan()


if __name__ == "__main__":
    main()
