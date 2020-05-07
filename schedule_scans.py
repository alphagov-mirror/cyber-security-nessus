import json
from functools import lru_cache

import toml


from nessus import (
    list_policies,
    list_policy_templates,
    create_scan,
    create_policy,
    policy_details,
    list_scans,
    describe_scan,
    update_scan,
)


@lru_cache(maxsize=1)
def set_policy():
    policies = list_policies()
    policy_id = None

    for policy in policies["policies"]:
        if policy["name"] == "standard_scan":
            policy_id = policy["id"]

    if not policy_id:
        print("No policies exist.")
        policy_id = create_gds_scan_policy()

    return policy_id


@lru_cache(maxsize=1)
def advanced_dynamic_policy_template_uuid():
    templates = list_policy_templates()
    return next(
        template
        for template in templates["templates"]
        if template["title"] == "Advanced Dynamic Scan"
    )["uuid"]


def create_gds_scan_policy():
    with open("scan_config/standard_scan_template.json", "r") as f:
        policy = json.load(f)
    policy["uuid"] = advanced_dynamic_policy_template_uuid()
    policy = create_policy(policy)
    return policy["policy_id"]


def create_scan_config(scan):
    return {
        "uuid": advanced_dynamic_policy_template_uuid(),
        "settings": {
            "name": scan["name"],
            "enabled": scan["enabled"],
            "rrules": f"FREQ={scan['rrules.freq']};INTERVAL={scan['rrules.interval']};BYDAY={scan['rrules.byday']}",
            "policy_id": set_policy(),
            "starttime": scan["starttime"],
            "timezone": "Europe/London",
            "text_targets": scan["text_targets"],
            "agent_group_id": [],
        },
    }


def create_all_gds_scans(config):
    for scan in config.values():
        create_scan(create_scan_config(scan))


def create_gds_scans(config, toml_scan):
    create_scan(create_scan_config(toml_scan))


def get_config_rules(config, name):
    for toml_scan in config.values():
        if toml_scan["name"] == name:
            return toml_scan
        else:
            return False


def get_names(config):
    toml_name_list = []
    for toml_scan in config.values():
        toml_name_list.append(toml_scan["name"])
    return toml_name_list


def get_scans_from_toml(config):
    toml_scans_list = []
    for toml_scan in config.values():
        toml_scans_list.append(toml_scan)
    return toml_scans_list


def load_scan_config():
    with open("scan_config/scan.toml", "r") as f:
        return toml.load(f)


def compare_rrules(toml_scan, nessus_scan_rrules):
    rrules = f"FREQ={toml_scan['rrules.freq']};INTERVAL={toml_scan['rrules.interval']};BYDAY={toml_scan['rrules.byday']}"
    if nessus_scan_rrules == rrules:
        return True
    else:
        return False


def check_remaining_rules(nessus_scan, toml_scan, config):
    rules = ["enabled", "starttime", "text_targets"]
    for rule in rules:
        if nessus_scan[rule] != toml_scan[rule]:
            return False
        else:
            return True


def compare_targets(toml_scan, id):
    scan = describe_scan(id)
    try:
        scan_targets = scan["info"]["targets"].split(",")
        toml_targets = toml_scan["text_targets"].split(",")
        return all(item in scan_targets for item in toml_targets)
    except KeyError:
        return False


def update_gds_scans(toml_scan, id):
    scan = create_scan_config(toml_scan)
    update_scan(scan, id)


def compare_scans(config, nessus_scans):
    nessus_scan_names = [scan["name"] for scan in nessus_scans]
    toml_scans = get_scans_from_toml(config)
    for toml_scan in toml_scans:
        if toml_scan["name"] not in nessus_scan_names:
            print("New scan config found, creating...")
            create_gds_scans(config, toml_scan)
            continue
        else:
            print(f"Scan {toml_scan['name']} already exists checking for changed config.")
            nessus_scan = [
                scan for scan in nessus_scans if scan["name"] == toml_scan["name"]
            ][0]
            compare_scans = [
                compare_rrules(toml_scan, nessus_scan["rrules"]),
                compare_targets(toml_scan, nessus_scan["id"]),
                check_remaining_rules(nessus_scan, toml_scan, config),
            ]
            if all(compare_scans):
                print("Scan already exists, skipping...")
            else:
                id = nessus_scan["id"]
                update_gds_scans(toml_scan, id)


def check_scan():
    if list_scans():
        scan_list = list_scans()
    else:
        scan_list = []

    config = load_scan_config()
    nessus_scans = scan_list["scans"]
    if not nessus_scans:
        create_all_gds_scans(config)
    else:
        compare_scans(config, nessus_scans)


def main():
    print("Scheduling scans...")
    check_scan()


if __name__ == "__main__":
    main()
