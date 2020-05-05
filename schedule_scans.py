import json
from functools import lru_cache

import toml


from nessus import (
    list_policies,
    list_policy_templates,
    create_scan,
    create_policy,
    policy_details,
    list_scans
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


def create_gds_scans(config):
    for scan in config.values():
        create_scan_config(scan)
        create_scan(create_scan_config(scan))


def find_new_rules(config, name):
    for new_scan in config.values():
        if new_scan["name"] == name:
            return new_scan
        else:
            return False


def get_names(config, new_scan):
    name_list = []
    for new_scan in config.values():
        name_list.append(new_scan)
    return name_list


def load_scan_config():
    with open("scan_config/scan.toml", "r") as f:
        return toml.load(f)


def compare_rrules(new_scan, scan_rrules):
    rrules = f"FREQ={new_scan['rrules.freq']};INTERVAL={new_scan['rrules.interval']};BYDAY={new_scan['rrules.byday']}"
    if scan_rrules == rrules:
        return True
    else:
        return False


def check_remaining_rules(scan, new_scan, config):
    rules = ["enabled", "starttime", "text_targets"]
    for rule in rules:
        print(scan)
        print(new_scan)
        print(f"Nessus: {scan['name']}: {scan[rule]}\nConfig: {new_scan['name']}: {new_scan[rule]}")
        if scan[rule] != new_scan[rule]:
            print(f"Nessus: {scan[rule]}\nConfig: {new_scan[rule]}")
            return False
        else:
            return True


def compare_targets(new_scan, id):
    describe_scan(id)
    # Check if they are the same here


def check_scan():
    scan_list = list_scans()
    config = load_scan_config()
    scans = scan_list["scans"]
    for scan in scans:
        new_scan = find_new_rules(config, scan["name"])
        if scan["name"] in get_names(config, new_scan):
            print(f"Scan {scan['name']} already exists checking for changed config.")
            if find_new_rules(config, scan["name"]):
                scan_rrules = scan["rrules"]
                if compare_rrules(new_scan, scan_rrules):
                    print(f"Scan {scan['name']} already exists with rrules given, skipping...")
                    pass
                elif compare_targets(new_scan, scan["id"]):
                    print(f"Scan {scan['name']} already exists with targets given, skipping...")
                    pass
                elif check_remaining_rules(scan, new_scan, config):
                    print(f"Scan {scan['name']} already exists with config given, skipping...")
                    pass
                else:
                    update_gds_scans(config)
        else:
            print("New scan config found, creating...")
            #Logic not working, still creating every time.
            create_gds_scans(config)


def main():
    print("Scheduling scans...")
    # config = load_scan_config()
    # create_gds_scans(config)
    check_scan()


if __name__ == "__main__":
    main()
