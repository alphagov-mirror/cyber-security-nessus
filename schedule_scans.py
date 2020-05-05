import json
from functools import lru_cache

import toml


from nessus import (
    list_policies,
    list_policy_templates,
    create_scan,
    create_policy,
    policy_details,
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


def load_scan_config():
    with open("scan_config/scan.toml", "r") as f:
        return toml.load(f)


def main():
    print("Scheduling scans...")
    config = load_scan_config()
    create_gds_scans(config)


if __name__ == "__main__":
    main()
