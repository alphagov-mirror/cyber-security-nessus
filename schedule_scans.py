import json
from pprint import pprint as p
from functools import lru_cache

import requests
import toml
import re

from nessus import get_param_from_ssm, create_custom_headers, get, post
from generate_api_keys import get_token


@lru_cache(maxsize=1)
def base_url():
    return "public_base_url"


@lru_cache(maxsize=1)
def custom_headers():
    return create_custom_headers()


def list_policies():
    return get("/policies", base_url())


def list_policy_templates():
    return get("/editor/policy/templates", base_url())


def policy_details(id):
    return get(f"/policies/{id}", base_url())


def schedule_scans(custom_headers, base_url, config_file):
    return post("/scans/", base_url(), {"format": "csv"})


def create_policy(policy):
    return post("/policies", base_url(), policy)


def create_scan(settings):
    headers = {"X-API-Token": get_x_api_token()}
    headers.update(get_token())
    p(headers)
    return post("/scans", base_url(), settings, headers)


def get_x_api_token():
    r = requests.get(get_param_from_ssm(base_url()) + "/nessus6.js", verify=False)
    # r'"getApiToken",value:function(){return"C37F7A9A-0DE8-4961-8DFA-03D1F03684E3"}}'
    m = re.search(
        r"([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})", r.text
    )
    return m.group(0)


#####


@lru_cache(maxsize=1)
def set_policy():
    policies = list_policies()
    try:
        for policy in policies["policies"]:
            if policy["name"] == "standard_scan":
                return policy["id"]
    except KeyError:
        print("No policies exist.")
        create_gds_scan_policy()


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
    r = create_policy(policy)
    return policy["id"]


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
        s = create_scan_config(scan)
        p(s)
        r = create_scan(create_scan_config(scan))


def dump_policy(id):
    with open("out.json", "w") as f:
        json.dump(policy_details(id), f, indent=4)


def load_scan_config():
    with open("scan_config/scan.toml", "r") as f:
        return toml.load(f)


def main():
    # set_policy(base_url, custom_headers)
    # p(policy_details(base_url, custom_headers, 7))
    # p(create_policy(base_url, custom_headers))
    # p(list_policy_templates())
    # p(advanced_dynamic_policy_template_uuid())

    config = load_scan_config()
    create_gds_scans(config)


if __name__ == "__main__":
    main()
