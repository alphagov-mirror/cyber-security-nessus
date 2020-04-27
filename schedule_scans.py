import json
from pprint import pprint as p
from functools import lru_cache
import boto3
import requests

from nessus import get_param_from_ssm, create_custom_headers


@lru_cache(maxsize=1)
def base_url():
    return get_param_from_ssm("public_base_url")


@lru_cache(maxsize=1)
def custom_headers():
    return create_custom_headers()


def get(url):
    return requests.get(base_url() + url, headers=custom_headers(), verify=False).json()


def list_policies():
    return get("/policies")


def list_policy_templates():
    return get("/editor/policy/templates")


def policy_details(id):
    return get(f"/policies/{id}")


def post(url, payload):
    return requests.post(
        base_url() + url, headers=custom_headers(), json=payload, verify=False
    ).json()


def schedule_scans(custom_headers, base_url, config_file):
    return post("/scans/", {"format": "csv"})


def create_policy(policy):
    return post("/policies", policy)


#####


def set_policy(base_url, custom_headers):
    policies = list_policies(base_url, custom_headers)
    print(policies)
    try:
        for policy in policies["policies"]:
            if policy["name"] == "standard_scan":
                template_id = policy["template_uuid"]
                print(template_id)
    except KeyError:
        print("No policies exist.")
        create_policy(base_url, custom_headers)


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
    p(r)


def dump_policy(id):
    with open("out.json", "w") as f:
        json.dump(policy_details(id), f, indent=4)


def main():
    # set_policy(base_url, custom_headers)
    # p(policy_details(base_url, custom_headers, 7))
    # p(create_policy(base_url, custom_headers))
    # p(list_policy_templates())
    # p(advanced_dynamic_policy_template_uuid())

    create_gds_scan_policy()

    # new_scans = schedule_scans(custom_headers, base_url, config_file)


if __name__ == "__main__":
    main()
