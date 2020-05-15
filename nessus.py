import re
from functools import lru_cache

import boto3
import requests
import validators
import os


def verify_ssl():
    is_domain = validators.domain(base_url()[8:])

    if is_domain:
        return True
    else:
        return False


def get(path, text=False):
    """Make a GET request to Nessus"""
    if text:
        return requests.get(
            base_url() + path, headers=api_credentials(), verify=verify_ssl(),
        ).text
    else:
        return requests.get(
            base_url() + path, headers=api_credentials(), verify=verify_ssl(),
        ).json()


def post(path, payload, headers=None):
    return requests.post(
        base_url() + path,
        headers=headers if headers else api_credentials(),
        json=payload,
        verify=verify_ssl(),
    ).json()


def put(path, payload, headers=None):
    return requests.put(
        base_url() + path,
        headers=headers if headers else api_credentials(),
        json=payload,
        verify=verify_ssl(),
    ).json()


@lru_cache(maxsize=10)
def get_param_from_ssm(param):
    ssm_client = boto3.client("ssm")
    response = ssm_client.get_parameter(Name=f"/nessus/{param}", WithDecryption=True)
    return response["Parameter"]["Value"]


@lru_cache(maxsize=1)
def username():
    return get_param_from_ssm("username")


@lru_cache(maxsize=1)
def password():
    return get_param_from_ssm("password")


@lru_cache(maxsize=1)
def get_token():
    response = post("/session", {"username": username(), "password": password()})
    return {"X-Cookie": f"token={response['token']}"}


@lru_cache(maxsize=1)
def get_x_api_token():
    r = get("/nessus6.js", text=True)
    m = re.search(r"([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})", r)
    return m.group(0)


@lru_cache(maxsize=1)
def api_credentials():
    access_key = get_param_from_ssm("access_key")
    secret_key = get_param_from_ssm("secret_key")
    return {"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}"}


@lru_cache(maxsize=1)
def manager_credentials():
    headers = {"X-API-Token": get_x_api_token()}
    headers.update(get_token())
    return headers


@lru_cache(maxsize=None)
def ec2_client():
    return boto3.client("ec2")


def get_ec2_param(param):
    return ec2_client().describe_instances(
        Filters=[
            {"Name": "tag:Name", "Values": ["Nessus Scanning Instance"]},
            {"Name": "instance-state-name", "Values": ["running"]},
        ]
    )["Reservations"][0]["Instances"][0][f"{param}"]



@lru_cache(maxsize=1)
def base_url():
    # Hack: See if we're a Lambda and use a different Nessus endpoint
    # to work around Lambda > ALB security groups.
    if os.getenv('AWS_EXECUTION_ENV'):
        return f"https://{get_ec2_param('PrivateIpAddress')}:8834"
    return get_param_from_ssm("public_base_url")


def list_policies():
    return get("/policies")


def create_policy(policy):
    return post("/policies", policy)


def policy_details(policy_id):
    return get(f"/policies/{policy_id}")


def list_scans():
    return get("/scans")


def create_scan(scan):
    return post("/scans", scan, manager_credentials())


def update_scan(scan, scan_id):
    return put(f"/scans/{scan_id}", scan, manager_credentials())


def describe_scan(scan_id):
    return get(f"/scans/{scan_id}")


def prepare_export(scan_id):
    return post(f"/scans/{scan_id}/export", {"format": "csv"})


def list_policy_templates():
    return get("/editor/policy/templates")


def download_report(token):
    return get(f"/tokens/{token}/download", text=True)
