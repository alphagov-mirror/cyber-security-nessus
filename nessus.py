import re
from functools import lru_cache

import boto3
import requests


def get(path, text=False):
    if text:
        return requests.get(
            get_param_from_ssm(base_url()) + path,
            headers=api_credentials(),
            verify=False,
        )
    else:
        return requests.get(
            get_param_from_ssm(base_url()) + path,
            headers=api_credentials(),
            verify=False,
        ).json()


def post(path, payload, headers=None):
    return requests.post(
        get_param_from_ssm(base_url()) + path,
        headers=headers if headers else api_credentials(),
        json=payload,
        verify=False,
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
    m = re.search(
        r"([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})", r.text
    )
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


def base_url():
    return "public_base_url"


def list_policies():
    return get("/policies")


def create_policy(policy):
    return post("/policies", policy)


def policy_details(id):
    return get(f"/policies/{id}")


def list_scans():
    return get("/scans")


def create_scan(scan):
    return post("/scans", scan, manager_credentials())


def describe_scan(id):
    return get(f"/scans/{id}")


def prepare_export(id):
    return post(f"/scans/{id}/export", {"format": "csv"})


def schedule_scans(custom_headers, config_file):
    return post("/scans/", {"format": "csv"})


def list_policy_templates():
    return get("/editor/policy/templates")


def download_report(export_token):
    return get(f"/tokens/{export_token['token']}/download", text=True).text
