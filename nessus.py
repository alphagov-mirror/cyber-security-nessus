import re
from functools import lru_cache

import boto3
import requests
import validators


def verify_ssl():
    is_domain = validators.domain(base_url())

    if is_domain:
        return True
    else:
        return False


def get(path, text=False):
    """Make a GET request to Nessus"""
    if text:
        return requests.get(
            base_url() + path, headers=api_credentials(), verify=verify_ssl(),
        )
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


@lru_cache(maxsize=1)
def base_url():
    return get_param_from_ssm("public_base_url")


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


def update_scan(scan, id):
    return put(f"/scans/{id}", scan, manager_credentials())


def describe_scan(id):
    return get(f"/scans/{id}")


def prepare_export(id):
    return post(f"/scans/{id}/export", {"format": "csv"})


def list_policy_templates():
    return get("/editor/policy/templates")


def download_report(token):
    return get(f"/tokens/{token}/download", text=True).text
