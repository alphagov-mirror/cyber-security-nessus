import json
import time
from functools import lru_cache

import boto3
import requests

from nessus import get_param_from_ssm


ssm_client = boto3.client("ssm")
ec2_client = boto3.client("ec2")


@lru_cache(maxsize=1)
def username():
    return get_param_from_ssm("username")


@lru_cache(maxsize=1)
def password():
    return get_param_from_ssm("password")


def get_ec2_param(param):
    return ec2_client.describe_instances(
        Filters=[
            {
                "Name": "tag:Name",
                "Values": ["Nessus Scanning Instance"],
                "Name": "instance-state-name",
                "Values": ["running"],
            }
        ]
    )["Reservations"][0]["Instances"][0][f"{param}"]


def get_status_checks():
    nessus_status_checks = ec2_client.describe_instance_status(
        InstanceIds=[get_ec2_param("InstanceId")]
    )

    status = nessus_status_checks["InstanceStatuses"][0]["InstanceStatus"]["Status"]
    reachability = nessus_status_checks["InstanceStatuses"][0]["InstanceStatus"][
        "Details"
    ][0]["Status"]

    if status != "ok":
        print(f"EC2 is not ready. Status: {status}")
        return False

    if reachability != "passed":
        print(f"EC2 is not reachable. Status: {reachability}")
        return False

    return True


def get_public_url():
    base_url = f"https://{get_ec2_param('PublicIpAddress')}:8834"
    put_param(base_url, type="public_base_url")
    return base_url


def get_private_url():
    base_url = f"https://{get_ec2_param('PrivateIpAddress')}:8834"
    put_param(base_url, type="private_base_url")
    return base_url


# TODO rename to put keys
def get_keys():
    keys_url = "/session/keys"
    keys_response = requests.put(
        get_public_url() + keys_url, headers=get_token(), verify=False
    )
    keys = json.loads(keys_response.text)
    access_key = keys["accessKey"]
    secret_key = keys["secretKey"]
    put_param(access_key, type="access_key")
    put_param(secret_key, type="secret_key")


def get_token():
    session_url = "/session"
    params = {"username": username(), "password": password()}
    response = requests.post(get_public_url() + session_url, data=params, verify=False)
    response_token = json.loads(response.text)
    return {"X-Cookie": f"token={response_token['token']}"}


def put_param(param, type):
    put_key = ssm_client.put_parameter(
        Name=f"/nessus/{type}",
        Description=f"{type} for the Nessus instance",
        Value=f"{param}",
        Overwrite=True,
        Type="SecureString",
    )


def get_nessus_status():
    try:
        server_status_url = "/server/status"
        response = requests.get(get_public_url() + server_status_url, verify=False)
        status = json.loads(response.text)
        return status
    except ConnectionError:
        print("connection error")
        return {"status": "loading", "progress": "0"}


def main():
    ec2_timeout = time.time() + 60 * 10
    while True:
        if get_status_checks():
            break
        elif time.time() > ec2_timeout:
            print("Timed out, failed to connect to ec2.")
            break
        else:
            time.sleep(60)

    nessus_timeout = time.time() + 60 * 60
    while True:
        put_param(get_public_url(), type="public_base_url")
        status = get_nessus_status()
        if status["status"] == "ready":
            get_keys()
            break
        elif time.time() > nessus_timeout:
            print("Timed out, check nessus is installed correctly.")
            break
        elif status["status"] != "ready":
            print(f"Nessus is still loading.\n Progess: {status['progress']}")
            time.sleep(300)


if __name__ == "__main__":
    print("generating api keys...")
    main()
