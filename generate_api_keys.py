import json
import time
from functools import lru_cache

import boto3
import requests

from nessus import get_token, base_url


@lru_cache(maxsize=None)
def ssm_client():
    return boto3.client("ssm")


@lru_cache(maxsize=None)
def ec2_client():
    return boto3.client("ec2")


def get_ec2_param(param):
    return ec2_client().describe_instances(
        Filters=[
            {
                "Name": "tag:Name",
                "Values": ["Nessus Scanning Instance"],
            },
            {
                "Name": "instance-state-name",
                "Values": ["running"],
            }
        ]
    )["Reservations"][0]["Instances"][0][f"{param}"]


def instance_ready():
    nessus_status_checks = ec2_client().describe_instance_status(
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


def update_ssm_base_url():
    """Update the `base_url` SSM parameter with the current instances
    public IP"""
    return put_param(
        f"https://{get_ec2_param('PublicIpAddress')}:8834", "public_base_url"
    )


def put_keys():
    keys_url = "/session/keys"
    keys_response = requests.put(
        base_url() + keys_url, headers=get_token(), verify=False
    )
    keys = json.loads(keys_response.text)
    access_key = keys["accessKey"]
    secret_key = keys["secretKey"]

    out = [
        put_param(access_key, name="access_key"),
        put_param(secret_key, name="secret_key"),
    ]
    return out


def put_param(value, name):
    ssm_client().put_parameter(
        Name=f"/nessus/{name}",
        Description=f"{name} for the Nessus instance",
        Value=f"{value}",
        Overwrite=True,
        Type="SecureString",
    )


def nessus_ready():
    try:
        server_status_url = "/server/status"
        response = requests.get(base_url() + server_status_url, verify=False)
        status = json.loads(response.text)
        return True

    except (ConnectionError, requests.exceptions.ConnectionError) as e:
        print("connection error")
        return False


def main():
    ec2_timeout = time.time() + 60 * 10
    while not instance_ready():
        if time.time() > ec2_timeout:
            print("Timed out, instance has not passed AWS EC2 status checks.")
            break
        time.sleep(60)

    update_ssm_base_url()

    nessus_timeout = time.time() + 60 * 60
    while nessus_ready():
        if time.time() > nessus_timeout:
            print("Timed out, check nessus is installed correctly.")
            break
        print(f"Nessus is still loading.\n Progess: {status['progress']}")
        time.sleep(300)

    put_keys()

if __name__ == "__main__":
    print("generating api keys...")
    main()
