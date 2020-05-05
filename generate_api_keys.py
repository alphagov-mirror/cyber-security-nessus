import json
import time

import boto3
import requests

from nessus import get_token, base_url


ssm_client = boto3.client("ssm")
ec2_client = boto3.client("ec2")


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


def put_keys():
    keys_url = "/session/keys"
    keys_response = requests.put(
        base_url() + keys_url, headers=get_token(), verify=False
    )
    keys = json.loads(keys_response.text)
    access_key = keys["accessKey"]
    secret_key = keys["secretKey"]
    put_param(access_key, type="access_key")
    put_param(secret_key, type="secret_key")


def put_param(param, type):
    ssm_client.put_parameter(
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
            put_keys()
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
