import json
import time

import boto3
import requests

ssm_client = boto3.client("ssm")
ec2_client = boto3.client("ec2")


def get_username():
    nessus_username_response = ssm_client.get_parameter(
        Name="/nessus/username", WithDecryption=True
    )
    nessus_username = nessus_username_response["Parameter"]["Value"]
    return nessus_username


def get_password():
    nessus_password_response = ssm_client.get_parameter(
        Name="/nessus/password", WithDecryption=True
    )
    nessus_password = nessus_password_response["Parameter"]["Value"]
    return nessus_password


def get_status_checks():
    nessus_instance_id = ec2_client.describe_instances(
        Filters=[
            {
                "Name": "tag:Name",
                "Values": ["Nessus Scanning Instance"],
                "Name": "instance-state-name",
                "Values": ["running"],
            }
        ]
    )["Reservations"][0]["Instances"][0]["InstanceId"]

    nessus_status_checks = ec2_client.describe_instance_status(
        InstanceIds=[nessus_instance_id]
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
    nessus_public_ip = ec2_client.describe_instances(
        Filters=[
            {
                "Name": "tag:Name",
                "Values": ["Nessus Scanning Instance"],
                "Name": "instance-state-name",
                "Values": ["running"],
            }
        ]
    )["Reservations"][0]["Instances"][0]["PublicIpAddress"]
    base_url = f"https://{nessus_public_ip}:8834"
    put_base_url(base_url, url_type="public_base_url")
    return base_url


def get_private_url():
    nessus_private_ip = ec2_client.describe_instances(
        Filters=[
            {
                "Name": "tag:Name",
                "Values": ["Nessus Scanning Instance"],
                "Name": "instance-state-name",
                "Values": ["running"],
            }
        ]
    )["Reservations"][0]["Instances"][0]["PrivateIpAddress"]
    base_url = f"https://{nessus_private_ip}:8834"
    put_base_url(base_url, url_type="private_base_url")
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
    put_access_key(access_key)
    put_secret_key(secret_key)


def get_token():
    session_url = "/session"
    params = {"username": get_username(), "password": get_password()}
    response = requests.post(get_public_url() + session_url, data=params, verify=False)
    response_token = json.loads(response.text)
    return {"X-Cookie": f"token={response_token['token']}"}



def put_access_key(access_key):
    put_access_key = ssm_client.put_parameter(
        Name="/nessus/access_key",
        Description="API Access Key for the Nessus instance",
        Value=access_key,
        Overwrite=True,
        Type="SecureString",
    )


def put_secret_key(secret_key):
    put_secret_key = ssm_client.put_parameter(
        Name="/nessus/secret_key",
        Description="API Secret Key for the Nessus instance",
        Value=secret_key,
        Overwrite=True,
        Type="SecureString",
    )


def put_base_url(base_url, url_type):

    put_base_url = ssm_client.put_parameter(
        Name=f"/nessus/{url_type}",
        Description="Base url for the Nessus instance",
        Value=base_url,
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
        put_base_url(get_public_url(), url_type="public_base_url")
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
