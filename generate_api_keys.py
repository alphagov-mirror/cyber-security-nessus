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
    private_base_url = f"https://{nessus_private_ip}:8834"
    put_base_url(private_base_url)
    return private_base_url


def get_keys(headers):
    keys_url = "/session/keys"
    keys_response = requests.put(
        get_public_url() + keys_url, headers=headers, verify=False
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
    headers = {"X-Cookie": f"token={response_token['token']}"}
    get_keys(headers)


def put_access_key(access_key):
    put_access_key = ssm_client.put_parameter(
        Name="/nessus/access_key",
        Description="API Access Key for the Nessus instance",
        Value=access_key,
        Type="SecureString",
    )


def put_secret_key(secret_key):
    put_secret_key = ssm_client.put_parameter(
        Name="/nessus/secret_key",
        Description="API Secret Key for the Nessus instance",
        Value=secret_key,
        Type="SecureString",
    )


def put_base_url(private_base_url):
    put_base_url = ssm_client.put_parameter(
        Name="/nessus/base_url",
        Description="Base url for the Nessus instance",
        Value=private_base_url,
        Type="SecureString",
    )


import time

timeout = time.time() + 60 * 5  # 5 minutes from now
while True:
    test = 0
    if test == 5 or time.time() > timeout:
        break
    test = test - 1


def main():
    server_status_url = "/server/status"
    response = requests.get(get_public_url() + server_status_url, verify=False)
    status = json.loads(response.text)
    # {"code":503,"progress":69,"status":"loading"}
    loading = True
    timeout = time.time() + 60 * 30
    while loading:
        if status["status"] == "ready":
            loading = False
            get_token()
        elif time.time() > timeout:
            print("Timed out, check nessus is installed correctly.")
            break
        elif status["status"] == "loading":
            loading = True
            print(f"Nessus is still loading.\n Progess: {status['progress']}")


if __name__ == "__main__":
    main()
