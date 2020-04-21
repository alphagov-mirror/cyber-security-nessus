import json

import boto3
import requests

ssm_client = boto3.client("ssm")
ec2_client = boto3.client("ec2")

nessus_username_response = ssm_client.get_parameter(Name="/nessus/username", WithDecryption=True)
nessus_username = nessus_username_response["Parameter"]["Value"]
nessus_password_response = ssm_client.get_parameter(Name="/nessus/password", WithDecryption=True)
nessus_password = nessus_password_response["Parameter"]["Value"]

nessus_ip = ec2_client.describe_instances(
    Filters=[{
        "Name": "tag:Name",
        "Values": ["Nessus Scanning Instance"],
        "Name": "instance-state-name",
        "Values": ["running"]
    }]
)['Reservations'][0]['Instances'][0]['PublicIpAddress']

base_url = f"https://{nessus_ip}:8834"

session_url = "/session"
params = {
    "username": nessus_username,
    "password": nessus_password
}
response = requests.post(base_url + session_url, data=params, verify=False)
response_token = json.loads(response.text)
headers = {"X-Cookie": f"token={response_token['token']}"}

keys_url = "/session/keys"
keys_response = requests.put(base_url + keys_url, headers=headers, verify=False)
keys = json.loads(keys_response.text)
access_key = keys['accessKey']
secret_key = keys['secretKey']

put_access_key = ssm_client.put_parameter(
    Name="/nessus/access_key",
    Description="API Access Key for the Nessus instance",
    Value=access_key,
    Type="SecureString"
)
put_secret_key = ssm_client.put_parameter(
    Name="/nessus/secret_key",
    Description="API Secret Key for the Nessus instance",
    Value=secret_key,
    Type="SecureString"
)
