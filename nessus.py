import requests
import json
import csv
import io
import boto3

from cloudwatch import send_logs_to_cloudwatch as send_to_cloudwatch


def get_param_from_ssm(param):
    ssm_client = boto3.client("ssm")
    response = ssm_client.get_parameter(Name=f"/nessus/{param}", WithDecryption=True)
    return response["Parameter"]["Value"]


def create_custom_headers():
    access_key = get_param_from_ssm("access_key")
    secret_key = get_param_from_ssm("secret_key")
    if access_key:
        return {"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}"}
    else:
        print("ERROR: Failed to get API keys from SSM.")


def prepare_export(custom_headers, base_url, id=18):
    url = f"/scans/{id}/export"
    payload = {"format": "csv"}
    response = requests.post(
        base_url + url, headers=custom_headers, data=payload, verify=False
    )
    response_dict = json.loads(response.text)
    return response_dict


def token_download(export_token, base_url, custom_headers):
    url = f"/tokens/{export_token['token']}/download"
    response = requests.get(base_url + url, headers=custom_headers, verify=False)
    return response.text


def process_csv(csv_text):
    """
    Send the CSV - 1 row at a time - to cloud watch. This will create a new event for each row in Splunk.
    """
    #  Need to use StringIO because csv.reader expects a file object
    with io.StringIO(csv_text) as f:
        reader = csv.reader(f)
        for row in reader:
            send_to_cloudwatch(row)


def main(event, context):
    base_url = get_param_from_ssm("base_url")
    custom_headers = create_custom_headers()
    token = prepare_export(custom_headers, base_url)
    csv_text = token_download(token, base_url, custom_headers)
    process_csv(csv_text)


if __name__ == "__main__":
    main(None, None)
