import requests
import os
import json
import csv
import io
import boto3

from cloudwatch import send_logs_to_cloudwatch


access_key = os.getenv("access_key", get_keys_from_ssm('access'))
secret_key = os.getenv("secret_key", get_keys_from_ssm('secret'))
nessus_ip = os.environ["nessus_ip"]
nessus_username = os.environ["nessus_username"]
nessus_password = os.environ["nessus_password"]

base_url = f"https://{nessus_ip}:8834"
filters = {
    "filter.0.filter": "severity",
    "filter.0.quality": "neq",
    "filter.0.value": "None",
    "filter.1.filter": "plugin.attributes.cvss_base_score",
    "filter.1.quality": "gt",
    "filter.1.value": "3",
    "filter.search_type": "and",
}


def get_keys_from_ssm(key):
    ssm_client = boto3.client("ssm")
    response = ssm_client.get_parameter(Name=f"/nessus/{key}_key", WithDecryption=True)
    return response["Parameter"]["Value"]

def create_custom_headers():
    if access_key:
        return {"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}"}
    else:
        # get token
        session_url = "/session"
        params = {
            "username": nessus_username,
            "password": nessus_password
        }
        response = requests.post(base_url + session_url, data=params, verify=False)
        response_token = json.loads(response.text)
        headers = {"X-Cookie": f"token={response_token['token']}"}

        # get api keys
        keys_url = "/session/keys"
        keys_response = requests.put(base_url + keys_url, headers=headers, verify=False)
        keys = json.loads(keys_response.text)
        new_access_key = keys['accessKey']
        new_secret_key = keys['secretKey']

        return {"X-ApiKeys": f"accessKey={new_access_key}; secretKey={new_secret_key}"}

def prepare_export(custom_headers, id=18):
    url = f"/scans/{id}/export"
    payload = {
        "format": "csv",
        "filters": filters,
        # The below are two different attempts at formatting the CSV response
        # Come back and look into this
        # "reportContents": {
        #     "vulnerabilitySections": {
        #         "plugin_information": "false",
        #         "solution": "false",
        #         "see_also": "false",
        #         "references": "true",
        #         "plugin_output": "false"
        #     }
        # }
        # "reportContents.vulnerabilitySections.plugin_information": "false",
        # "reportContents.vulnerabilitySections.solution": "false",
        # "reportContents.vulnerabilitySections.see_also": "false",
        # "reportContents.vulnerabilitySections.references": "true",
        # "reportContents.vulnerabilitySections.plugin_output": "false"
    }
    response = requests.post(
        base_url + url, headers=custom_headers, data=payload, verify=False
    )
    response_dict = json.loads(response.text)
    return response_dict


def token_download(export_token, custom_headers):
    print(export_token)
    url = f"/tokens/{export_token['token']}/download"
    response = requests.get(base_url + url, headers=custom_headers, verify=False)
    return response.text


def send_to_cloudwatch(csv_text):
    send_logs_to_cloudwatch(csv_text)


def process_csv(csv_text):
    """
    Remove some columns of the response to get the CSV file within the CloudWatch
    request size limit
    """
    output = io.StringIO()
    writer = csv.writer(output, quotechar='"', quoting=csv.QUOTE_ALL)
    with io.StringIO(csv_text) as f: # Need to use StringIO because csv.reader expects a file object
        reader = csv.reader(f)
        for row in reader:
            writer.writerow(row[:-1])
    # print(output.getvalue())
    return output.getvalue()


def main(event, context):
    custom_headers = create_custom_headers()
    token = prepare_export(custom_headers)
    csv_text = token_download(token, custom_headers)
    reduced_csv = process_csv(csv_text)
    # send_to_cloudwatch(reduced_csv)login


if __name__ == "__main__":
    main(None, None)
