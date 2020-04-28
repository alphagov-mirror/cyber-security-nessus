import csv
import io
from functools import lru_cache

import boto3
import requests

def get(url, param, text=False):
    if text:
        return requests.get(
            get_param_from_ssm(param) + url,
            headers=create_custom_headers(),
            verify=False,
        )
    else:
        return requests.get(
            get_param_from_ssm(param) + url,
            headers=create_custom_headers(),
            verify=False,
        ).json()


def post(url, param, payload, headers=None):
    return requests.post(
        get_param_from_ssm(param) + url,
        headers=headers if headers else create_custom_headers(),
        json=payload,
        verify=False,
    ).json()


def base_url():
    return "public_base_url"


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


def prepare_export(id):
    url = f"/scans/{id}/export"
    payload = {"format": "csv"}
    return post(url, base_url(), payload)


def download_report(export_token):
    url = f"/tokens/{export_token['token']}/download"
    response = get(url, base_url(), text=True)
    return response.text


def list_scans():
    return get("/scans", base_url())


@lru_cache(maxsize=1)
def find_scans():
    scans = list_scans()
    try:
        for scan in scans["scans"]:
            # This is for testing as we haven't run a full scan yet
            if scan["status"] == "canceled":
                print(f"Preparing export for {scan['name']}")
                token = prepare_export(scan["id"])
                csv_text = download_report(token)
                process_csv(csv_text, scan)
            elif scan["status"] == "empty":
                print(f"Scan {scan['name']} has not run.")
    except KeyError:
        print("Unable to find scans.")


@lru_cache(maxsize=None)
# def logs_client() -> logs.CloudWatchLogsClient:
def logs_client():
    return boto3.client("logs")


def process_csv(csv_text, scan):
    """
    Send the CSV - 1 row at a time - to cloud watch. This will create a 
    new event for each row in Splunk.
    """
    #  Need to use StringIO because csv.reader expects a file object
    with io.StringIO(csv_text) as f:
        reader = csv.reader(f)

        group_name = "/gds/nessus-data"
        stream_name = f"{scan['last_modification_date']}-{scan['name']}"

        try:
            logs_client().create_log_stream(
                logGroupName=group_name, logStreamName=stream_name
            )
        except logs_client().exceptions.ResourceAlreadyExistsException:
            pass

        
        
        logs_client().put_log_events(
            logGroupName="/gds/nessus-data",
            logStreamName=stream_name,
            logEvents=[
                {
                    "timestamp": scan['last_modification_date'] * 1000,
                    "message": ",".join(row).replace("\n", " ")
                }
                for row in reader
            ],
        )


def main(event, context):
    find_scans()
    # scans = list_scans()
    # p(scans)
    # token = prepare_export()
    # csv_text = download_report(token)
    # process_csv(csv_text)


if __name__ == "__main__":
    main(None, None)
