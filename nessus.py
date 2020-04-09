import requests
import os
import json
import csv
import io

from cloudwatch import send_logs_to_cloudwatch


access_key = os.environ["access_key"]
secret_key = os.environ["secret_key"]
nessus_ip = os.environ["nessus_ip"]

base_url = f"https://{nessus_ip}:8834"
custom_headers = {"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}"}
filters = {
    "filter.0.filter": "severity",
    "filter.0.quality": "neq",
    "filter.0.value": "None",
    "filter.1.filter": "plugin.attributes.cvss_base_score",
    "filter.1.quality": "gt",
    "filter.1.value": "3",
    "filter.search_type": "and",
}


def prepare_export(id=5):
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


def token_download(export_token):
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
    csv_list = csv_text.split("\n")
    reader = csv.reader(csv_list)
    writer = csv.writer(output)
    for row in reader:
        if len(row) > 0:
            row.pop()
            writer.writerow(row)
    print(output.getvalue())
    return output.getvalue()


def main():
    token = prepare_export()
    csv_text = token_download(token)
    reduced_csv = process_csv(csv_text)
    send_to_cloudwatch(reduced_csv)


if __name__ == "__main__":
    main()
