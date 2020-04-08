import requests
import os
import json

access_key = os.environ["access_key"]
secret_key = os.environ["secret_key"]
nessus_ip = os.environ["nessus_ip"]

base_url = f"https://{}:8834"
custom_headers = {"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}"}


def prepare_export(id=5):
    url = f"/scans/{id}/export"
    payload = {"format": "csv"}
    response = requests.post(
        base_url + url, headers=custom_headers, data=payload, verify=False
    )
    response_dict = json.loads(response.text)
    return response_dict


def token_download(export_token):
    url = f"/tokens/{export_token['token']}/download"
    response = requests.get(base_url + url, headers=custom_headers, verify=False)
    return response.text


def save_csv(csv_text):
    file = open("scan_results.csv", "w")
    file.write(csv_text)
    file.close()


def main():
    token = prepare_export()
    csv_text = token_download(token)
    save_csv(csv_text)


if __name__ == "__main__":
    main()
