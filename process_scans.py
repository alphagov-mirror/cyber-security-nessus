import csv
import io
from functools import lru_cache

import boto3

from nessus import download_report, list_scans, prepare_export


def find_scans():
    scans = list_scans()
    for scan in scans["scans"]:
        # This is for testing as we haven't run a full scan yet
        if scan["status"] == "completed":
            print(f"Preparing export for {scan['name']}")
            token = prepare_export(scan["id"])
            csv_text = download_report(token["token"])
            process_csv(csv_text, scan)
        elif scan["status"] == "empty":
            print(f"Scan {scan['name']} has not run.")


def process_csv(csv_text, scan):
    """
    Send the CSV - 1 row at a time - to cloud watch. This will create a
    new event for each row in Splunk.
    """
    #  Need to use StringIO because csv.reader expects a file object
    with io.StringIO(csv_text) as f:
        reader = csv.reader(f)

        group_name = "/gds/nessus-scans"
        stream_name = f"{scan['last_modification_date']}-{scan['name']}"
        token = create_log_stream(group_name, stream_name)

        events = []

        for row in reader:

            events.append(
                {
                    "timestamp": scan["last_modification_date"] * 1000,
                    "message": ",".join(row).replace("\n", " "),
                }
            )

            # Send in batches of 10_000
            if len(events) >= 9999:
                token = logs_client().put_log_events(
                    logGroupName=group_name,
                    logStreamName=stream_name,
                    logEvents=events,
                    sequenceToken=token,
                )["nextSequenceToken"]

                events = []

        # send finial batch
        logs_client().put_log_events(
            logGroupName=group_name,
            logStreamName=stream_name,
            logEvents=events,
            sequenceToken=token,
        )


@lru_cache(maxsize=None)
def logs_client():
    return boto3.client("logs")


def create_log_stream(group_name, stream_name):

    try:
        logs_client().create_log_stream(
            logGroupName=group_name, logStreamName=stream_name
        )
    except logs_client().exceptions.ResourceAlreadyExistsException:
        pass

    response = logs_client().describe_log_streams(
        logGroupName=group_name, logStreamNamePrefix=stream_name,
    )

    if "uploadSequenceToken" in response["logStreams"][0]:
        token = response["logStreams"][0]["uploadSequenceToken"]
    else:
        token = "0"

    return token


def main(event, context):
    print("Processing scans and sending to cloudwatch...")
    find_scans()


if __name__ == "__main__":
    main(None, None)
