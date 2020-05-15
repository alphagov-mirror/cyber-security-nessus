# Cyber Security Nessus
This repo holds the infrastructure to support cyber security's Nessus instance. [Nessus](https://www.tenable.com/products/nessus) is a vulnerability scanner which we have set up to scan specified government domains on a daily schedule. 

## Architecture
This infrastructure can broadly be broken down into the following steps:
- Nessus is set up on an EC2 instance, and scans the specified domains daily. 
- Each day, a lambda will take the generated scans from Nessus and send them forward to cloudwatch
- Using the [centralised-security-logging-service](https://github.com/alphagov/centralised-security-logging-service), these cloudwatch logs are then forwarded onto splunk, where they can be queried under index `nessus_scans`

See below for a diagram of the architecture.
![Architecture diagram](assets/architecture.jpg?raw=true)

## Deployment details
Merges to master will trigger a deploy in [Concourse](https://cd.gds-reliability.engineering/teams/cybersecurity-tools/pipelines/nessus).

This deploys to account `676218256630` in region `eu-west-2`

## Prerequisites
Before contributing to this project for the first time, you will need to install pipenv and create an environment for this repo:
```
pip install pipenv
pipenv install --dev
cd cyber-security-nessus
pipenv shell
```

This will install all dev dependencies listed in Pipfile.

## Tests
Tests are run as part of the concourse deployment, however if you want to run the tests manually, you need to use AWS credentials. The easiest was to do this is with aws-vault:
- run the tests in the root of the project with
  ```
  aws-vault exec {vulnerability-account} -- pipenv run pytest
  ```

## Adding a new scan
In order to schedule a new scan, you will need to add the scan details to [scan.toml](scan_config/scan.toml). Here you can
configure scan schedule and domain. Information on how to do this can be found in this file. 

This change is deployed by the [Concourse](https://cd.gds-reliability.engineering/teams/cybersecurity-tools/pipelines/nessus) pipeline on a merge to master.

## Resources

- Documentation for the Nessus API can be found on the Nessus server itself: https://nessus.gds-cyber-security.digital/api#/overview (Must connect over VPN)
- tests are mocked with [vcrpy](https://github.com/kevin1024/vcrpy)
