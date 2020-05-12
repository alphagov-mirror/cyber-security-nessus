# Cyber Security Nessus
This repo holds the infrastructure to support cyber security's Nessus instance. Nessus is a vulnerability scanner which we have set up to scan specified government domains on a daily schedule. 

## Architecture
This infrastructure can broadly be broken down into the following steps:
- Nessus is set up on an EC2 instance, and scans the specified domains daily. 
- Each day, a lambda will take the generated scans from Nessus and send them forward to cloudwatch
- Using the [centralised-security-logging-service](https://github.com/alphagov/centralised-security-logging-service), these cloudwatch logs are then forwarded onto splunk, where they can be queried under index `TODO: add index name`

See below for a diagram of the architecture.
![Architecture diagram](assets/architecture.jpg?raw=true)

## Deployment details
Merges to master will trigger a deploy in [Concourse](https://cd.gds-reliability.engineering/teams/cybersecurity-tools/pipelines/nessus).

This deploys to account `676218256630` in region `eu-west-2`

## Prerequisites
Before working on this project, install pipenv and create an environment for this repo:
```
brew install pipenv
cd cyber-security-nessus
pipenv shell
```

## Tests
Tests are run as part of the concourse deployment, however if you want to run the tests manually, you need to use AWS credentials. The easiest was to do this is with aws-vault:
- run the tests in the root of the project with
  ```
  aws-vault exec {vulnerability-account} -- pipenv run pytest
  ```

## Resources

- TODO [link to Nessus api docs when we have hostname]()
- tests are mocked with [vcrpy](https://github.com/kevin1024/vcrpy)