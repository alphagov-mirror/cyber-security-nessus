# Cyber Security Nessus
This repo holds the infrastructure to support cyber security's Nessus instance. Nessus is a vulnerability scanner which we have set up to scan specified government domains on a daily schedule.

## Architecture
TODO arch diagram here

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
Tests are run as part of the concourse deployment, however follow these steps if you want to run the tests manually:
- ensure the virtual environment is running, or activate it by running 
  ```
  pipenv shell
  ```
- run the tests in the root of the project with
  ```
  make tests
  ```

## Resources

- TODO [link to Nessus api docs when we have hostname]()
- tests are mocked with [vcrpy](https://github.com/kevin1024/vcrpy)