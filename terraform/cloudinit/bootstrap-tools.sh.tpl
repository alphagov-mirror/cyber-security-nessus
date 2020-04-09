#!/usr/bin/env bash
set -euo pipefail

echo "Starting Bootstrapping"
yum update -y
sudo service nessusd stop
sudo /opt/nessus/sbin/nessuscli fetch --register <serial>
sudo service nessusd start
sudo /opt/nessus/sbin/nessuscli adduser <username>
sudo /opt/nessus/sbin/nessuscli chpasswd <password>
echo "Bootstrapping Complete"
exit 0
