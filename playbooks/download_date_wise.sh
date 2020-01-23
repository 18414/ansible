#!/bin/bash

echo -e "Enter specific date to download data"

read -p "Please enter the value"


aws s3 put /var/log/mysql/$datewiseval 



