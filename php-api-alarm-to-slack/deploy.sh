#!/bin/sh
aws-vault exec allthings-admin -- aws cloudformation package \
  --template-file template.yml \
  --s3-bucket allthings-lambda-deployments-eu-west-1 \
  --output-template-file packaged.yml

aws-vault exec allthings-admin -- aws cloudformation deploy \
  --template-file ./packaged.yml \
  --stack-name php-api-alarm-to-slack \
  --capabilities CAPABILITY_IAM
