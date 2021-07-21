#!/usr/bin/env bash
# Generates a tab delimited list of ec2 sku attributes for pricing
aws pricing describe-services --service-code AmazonEC2 --query Services[0].AttributeNames[*] --output text
