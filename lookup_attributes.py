import boto3
import logging
from botocore.config import Config
from os import getenv
import sys
import json
import click

logger = logging.getLogger()
handler = logging.StreamHandler(sys.stdout)
log_level = getenv("LOGLEVEL", "INFO")
level = logging.getLevelName(log_level)
logger.setLevel(level)
logger.addHandler(handler)


def boto3_client(resource, assumed_credentials=None):
    config = Config(
        retries=dict(
            max_attempts=40
        )
    )
    if assumed_credentials:
        client = boto3.client(
            resource,
            aws_access_key_id=assumed_credentials['AccessKeyId'],
            aws_secret_access_key=assumed_credentials['SecretAccessKey'],
            aws_session_token=assumed_credentials['SessionToken'],
            config=config
        )
    else:
        client = boto3.client(
            resource,
            config=config
        )

    return client


@click.command()
@click.option("--service_code", required=True)
@click.option("--attributes_file", required=False, default=None)
@click.option("--exclude_attributes", required=False, default=['instancesku'])
@click.option("--output_allowed_values", default=False)
@click.option("--allowed_values_file", required=False, default=None)
def lookup_attributes(service_code, attributes_file, output_allowed_values, allowed_values_file, exclude_attributes):
    try:
        client = boto3.client('pricing')
        describe_services_paginator = client.get_paginator('describe_services')
        response_iterator = describe_services_paginator.paginate(
            ServiceCode=service_code,
            # FormatVersion='string',
            # PaginationConfig={
            #     'MaxItems': 123,
            #     'PageSize': 123,
            # }
        )
        if attributes_file:
            attributes_file_handler = open(attributes_file, "w")
        if allowed_values_file:
            allowed_values_file_handler = open(allowed_values_file, "w")
        for response in response_iterator:
            if 'Services' in response and len(response['Services']) > 0:
                for attribute in response['Services'][0]['AttributeNames']:
                    if attribute in exclude_attributes:
                        continue
                    if attributes_file:
                        attributes_file_handler.write('{}\t'.format(attribute))
                    logger.info(attribute)

                    if output_allowed_values:
                        if allowed_values_file:
                            allowed_values_file_handler.write('{}'.format(attribute))
                        get_attribute_values_paginator = client.get_paginator('get_attribute_values')
                        get_attribute_values_response_iterator = get_attribute_values_paginator.paginate(
                            ServiceCode=service_code,
                            AttributeName=attribute,
                            # PaginationConfig={
                            #     'MaxItems': 123,
                            #     'PageSize': 123,
                            #     'StartingToken': 'string'
                            # }
                        )

                        for get_attribute_values_response in get_attribute_values_response_iterator:
                            if 'AttributeValues' in get_attribute_values_response:
                                for attribute_value in get_attribute_values_response['AttributeValues']:
                                    if allowed_values_file:
                                        allowed_values_file_handler.write(',{}'.format(attribute_value['Value']))
                                    logger.info("\t{}".format(attribute_value['Value']))
                                if allowed_values_file:
                                    allowed_values_file_handler.write('\n')

        if attributes_file:
            attributes_file_handler.close()

        if allowed_values_file:
            allowed_values_file_handler.close()

    except Exception as e:
        # If any other exceptions which we didn't expect are raised
        # then fail and log the exception message.
        logger.error('Lookup Attributes Failed: {}'.format(e))
        raise


lookup_attributes()
