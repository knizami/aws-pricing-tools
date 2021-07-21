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


@click.command()
@click.option("--file", required=True)
def lookup_products(file):
    try:
        f = open(file, "r")
        product_options = json.loads(f.read())
        logger.info('product options are: {}'.format(product_options))
        client = boto3.client('pricing')
        paginator = client.get_paginator('get_products')
        response_iterator = paginator.paginate(**product_options)
        for response in response_iterator:
            for product in response['PriceList']:
                product_json = json.loads(product)
                for attribute, value in product_json['product']['attributes'].items():
                    logger.info("{}: {}".format(attribute,value))
                for term, items in product_json['terms'].items():
                    logger.info("\n\nTerm: {}: {}".format(term, json.dumps(items)))
                    for code, details in items.items():
                        logger.info("\n{}: {}".format(code,details))

    except Exception as e:
        # If any other exceptions which we didn't expect are raised
        # then fail and log the exception message.
        logger.error('Lookup Attributes Failed: {}'.format(e))
        raise


lookup_products()
