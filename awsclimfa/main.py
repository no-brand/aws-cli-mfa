# -*- coding: utf-8 -*-

import argparse
import configparser
import json
import subprocess
import os
from .log import Logger


def run():
    logger = Logger().logger
    AWS_CONFIG_CREDENTIALS_PATH = '{}/.aws/credentials'.format(os.path.expanduser('~'))

    # aws sts get-session-token --serial-number $MFA_DEVICE_ARN --token-code $TOKEN_CODE
    parser = argparse.ArgumentParser(description='Get and enable your AWS session token')
    parser.add_argument('--mfa', help='MFA token code (--token-code)', type=int, required=True)
    parser.add_argument('--profile', help='AWS profile you want to use (--profile)', type=str, default=os.getenv('AWS_PROFILE'))
    parser.add_argument('--arn', help='ARN of the MFA device (--serial-number)', type=str)
    args = parser.parse_args()

    if args.profile is None:
        parser.error('AWS_PROFILE environment variable is not ready to use')

    # Prepare MFA device ARN
    config = configparser.ConfigParser()
    config.read(AWS_CONFIG_CREDENTIALS_PATH)

    if args.arn is not None:
        config[args.profile]['mfa_device_arn'] = args.arn
        with open(AWS_CONFIG_CREDENTIALS_PATH, 'w') as f:
            config.write(f)
        logger.debug('write mfa_device_arn ({}) into ~/.aws/credentials'.format(args.arn))
    else:
        args.arn = config[args.profile]['mfa_device_arn']
        logger.debug('read mfa_device_arn ({}) from ~/.aws/credentials'.format(args.arn))

    if args.arn is None:
        parser.error('ARN of the MFA device is not ready to use')

    # Get session token
    result = subprocess.run(['aws', 'sts', 'get-session-token',
                            '--profile', args.profile + '-default',
                            '--serial-number', args.arn,
                            '--token-code', str(args.mfa)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if result.returncode != 0:
        logger.debug('get-session-token if failed')
        parser.error(result.stderr.decode('utf-8').strip('\n'))
    else:
        logger.debug('get-session-token is succeeded')
        credentials = json.loads(result.stdout.decode('utf-8'))['Credentials']
        
        config = configparser.ConfigParser()
        config.read(AWS_CONFIG_CREDENTIALS_PATH)

        config[args.profile]['aws_access_key_id'] = credentials['AccessKeyId']
        config[args.profile]['aws_secret_access_key'] = credentials['SecretAccessKey']
        config[args.profile]['aws_session_token'] = credentials['SessionToken']
        config[args.profile]['aws_session_expiration'] = credentials['Expiration']

        with open(AWS_CONFIG_CREDENTIALS_PATH, 'w') as f:
            config.write(f)
