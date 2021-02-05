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
    parser = argparse.ArgumentParser(description='Get and enable your AWS session token. Furthermore, ')
    parser.add_argument('--mfa', help='MFA token code (get-session-token --token-code)', type=int, required=True)
    parser.add_argument('--profile', help='AWS profile you want to use (get-session-token --profile)', type=str, default=os.getenv('AWS_PROFILE'))
    parser.add_argument('--arn', help='ARN of the MFA device (get-session-token --serial-number)', type=str)
    parser.add_argument('--assume_role', help='ARN of the role to assume (assume-role --role-arn)', type=str)
    parser.add_argument('--assume_profile', help='AWS profile you want to get role to assume (assume-role)', type=str)
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
        logger.debug('get-session-token is failed')
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

    # Assuming role to be other account
    if args.assume_role is not None:
        if args.assume_profile is None:
            parser.error('missing AWS profile, having role to assume')

        # Remeber assume role arn
        if not config.has_section(args.assume_profile):
            config.add_section(args.assume_profile)
        config[args.assume_profile]['assume_role_arn'] = args.assume_role
        with open(AWS_CONFIG_CREDENTIALS_PATH, 'w') as f:
            config.write(f)
        logger.debug('write assume_role_arn ({}) into ~/.aws/credentials'.format(args.assume_role))
    else:
        args.assume_role = config[args.assume_profile]['assume_role_arn']
        logger.debug('read mfa_device_arn ({}) from ~/.aws/credentials'.format(args.assume_role))

    # Generate identifier of assuming role    
    result = subprocess.run(['aws', 'iam', 'get-user', '--profile', args.profile,],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        logger.debug('get-user is failed')
        parser.error(result.stderr.decode('utf-8').strip('\n'))
    else:
        logger.debug('get-user is succeeded')
        user = json.loads(result.stdout.decode('utf-8'))['User']['UserName']
    
    # Get session token for assume-role
    result = subprocess.run(['aws', 'sts', 'assume-role',
                            '--role-arn', args.assume_role,
                            '--role-session-name', user], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        logger.debug('assume-role is failed')
        parser.error(result.stderr.decode('utf-8').strip('\n'))
    else:
        logger.debug('assume-role is succeeded')
        credentials = json.loads(result.stdout.decode('utf-8'))['Credentials']
        
        config = configparser.ConfigParser()
        config.read(AWS_CONFIG_CREDENTIALS_PATH)

        config[args.assume_profile]['aws_access_key_id'] = credentials['AccessKeyId']
        config[args.assume_profile]['aws_secret_access_key'] = credentials['SecretAccessKey']
        config[args.assume_profile]['aws_session_token'] = credentials['SessionToken']
        config[args.assume_profile]['aws_session_expiration'] = credentials['Expiration']

        with open(AWS_CONFIG_CREDENTIALS_PATH, 'w') as f:
            config.write(f)
