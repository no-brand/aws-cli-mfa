# -*- coding: utf-8 -*-

import argparse
import configparser
import json
import subprocess
import os
import sys
from .log import Logger


def run():
    logger = Logger().logger
    AWS_CONFIG_CREDENTIALS_PATH = '{}/.aws/credentials'.format(os.path.expanduser('~'))

    parser = argparse.ArgumentParser(
        description='Get AWS session token with MFA and optionally assume a role'
    )
    parser.add_argument('--mfa', help='MFA token code (get-session-token --token-code)', type=str, required=True)
    parser.add_argument('--profile', help='AWS profile you want to use (get-session-token --profile)', type=str, default=os.getenv('AWS_PROFILE'))
    parser.add_argument('--arn', help='ARN of the MFA device (get-session-token --serial-number)', type=str)
    parser.add_argument('--assume_role', help='ARN of the role to assume (assume-role --role-arn)', type=str)
    parser.add_argument('--assume_profile', help='AWS profile to store assumed role credentials', type=str)
    args = parser.parse_args()

    if args.profile is None:
        parser.error('AWS_PROFILE environment variable is not set. Use --profile or set AWS_PROFILE.')

    config = configparser.ConfigParser()
    config.read(AWS_CONFIG_CREDENTIALS_PATH)

    if args.arn is not None:
        if not config.has_section(args.profile):
            config.add_section(args.profile)
        config[args.profile]['mfa_device_arn'] = args.arn
        with open(AWS_CONFIG_CREDENTIALS_PATH, 'w') as f:
            config.write(f)
        logger.debug('Saved mfa_device_arn ({}) to ~/.aws/credentials'.format(args.arn))
    else:
        try:
            args.arn = config[args.profile]['mfa_device_arn']
            logger.debug('Read mfa_device_arn ({}) from ~/.aws/credentials'.format(args.arn))
        except KeyError:
            parser.error('MFA device ARN not found. Provide --arn or set mfa_device_arn in ~/.aws/credentials')

    result = subprocess.run([
        'aws', 'sts', 'get-session-token',
        '--profile', args.profile + '-default',
        '--serial-number', args.arn,
        '--token-code', str(args.mfa)
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if result.returncode != 0:
        logger.error('get-session-token failed')
        parser.error(result.stderr.decode('utf-8').strip('\n'))

    logger.debug('get-session-token succeeded')
    credentials = json.loads(result.stdout.decode('utf-8'))['Credentials']

    config.read(AWS_CONFIG_CREDENTIALS_PATH)
    if not config.has_section(args.profile):
        config.add_section(args.profile)

    config[args.profile]['aws_access_key_id'] = credentials['AccessKeyId']
    config[args.profile]['aws_secret_access_key'] = credentials['SecretAccessKey']
    config[args.profile]['aws_session_token'] = credentials['SessionToken']
    config[args.profile]['aws_session_expiration'] = credentials['Expiration']

    with open(AWS_CONFIG_CREDENTIALS_PATH, 'w') as f:
        config.write(f)

    print('Session token acquired. Expires: {}'.format(credentials['Expiration']))

    if args.assume_profile is None and args.assume_role is None:
        sys.exit(0)

    if args.assume_profile is None:
        parser.error('--assume_profile is required when using --assume_role')

    if args.assume_role is not None:
        if not config.has_section(args.assume_profile):
            config.add_section(args.assume_profile)
        config[args.assume_profile]['assume_role_arn'] = args.assume_role
        with open(AWS_CONFIG_CREDENTIALS_PATH, 'w') as f:
            config.write(f)
        logger.debug('Saved assume_role_arn ({}) to ~/.aws/credentials'.format(args.assume_role))
    else:
        try:
            args.assume_role = config[args.assume_profile]['assume_role_arn']
            logger.debug('Read assume_role_arn ({}) from ~/.aws/credentials'.format(args.assume_role))
        except KeyError:
            parser.error('Role ARN not found. Provide --assume_role or set assume_role_arn in ~/.aws/credentials')

    result = subprocess.run([
        'aws', 'iam', 'get-user',
        '--profile', args.profile
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if result.returncode != 0:
        logger.error('get-user failed')
        parser.error(result.stderr.decode('utf-8').strip('\n'))

    logger.debug('get-user succeeded')
    user = json.loads(result.stdout.decode('utf-8'))['User']['UserName']

    result = subprocess.run([
        'aws', 'sts', 'assume-role',
        '--profile', args.profile,
        '--role-arn', args.assume_role,
        '--role-session-name', user
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if result.returncode != 0:
        logger.error('assume-role failed')
        parser.error(result.stderr.decode('utf-8').strip('\n'))

    logger.debug('assume-role succeeded')
    credentials = json.loads(result.stdout.decode('utf-8'))['Credentials']

    config.read(AWS_CONFIG_CREDENTIALS_PATH)
    if not config.has_section(args.assume_profile):
        config.add_section(args.assume_profile)

    config[args.assume_profile]['aws_access_key_id'] = credentials['AccessKeyId']
    config[args.assume_profile]['aws_secret_access_key'] = credentials['SecretAccessKey']
    config[args.assume_profile]['aws_session_token'] = credentials['SessionToken']
    config[args.assume_profile]['aws_session_expiration'] = credentials['Expiration']

    with open(AWS_CONFIG_CREDENTIALS_PATH, 'w') as f:
        config.write(f)

    print('Assumed role {}. Expires: {}'.format(args.assume_role, credentials['Expiration']))
