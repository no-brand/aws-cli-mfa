# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
import re
import os

with open('awsclimfa/__init__.py', encoding='utf8') as f:
    version = re.search(r'__version__ = \'(.*)\'', f.read()).group(1)
    
setup(
    name='aws-cli-mfa',
    version=version,
    description='',
    install_requires=['boto3'],
    packages=find_packages(exclude=['tests*']),
    author='no-brand',
    author_email='do.dream.david@gmail.com',
    url='https://github.com/no-brand/aws-cli-mfa',
    license='MIT'
)
