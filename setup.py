# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
import re
import os

with open('awsclimfa/__init__.py', encoding='utf8') as f:
    version = re.search(r'__version__ = \'(.*)\'', f.read()).group(1)
    
with open('README.md', 'r') as f:
    long_description = f.read() 

setup(
    name='aws-cli-mfa',
    version=version,
    description='It can help you to access AWS resources through AWS CLI with MFA token',
    long_description=long_description,
    long_description_content_type='text/markdown',
    install_requires=['boto3'],
    packages=find_packages(exclude=['tests*']),
    include_package_data=True,
    author='no-brand',
    author_email='do.dream.david@gmail.com',
    url='https://github.com/no-brand/aws-cli-mfa',
    license='MIT',
    entry_points={
        'console_scripts': [
            'aws-cli-mfa=awsclimfa.main:run'
        ]
    }
)
