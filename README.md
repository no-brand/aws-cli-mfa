# AWS CLI MFA
It can help you to access AWS resources through AWS CLI with MFA token.<br>

## Preperation
1. AWS CLI environemnt (including configurations in ~/.aws)
```bash
$ curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
$ unzip awscliv2.zip
$ sudo ./aws/install
```
2. AWS profile name should follow this rule.
You need to prepare 2 profiles.
One for your original IAM user `${profile}-default`, and ther other is for your temporary profile, activated by MFA token. `${profile}`.
```bash
# Let's assume your IAM user name is 'lol'
# ~/.aws/credentials
[lol-default]
aws_access_key_id = ...
aws_secret_access_key = ...

[lol]
```

## Usage
|argument |description                            |mandatory|default                     |
|---------|---------------------------------------|---------|----------------------------|
|--mfa    |MFA token code (--token-code)          |Y        |-                           |
|--profile|AWS profile you want to use (--profile)|N        |AWS_PROFILE in your shell   |
|--arn    |ARN of the MFA device (--serial-number)|N        |.credentials' mfa_device_arn|
```bash
# Your profile should be 'lol'
$ echo $AWS_PROFILE
  lol

# 1st usage: pass arn of mfa togegher
# then, credentials keep your temporary information.
$ aws-cli-mfa --mfa ${mfa-token} --arn arn:aws:iam::${account-id}:mfa/${username} 

# Further usage: only pass mfa token is enough
$ aws-cli-mfa --mfa ${mfa-token}
```
