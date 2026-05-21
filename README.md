# AWS CLI MFA

A CLI tool to simplify AWS access with MFA authentication and cross-account role assumption.

## Features

- Get temporary session tokens using MFA
- Assume roles in other AWS accounts
- Automatically store and reuse MFA device ARN and role ARN

## Prerequisites

1. AWS CLI installed and configured
```bash
$ curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
$ unzip awscliv2.zip
$ sudo ./aws/install
```

2. Configure AWS profiles in `~/.aws/credentials`

You need two profiles: one for your IAM user credentials (`${profile}-default`) and one for the MFA-authenticated session (`${profile}`).

```ini
# ~/.aws/credentials
# Example: if your profile name is 'myprofile'

[myprofile-default]
aws_access_key_id = AKIA...
aws_secret_access_key = ...

[myprofile]
# This section will be populated by aws-cli-mfa
```

## Installation

```bash
pip install aws-cli-mfa
```

## Usage

### Basic MFA Authentication

| Argument    | Description                              | Required | Default                      |
|-------------|------------------------------------------|----------|------------------------------|
| `--mfa`     | MFA token code                           | Yes      | -                            |
| `--profile` | AWS profile to use                       | No       | `$AWS_PROFILE` env variable  |
| `--arn`     | ARN of the MFA device                    | No       | Stored `mfa_device_arn`      |

```bash
# Set your profile
$ export AWS_PROFILE=myprofile

# First time: provide MFA device ARN (it will be saved for future use)
$ aws-cli-mfa --mfa 123456 --arn arn:aws:iam::111111111111:mfa/username

# Subsequent uses: just provide the MFA token
$ aws-cli-mfa --mfa 123456
```

### Cross-Account Role Assumption

| Argument           | Description                              | Required | Default                      |
|--------------------|------------------------------------------|----------|------------------------------|
| `--assume_role`    | ARN of the role to assume                | No       | Stored `assume_role_arn`     |
| `--assume_profile` | Profile name to store assumed credentials| No       | -                            |

```bash
# Assume a role in another account
$ aws-cli-mfa --mfa 123456 \
    --assume_role arn:aws:iam::222222222222:role/CrossAccountRole \
    --assume_profile other-account

# After the first time, the role ARN is saved
$ aws-cli-mfa --mfa 123456 --assume_profile other-account

# Now you can use the assumed role
$ aws s3 ls --profile other-account
```

## How It Works

1. Authenticates using your base credentials (`${profile}-default`) with MFA
2. Stores temporary session credentials in `${profile}`
3. If role assumption is requested, assumes the role and stores those credentials in `${assume_profile}`

## License

MIT
