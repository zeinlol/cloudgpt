import csv
import json
import os
import random
import re
from datetime import datetime, timezone

import boto3
import openai
from botocore.exceptions import ProfileNotFound, ClientError

from core.arguments import cli_arguments
from core.policy import *

openai.api_key = ''


def redact_policy(policy):
    new_policy = policy
    new_policy.original_document = str(policy.policy)

    if match := re.search(r'\b\d{12}\b', new_policy.original_document):
        original_account = match.group()
        new_account = random.randint(100000000000, 999999999999)
        new_policy.map_accounts(original_account, new_account)
        new_policy.redacted_document = new_policy.original_document.replace(original_account, str(new_account))
    else:
        new_policy.redacted_document = new_policy.original_document

    return new_policy


def check_policy(policy):
    prompt = f'Does this AWS policy have any security vulnerabilities: \n{policy.redacted_document}'
    response = openai.Completion.create(
        model="text-davinci-003",
        prompt=prompt,
        temperature=0.5,
        max_tokens=1000,
        top_p=1,
        frequency_penalty=0.0,
        presence_penalty=0.0,
        stream=False,
    )
    policy.ai_response = response.choices[0]['text'].strip()
    is_vulnerable = policy.is_vulnerable()
    log(f'Policy {policy.name} [{is_vulnerable}]')

    return policy


def preserve(filename: str, results: list[Policy]):
    header = ['account', 'name', 'arn', 'version', 'vulnerable', 'policy', 'mappings']
    mode = 'a' if os.path.exists(filename) else 'w'

    log(f'Saving scan: {filename}')

    with open(filename, mode) as f:
        if cli_arguments.json:
            json.dump(results, f, indent=2)
        else:
            writer = csv.DictWriter(f, fieldnames=header)
            if mode == 'w':
                writer.writeheader()
                for policy in results:
                    mappings = '' if len(policy.retrieve_mappings()) == 0 else policy.retrieve_mappings()
                    row = {
                        'account': policy.account, 'name': policy.name, 'arn': policy.arn,
                        'version': policy.version, 'vulnerable': policy.ai_response, 'policy':
                            policy.original_document, 'mappings': mappings
                    }
                    writer.writerow(row)


def log(data):
    print(f'[*] {data}')


def main():
    results = []
    openai.api_key = cli_arguments.key
    credentials = {}
    if cli_arguments.amazon_key:
        credentials['aws_access_key_id'] = cli_arguments.amazon_key
    if cli_arguments.secret_key:
        credentials['aws_secret_access_key'] = cli_arguments.secret_key
    if cli_arguments.token:
        credentials['aws_session_token'] = cli_arguments.token
    if cli_arguments.profile:
        credentials['profile_name'] = cli_arguments.profile
    if cli_arguments.region:
        credentials['region_name'] = cli_arguments.region
    try:
        session = boto3.session.Session(**credentials)
    except ProfileNotFound:
        log(f'Profile {cli_arguments.profile} not found. Validate aws credentials or setup')
        exit(1)

    scan_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%MZ")

    client = session.client('iam')
    account = session.client('sts').get_caller_identity().get('Account')
    log(f'Retrieving and redacting policies for account: {account}')

    paginator = client.get_paginator('list_policies')
    try:
        response_iterator = paginator.paginate(Scope='Local', OnlyAttached=False)
        for response in response_iterator:
            policies_raw = response['Policies']
            if len(policies_raw) < 0:
                log('Could not find Local polices')
                continue
            for policy in policies_raw:

                policy_name = policy['PolicyName']

                policy_arn = policy['Arn']
                policy_version = client.get_policy_version(PolicyArn=policy_arn, VersionId=policy['DefaultVersionId'])
                default_version = policy_version['PolicyVersion']['VersionId']

                if not policy_arn.startswith("arn:aws:iam::aws"):
                    p = Policy(
                        account=account,
                        arn=policy_arn,
                        name=policy_name,
                        policy=policy_version['PolicyVersion']['Document'],
                        version=default_version,
                    )
                    if cli_arguments.redact:
                        p = redact_policy(p)
                        p = check_policy(p)

                    results.append(p)
    except ClientError as e:
        log(e.__str__())
        exit(2)
    output_file = cli_arguments.output or f'cache/{account}_{scan_utc}.csv'
    preserve(output_file, results)


if __name__ == '__main__':
    main()
