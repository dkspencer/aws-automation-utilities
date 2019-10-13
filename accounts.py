import os

from botocore.exceptions import ClientError

import boto3
from lib import assume_role, get_account_list, save_output


def lambda_handler(event, context):
    """ Runs through a list of AWS accounts stored in a csv file (created via
    accounts.py) and generates a credential accounts_list per account and saves them in
    a specified S3 bucket.

    NOTE: It's easier to have the same role name throughout all accounts.

    Parameters
    ----------
    event : object
        The event invoking the lambda. Should be CloudWatch.
    context : object
        Information about invocation, function and execution environment.

    """

    print(f'Incoming Event: {e}')

    accounts_list = dict()

    try:
        print(f'Processing organisation account.')

        # Assume a role in the account.
        temp_keys = assume_role.main(
            os.environ['org_account'], os.environ['role'])

        local_session = boto3.Session(
            aws_access_key_id=temp_keys['AccessKeyId'],
            aws_secret_access_key=temp_keys['SecretAccessKey'],
            aws_session_token=temp_keys['SessionToken'],
        )

        organisations_session = local_session.client('organizations')
        paginator = organisations_session.get_paginator('list_accounts')
        accounts_paginator = paginator.paginate()

        for accounts in accounts_paginator:
            for account in accounts:
                accounts_list.update(
                    {
                        organization['Id']:
                            {
                                "ID": organization['Id'],
                                "Name": organization['Name'],
                                "Email": organization['Email'],
                                "Alias": ""
                        }
                    }
                )

        if os.environ['get_aliases']:
            accounts_list = get_account_aliases(file_contents)

        save_output.main(
            accounts_list, 'accounts.json', os.environ['bucket'], os.environ['account'], os.environ['role'])

    except Exception as e:
        print(f'Exception in the accounts utility: {e}')


def get_account_aliases(accounts_list):
    """ Assume roles in all accounts listed under the organisation and gather
    their account aliases.

    Parameters
    ----------
    accounts_list : dict
        A dict containing all accounts listed under the organisation.

    Returns
    -------
    dict
        An updated accounts_list dict containing account aliases.

    """

    for account in accounts_list:
        print(f'Processing account: {account}')

        # Assume a role in the account.
        temp_keys = assume_role.main(account, os.environ['role'])

        local_session = boto3.Session(
            aws_access_key_id=temp_keys['AccessKeyId'],
            aws_secret_access_key=temp_keys['SecretAccessKey'],
            aws_session_token=temp_keys['SessionToken'],
        )

        iam = local_session.client('iam')

        aliases = iam.list_account_aliases()

        alias = aliases['AccountAliases'][0]

        accounts_list[account]['Alias'] = alias

    return accounts_list
