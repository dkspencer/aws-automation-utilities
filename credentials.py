import os

from botocore.exceptions import ClientError

import boto3
from lib import assume_role, get_account_list, save_output


def lambda_handler(event, context):
    """ Runs through a list of AWS accounts stored in a csv file (created via
    accounts.py) and generates a credential report per account and saves them in
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

    accounts_list = list()

    try:

        accounts_response = get_account_list.main(
            os.environ['bucket'], os.environ['account'], os.environ['role'])

        if not accounts_response:
            return "No accounts list to use"

        for account in accounts_response:
            print(f'Processing account: {account}')

            # Assume a role in the account.
            temp_keys = assume_role.main(account, os.environ['role'])

            local_session = boto3.Session(
                aws_access_key_id=temp_keys['AccessKeyId'],
                aws_secret_access_key=temp_keys['SecretAccessKey'],
                aws_session_token=temp_keys['SessionToken'],
            )

            iam_session = local_session.client('iam')

            # Execute the AWS generate credential report tool.
            iam_session.generate_credential_report()

            # This can take awhile depending on how many users there are per account
            while True:
                try:
                    get_report = iam_session.get_credential_report()
                    report = get_report['Content']
                    break
                except ClientError:
                    pass

            file_name = f'Credentials-{account}.csv'

            save_output.main(
                report, file_name, os.environ['bucket'], os.environ['account'], os.environ['role'])

    except Exception as e:
        print(f'Exception in the credentials utility: {e}')
