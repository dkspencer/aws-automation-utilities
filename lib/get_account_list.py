import json

import boto3
from lib import assume_role


def main(bucket_name, account_number, role_name):
    """ Retrieves the accounts list from the specified S3 bucket.

    Parameters
    ----------
    bucket_name : string
        The S3 bucket name where the accounts list is stored.
    account_number : int
        The account number where the bucket lives.
    role_name : string
        The name of the role in the account to assume.

    Returns
    -------
    dict
        A dictionary of the accounts.

    """

    temp_keys = assume_role.main(account_number, role_name)

    local_session = boto3.Session(
        aws_access_key_id=temp_keys['AccessKeyId'],
        aws_secret_access_key=temp_keys['SecretAccessKey'],
        aws_session_token=temp_keys['SessionToken'],
    )

    s3 = local_session.resource('s3')

    content_object = s3.Object(bucket_name, 'accounts.json')

    file_content = content_object.get()['Body'].read().decode('utf-8')
    accounts_json = json.loads(file_content)

    return (accounts_json)
