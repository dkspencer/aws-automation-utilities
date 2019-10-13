import json

import assume_role
import boto3


def main(file_contents, file_name, bucket_name, account_number, role_name):
    """ Save the tools output to S3.

    Parameters
    ----------
    file_contents : dict
        The dict output from the tools.
    file_name : type
        The file name to save the output as.
    bucket_name : type
        The bucket name to save the file to.
    account_number : type
        The account number of the S3 bucket.
    role_name : type
        The role to assume to save the output to S3.

    """

    temp_keys = assume_role.main(account_number, role_name)

    local_session = boto3.Session(
        aws_access_key_id=temp_keys['AccessKeyId'],
        aws_secret_access_key=temp_keys['SecretAccessKey'],
        aws_session_token=temp_keys['SessionToken'],
    )

    s3 = local_session.resource('s3')

    output_file = s3.Object(bucket_name, file_name)

    if "json" in file_name:
        output_dump = json.dumps(file_contents)
        output_file.put(Body=output_dump)
    else:
        output_file.put(Body=file_contents)
