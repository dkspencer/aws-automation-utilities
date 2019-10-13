import boto3


def main(account_number, role_name, session_name="AutomationUtility", duration=900):
    """ Assumes a role in an AWS account.

    Parameters
    ----------
    account_number : int
        The destination accounts number.
    role_name : string
        The name of the role, found after :role/<your role name>.
    session_name : string
        This tool description will be shown in Cloudtrail logs.
    duration : int
        How long to assume the role before logging out.

    Returns
    -------
    dict
        The roles credentials, including access keys and a session token.

    """

    sts = boto3.client('sts')

    role_arn = "arn:aws:iam::" + account_number + ":role/" + role_name

    assume_role = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        DurationSeconds=duration
    )

    temp_keys = assume_role['Credentials']

    return (temp_keys)
