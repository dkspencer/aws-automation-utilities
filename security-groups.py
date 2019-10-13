import os

import boto3
from datatime import datetime
from lib import assume_role, get_account_list, save_output

report = dict()


def lambda_handler(event, context):
    """ Runs through a list of AWS accounts stored in a csv file (created via
    accounts.py) and generates a dict of Elastic IPs, network interfaces and
    related data per account and saves it in a specified S3 bucket.

    NOTE: It's easier to have the same role name throughout all accounts.

    Parameters
    ----------
    event : object
        The event invoking the lambda. Should be CloudWatch.
    context : object
        Information about invocation, function and execution environment.

    """

    print(f'Incoming Event: {e}')

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

            ec2 = local_session.client('ec2')

            # Paginate over the result from the EC2 describe.
            paginator = ec2.get_paginator('describe_security_groups')
            security_groups = paginator.paginate()

            for security_group in security_groups:
                for groups in security_group['SecurityGroups']:
                    security_group_id = groups['GroupId']
                    security_group_name = groups['GroupName']

                    for permission in groups['IpPermissions']:

                        ip_permissions = dict()

                        if 'FromPort' in permission:
                            from_port = permission['FromPort']
                            to_port = permission['ToPort']

                            if from_port == to_port:
                                ports = str(from_port)
                            else:
                                ports = str(from_port) + " - " + str(to_port)

                            protocol = permission['IpProtocol']

                            ip_ranges = []

                            for ip in permission['IpRanges']:
                                ip_ranges.append(ip['CidrIp'])

                            ip_permissions.update({
                                "Ports": ports,
                                "Protocol": protocol.upper(),
                                "IPRanges": ip_ranges
                            })

                        create_dict(report, security_group_id,
                                    security_group_name, account, ip_permissions)

                nacls = ec2.describe_network_acls()

                for nacl in nacls['NetworkAcls']:

                    for x in nacl['Associations']:
                        report[account]['NetworkACLs'].append([x])

        save_output.main(
            report, os.environ['security_groups'], os.environ['bucket'], os.environ['account'], os.environ['role'])

    except Exception as e:
        print(f'Exception in security-groups utility: {e}')


def create_dict(security_group_id, security_group_name, account, ip_permissions):
    """ Creates a dictionary of the accounts security group results.

    Parameters
    ----------
    report : dict
        The overall report of the utility
    security_group_id : int
        The ID of the security group to be added to the report.
    security_group_name : string
        The name of the security grouo to be added to the report.
    account : int
        The ID of the account being processed.
    ip_permissions : object
        The security groups ingress and egress rules.

    """
    if account in report:

        if security_group_id in report[account]['SecurityGroups']:

            report[account]['SecurityGroups'][security_group_id]['IPPermissions'].append(
                [
                    ip_permissions
                ]
            )

        elif security_group_id not in report[account]['SecurityGroups']:

            report[account]['SecurityGroups'].update(
                {
                    security_group_id: {
                        "Name": security_group_name,
                        "IPPermissions": [ip_permissions]
                    }
                }
            )

    else:

        report.update(
            {
                account: {
                    "SecurityGroups": {
                        security_group_id: {
                            "Name": security_group_name,
                            "IPPermissions": [ip_permissions]
                        }
                    },
                    "NetworkACLs": []
                }
            }
        )
