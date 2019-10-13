import os

import boto3
from datatime import datetime
from lib import assume_role, get_account_list, save_output


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

    accounts_list = list()
    report = dict()

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

            ec2_session = local_session.client('ec2')
            addresses = ec2_session.describe_addresses()

            # Gather the association and disassociation events from CloudTrail
            cloudtrail_session = local_session.client('cloudtrail')

            association_events = cloudtrail_session.lookup_events(LookupAttributes=[
                {
                    'AttributeKey': 'EventName',
                    'AttributeValue': 'AssociateAddress'
                }
            ])

            disassociation_events = cloudtrail_session.lookup_events(LookupAttributes=[
                {
                    'AttributeKey': 'EventName',
                    'AttributeValue': 'DisassociateAddress'
                }
            ])

            events = []

            if 'Events' in association_events:
                events = list(association_events['Events'])

            if 'Events' in disassociation_events:
                events.extend(disassociation_events['Events'])

            ips = dict()

            for address in addresses['Addresses']:
                external_ip = address['PublicIp']

                if external_ip not in ips:
                    ips.update({external_ip: {}})

                if 'AllocationId' in address:
                    allocation_id = address['AllocationId']

                    for event in events:

                        if 'EventTime' in event:
                            event_time = event['EventTime']

                            event_name = event['EventName']

                            if event_name == 'DisassociateAddress':
                                ips.update({external_ip: {
                                    event['EventName']: {"Time": event_time.strftime("%H:%M:%S : %d-%m-%y")}}})

                            elif event_name == 'AssociateAddress':

                                for resource in event['Resources']:
                                    resource_type = resource['ResourceType']

                                    if resource_type == 'AWS::EC2::EIP':
                                        resource_name = resource['ResourceName']

                                        if allocation_id in resource_name:

                                            for resources in event['Resources']:

                                                if 'AWS::EC2::Instance' in resources['ResourceType']:
                                                    resource_name = resources['ResourceName']

                                                    if ips.get(external_ip):

                                                        ips.get(external_ip).update({
                                                            event['EventName']: {
                                                                "Time": event_time.strftime("%H:%M:%S : %d-%m-%y"),
                                                                "EC2 Instance": resource_name}})

                                                    else:
                                                        ips.update({external_ip: {
                                                            event['EventName']: {
                                                                "Time": event_time.strftime("%H:%M:%S : %d-%m-%y"),
                                                                "EC2 Instance": resource_name}}})
            report.update(
                {
                    account:
                        {
                            "IPS": ips
                        }
                })

            session_elb = local_session.client('elbv2')
            elb = session_elb.describe_load_balancers()

            interfaces = ec2.describe_network_interfaces()

            for interfaces in interfaces['NetworkInterfaces']:
                if 'Groups' in interfaces:
                    for groups in interfaces['Groups']:
                        sg_group = groups['GroupId']

                        if get_security_groups(elb, sg_group, interfaces):

                            for addresses in interfaces['PrivateIpAddresses']:

                                if 'Association' in addresses:

                                    if 'PublicIp' in addresses['Association']:

                                        external_ip = addresses['Association']['PublicIp']

                                        if external_ip not in ips:
                                            ips.update({external_ip: {}})

                                            ips.update({external_ip: {
                                                "LoadBalancer": get_security_groups(elb, sg_group, interfaces)
                                            }})

            save_output.main(
                report, os.environ['elastic_ip'], os.environ['bucket'], os.environ['account'], os.environ['role'])


def get_security_groups(elb, sg_group, interfaces):
    """ Retrieve Load Balancer data associated with the network interface.

    Parameters
    ----------
    elb : dict
        The response from Boto3 describe load balancers function.
    sg_group : dict
        The security group id associated with the network interface.
    interfaces : dict
        The network interface.

    Returns
    -------
    string
        The name of the Load Balancer

    """

    for x in elb:
        if elb['LoadBalancers']:

            for address in elb['LoadBalancers']:

                if "internet-facing" in address['Scheme']:

                    elb_name = address['LoadBalancerName']

                    if 'SecurityGroups' in address:

                        for groups in address['SecurityGroups']:
                            securitygroup = groups

                            for addresses in interfaces['PrivateIpAddresses']:

                                if sg_group == securitygroup:
                                    return elb_name
                                else:
                                    pass
