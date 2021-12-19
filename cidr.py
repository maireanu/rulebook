#!/usr/bin/env python

import os
import sys
import json
import argparse
import logging
import boto3
import googleapiclient.discovery
from google.oauth2 import service_account
from pprint import pprint
from botocore.exceptions import ClientError
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.v2017_03_01.models import NetworkSecurityGroup
from azure.mgmt.network.v2017_03_01.models import SecurityRule
from azure.mgmt.resource.resources import ResourceManagementClient



class CidrRule(object):
    def __init__(self, idRule, way, network, ipProtocol, fromPort, toPort):
        self.idRule = idRule
        # ingress, egress
        self.way = way
        # network 209.170.113.98/31
        self.network = network
        # IP Protocol TCP
        self.ipProtocol = ipProtocol
        # From PORT
        self.fromPort = fromPort
        # TO PORT
        self.toPort = toPort


    def get_staging_cidr(filename):
        rules = {}
        with open(filename) as f:
            # remove header lines
            header = f.pop(0)
            for line in f:
                row = line.strip(',')
                if len(row) < 6:
                    continue
                idRule, way, network, ipProtocol, fromPort, toPort = [index.strip() for index in row]
                rule = cidrRules.get(idRule, CidrRule(idCidr, way, network, ipProtocol, fromPort, toPort))
        return rule


def add_cidr_rule_azure():

    new_cidrRule = get_staging_cidr(azure_rule_list.csv)

    subscription_id = 'xxxxxxxxx-xxxxxxxxxxxxxxxxxxxx'
    credentials = ServicePrincipalCredentials(
        client_id = 'xxxxxx-xxxx-xxx-xxxx-xxxxxxx',
        secret = 'xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxx',
        tenant = 'xxxxxx-xxxxxxx'
    )

    compute_client = ComputeManagementClient(
        credentials,
        subscription_id
    )

    network_client = NetworkManagementClient(
        credentials,
        subscription_id
    )

    resource_client = ResourceManagementClient(
        credentials,
        subscription_id
    )
    resource_client.providers.register('Microsoft.Compute')
    resource_client.providers.register('Microsoft.Network')

    resource_group_name = 'cirdRule'


    parameters = NetworkSecurityGroup()
    parameters.location = 'US East'

    parameters.security_rules = [SecurityRule('new_cidrRule.ipProtocol', 'new_cidrRule.network', 'new_cidrRule.network', 'Allow', 'new_cidrRule.way', description='Test new CIDR rule',source_port_range='new_cidrRule.fromPort', destination_port_range='new_cidrRule.toPort', priority=100, name='new_cidrRule.idRule')]


def add_cidr_rule_aws():

        new_cidrRule = get_staging_cidr(aws_rule_list.csv)

        ec2 = boto3.client('ec2')
        response = ec2.describe_vpcs()
        vpc_id = response.get('Vpcs', [{}])[0].get('VpcId', '')

        try:
        response = ec2.create_security_group(GroupName='SECURITY_GROUP_NAME_TEST',
                                             Description='DESCRIPTION_AWS_TEST',
                                             VpcId=vpc_id_test)
        security_group_id = response['GroupIdTest']
        print('Security Group Created %s in vpc %s.' % (security_group_id, vpc_id))

        data = ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[
                {'IpProtocol': 'new_cidrRule.ipProtocol',
                 'FromPort': new_cidrRule.fromPort,
                 'ToPort': new_cidrRule.toPort,
                 'IpRanges': [{'CidrIp': 'new_cidrRule.network'}]}
            ])
        print('Ingress Successfully Set %s' % data)
        except ClientError as e:
        print(e)

def cidr_main():

    # Create a security group and allow SSH inbound rule through the VPC

    add_cidr_rule_aws()
    add_cidr_rule_azure()

if __name__ == '__main__':
    cidr_main()