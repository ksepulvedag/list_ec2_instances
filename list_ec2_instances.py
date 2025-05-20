from time import time, sleep
import webbrowser
from boto3.session import Session
import boto3
import os
import pandas as pd
import argparse

# Modify
start_url = 'https://xxxxx.awsapps.com/start/#'
region = 'us-xxxx-x'
accepted_roles = ['rolename1', 'rolename2', 'rolename3']

######## Do not touch ########
auth_region_name="us-east-1" #
##############################
# SSO runs in us-east-1


def configure_session(start_url):
    session = Session()
    sso_oidc = session.client('sso-oidc', region_name=auth_region_name)
    client_creds = sso_oidc.register_client(
        clientName='listEc2Instances', 
        clientType='public',
    )
    device_authorization = sso_oidc.start_device_authorization(
        clientId=client_creds['clientId'],
        clientSecret=client_creds['clientSecret'],
        startUrl=start_url,
    )

    url = device_authorization['verificationUriComplete']
    device_code = device_authorization['deviceCode']
    expires_in = device_authorization['expiresIn']
    interval = device_authorization['interval']

    print(f"Please verify user code shown in web browser: {device_authorization['userCode']}")
    webbrowser.open(url, autoraise=True)
    for n in range(1, expires_in // interval + 1):
        sleep(interval)
        try:
            token = sso_oidc.create_token(
                grantType='urn:ietf:params:oauth:grant-type:device_code',
                deviceCode=device_code,
                clientId=client_creds['clientId'],
                clientSecret=client_creds['clientSecret'],
            )
            break
        except sso_oidc.exceptions.AuthorizationPendingException:
            pass

    return token['accessToken']


def get_accounts_ids(access_token):

    try:
        sso_client = boto3.client('sso', region_name=auth_region_name)
        paginator = sso_client.get_paginator('list_accounts')
        
        account_ids = []
        for page in paginator.paginate(accessToken=access_token):
            for account in page['accountList']:
                new_data = {
                    'accountId': account['accountId'],
                    'accountName': account['accountName']
                }
                account_ids.append(new_data)

        return account_ids
    except Exception as e:
        print(f"Failed to list accounts. Error: {str(e)}")
        return None
    finally:
        sso_client.close()


def get_sso_credentials(access_token, account_id, accepted_roles):
    sso_client = boto3.client('sso', region_name=auth_region_name,)
    role_name = ''

    # Get list of roles for the account
    try:
        account_roles = sso_client.list_account_roles(
            accessToken=access_token,
            accountId=account_id,
        )

        for role in account_roles['roleList']:
            if role['roleName'] in accepted_roles:
                role_name = role['roleName']
                print(f"Role found {role_name} for account {account_id}")
            
        if not role_name:
            print(f"No role found for account {account_id}, check accepted_roles")
            return None
    except Exception as e:
        print(f"Failed to get list of roles for account {account_id}. Error: {str(e)}")
        return None
    finally:
        sso_client.close()

    try:
        credentials = sso_client.get_role_credentials(
            accountId=account_id,
            accessToken=access_token,
            roleName=role_name,
        )
        return credentials['roleCredentials']
    except Exception as e:
        print(f"Failed to get credentials for account {account_id}. Error: {str(e)}")
        return None
    finally:
        sso_client.close()


def describe_instance_properties(session, instance_id):
    try:
        ssm_client = session.client('ssm', region_name=region)

        response = ssm_client.describe_instance_information(
            InstanceInformationFilterList=[
                {
                    'key': 'InstanceIds',
                    'valueSet': [
                        instance_id,
                    ]
                },
            ]
        )
        return response
    except Exception as e:
        print(f"Can not list properties for instance '({instance_id})'. Error: {str(e)}")
    finally:
        ssm_client.close()


def list_ec2_instances_in_account(session, account_id, account_name, csv_file_name):
    try:
        ec2_client = session.client('ec2', region_name=region)
        paginator = ec2_client.get_paginator('describe_instances')

        instances = []
        for page in paginator.paginate():
            for Reservation in page['Reservations']:

                RequesterId = ""
                if 'RequesterId' in Reservation:
                    RequesterId = Reservation['RequesterId']

                for instance in Reservation['Instances']:
                    instance_properties = describe_instance_properties(session, instance['InstanceId'])

                    desired_states = ['running', 'stopped', 'pending', 'stopping']
                    if instance['State']['Name'] in desired_states:
                        new_data = {
                            'InstanceId': instance['InstanceId'],
                            'PlatformType': instance_properties['InstanceInformationList'][0]['PlatformType'] if instance_properties['InstanceInformationList'] and "PlatformType" in instance_properties['InstanceInformationList'][0] != "" else instance['PlatformDetails'],
                            'PlatformName': instance_properties['InstanceInformationList'][0]['PlatformName'] if instance_properties['InstanceInformationList'] and "PlatformName" in instance_properties['InstanceInformationList'][0] != "" else "",
                            'PlatformVersion': instance_properties['InstanceInformationList'][0]['PlatformVersion'] if instance_properties['InstanceInformationList'] and "PlatformVersion" in instance_properties['InstanceInformationList'][0] != "" else "",
                            'ImageId': instance['ImageId'],
                            'State': instance['State']['Name'],
                            'ASG': RequesterId if RequesterId != "" else 'na',
                            'IPAddress': instance_properties['InstanceInformationList'][0]['IPAddress'] if instance_properties['InstanceInformationList'] else instance['PrivateIpAddress'],
                            'Hostname': instance_properties['InstanceInformationList'][0]['ComputerName'] if instance_properties['InstanceInformationList'] else instance['PrivateDnsName'],
                            'SSM': 'Si' if instance_properties['InstanceInformationList'] else 'No',
                            'SecurityId': instance["NetworkInterfaces"][0]["Groups"][0]["GroupId"] if instance["NetworkInterfaces"][0]["Groups"][0]["GroupId"] else 'na',
                            'SecurityName': instance["NetworkInterfaces"][0]["Groups"][0]["GroupName"] if instance["NetworkInterfaces"][0]["Groups"][0]["GroupName"] else 'na',
                            'InstanceRegion': region
                        }
                        instances.append(new_data)

        csv_file = f'./{csv_file_name}'
        columns = ['AccountName', 'AccountId', 'InstanceId', 'PlatformType', 'PlatformName', 'PlatformVersion',
                   'ImageId', 'State', 'ASG', 'IPAddress', 'Hostname', 'SSM', "SecurityId", "SecurityName", "InstanceRegion"]

        save_instance_tocsv(account_id, account_name, csv_file, columns, instances)
    except Exception as e:
        print(f"Can not list instances in account '{account_name}' '({account_id})' '({instance['InstanceId']})'. Error: {str(e)}")
    finally:
        ec2_client.close()


def save_instance_tocsv(account_id, account_name, csv_file, columns, instances):
        if os.path.exists(csv_file):
            header = False
        else:
            header = True

        # Validate if the response is empty
        if not instances:
            mode = 'w' if header else 'a'
            instance = 'No ec2 instances found'
            df = pd.DataFrame([[account_name, account_id, instance, "", "", "", "", "", "", "", "", "", "", "", ""]], columns=columns)
            df.to_csv(csv_file, encoding='utf-8', mode=mode, header=header, index=False)
            print(f"No ec2 instances found for '{account_name}' '({account_id})'")
            return

        for instance in instances:
            mode = 'w' if header else 'a'
            df = pd.DataFrame([[account_name, account_id, instance['InstanceId'], instance['PlatformType'], instance['PlatformName'], instance['PlatformVersion'],
                                instance['ImageId'], instance['State'], instance['ASG'], instance['IPAddress'], 
                                instance['Hostname'], instance['SSM'], instance['SecurityId'], instance['SecurityName'],  instance['InstanceRegion']]],
                                columns=columns)
            df.to_csv(csv_file, encoding='utf-8', mode=mode, header=header, index=False)
            header = False
        print(f"EC2 instances for '{account_name}' '({account_id})' saved in file '{csv_file}'")


def main():
    
    parser = argparse.ArgumentParser(description='Name of the CSV file where to export ec2 instances info.')
    parser.add_argument('--csv-file-name', required=True, help='Name of the CSV file')
    args = parser.parse_args()

    access_token=configure_session(start_url)
    accounts = get_accounts_ids(access_token)
    count = 1

    print(f"{len(accounts)} accounts found")

    for account in accounts:
        print(f"{count}/{len(accounts)}")
        print(f"Checking access to the account {account['accountName']} '({account['accountId']})'...")
        credentials = get_sso_credentials(access_token, account['accountId'], accepted_roles)
        if credentials:
            session = Session(
                region_name=region,
                aws_access_key_id=credentials['accessKeyId'],
                aws_secret_access_key=credentials['secretAccessKey'],
                aws_session_token=credentials['sessionToken'],
            )
            list_ec2_instances_in_account(session, account['accountId'], account['accountName'], args.csv_file_name)
        else:
            print(f"No access to the account {account['accountName']} '({account['accountId']})'")
        print()
        count += 1


if __name__ == "__main__":
    main()
