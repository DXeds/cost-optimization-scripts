import boto3
import csv
from botocore.exceptions import ClientError, BotoCoreError

# Configurações
SSO_PROFILE = 'inserir-profile-sso' #configurar via aws configure sso
MASTER_ROLE_NAME = 'darede'
MASTER_ACCOUNT_ID = '466911142877' #conta payer da organização

boto3.setup_default_session(profile_name=SSO_PROFILE)
sts_client = boto3.client('sts')

def assume_role(account_id, role_name):
    try:
        assumed_role = sts_client.assume_role(
            RoleArn=f'arn:aws:iam::{account_id}:role/{role_name}',
            RoleSessionName=f'{role_name}_session'
        )
        return assumed_role['Credentials']
    except ClientError as e:
        print(f"Erro ao assumir o papel na conta {account_id}: {e}")
        return None

def fetch_volumes_from_stopped_instances(ec2_client):
    ebs_volumes_info = []
    try:
        instances = ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['stopped']}])

        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                for block_device in instance.get('BlockDeviceMappings', []):
                    volume_id = block_device['Ebs']['VolumeId']
                    volume_info = ec2_client.describe_volumes(VolumeIds=[volume_id])['Volumes'][0]
                    info = {
                        'InstanceId': instance['InstanceId'],
                        'VolumeId': volume_info['VolumeId'],
                        'Size': volume_info['Size'],
                        'State': volume_info['State'],
                        'AvailabilityZone': volume_info['AvailabilityZone']
                    }
                    ebs_volumes_info.append(info)
    except (BotoCoreError, ClientError) as e:
        print(f"Erro ao obter informações dos volumes EBS: {e}")
    return ebs_volumes_info

if __name__ == '__main__':
    master_credentials = assume_role(MASTER_ACCOUNT_ID, MASTER_ROLE_NAME)
    if master_credentials is None:
        print("Falha ao assumir o papel da conta mestre.")
        exit(1)

    org_client = boto3.client(
        'organizations',
        aws_access_key_id=master_credentials['AccessKeyId'],
        aws_secret_access_key=master_credentials['SecretAccessKey'],
        aws_session_token=master_credentials['SessionToken']
    )

    accounts = org_client.list_accounts()['Accounts']

    with open('ebs_volumes_from_stopped_instances.csv', 'w', newline='') as csvfile:
        fieldnames = ['Account_ID', 'Account_Name', 'Region', 'InstanceId', 'VolumeId', 'Size', 'State', 'AvailabilityZone']
        csvwriter = csv.DictWriter(csvfile, fieldnames=fieldnames)
        csvwriter.writeheader()

        for account in accounts:
            account_id = account['Id']
            account_name = account['Name']

            assumed_credentials = assume_role(account_id, MASTER_ROLE_NAME)
            if assumed_credentials is None:
                continue

            ec2_client = boto3.client(
                'ec2',
                aws_access_key_id=assumed_credentials['AccessKeyId'],
                aws_secret_access_key=assumed_credentials['SecretAccessKey'],
                aws_session_token=assumed_credentials['SessionToken']
            )

            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

            for region in regions:
                ec2_region_client = boto3.client(
                    'ec2',
                    region_name=region,
                    aws_access_key_id=assumed_credentials['AccessKeyId'],
                    aws_secret_access_key=assumed_credentials['SecretAccessKey'],
                    aws_session_token=assumed_credentials['SessionToken']
                )

                ebs_volumes = fetch_volumes_from_stopped_instances(ec2_region_client)
                for volume in ebs_volumes:
                    csvwriter.writerow({
                        'Account_ID': account_id,
                        'Account_Name': account_name,
                        'Region': region,
                        'InstanceId': volume['InstanceId'],
                        'VolumeId': volume['VolumeId'],
                        'Size': volume['Size'],
                        'State': volume['State'],
                        'AvailabilityZone': volume['AvailabilityZone']
                    })

    print("CSV com informações dos volumes EBS de instâncias interrompidas gerado com sucesso!")
