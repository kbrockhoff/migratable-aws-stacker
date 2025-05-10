# Bastion Stack
#
# These hosts are the only SSH entrypoint into the VPC. To SSH to a host inside
# the VPC you must first SSH to a bastion host, and then SSH from that host to
# another inside the VPC.

from troposphere import Ref, ec2, autoscaling, FindInMap, Output, kms, GetAtt, AWS_ACCOUNT_ID, Join, iam
import boto3
import base64

from stacker.blueprints.base import Blueprint
from stacker.blueprints.variables.types import (
    CFNNumber,
    CFNString,
    EC2VPCId,
)


class Bastion(Blueprint):
    VARIABLES = {
        "Environment": {
            "type": str,
            "description": "Environment name (e.g., development-blue)",
        },
        "NamePrefix": {
            "type": str,
            "description": "Prefix for resource names (e.g., bkff-demo)",
        },
        "VpcId": {"type": EC2VPCId, "description": "Vpc Id"},
        "InstanceType": {"type": CFNString,
                         "description": "EC2 Instance Type",
                         "default": "t3.micro"},
        "MinSize": {"type": CFNNumber,
                    "description": "Minimum # of instances.",
                    "default": "1"},
        "MaxSize": {"type": CFNNumber,
                    "description": "Maximum # of instances.",
                    "default": "5"},
        "ImageName": {
            "type": CFNString,
            "description": "The image name to use from the AMIMap (usually "
                           "found in the config file.)",
            "default": "bastion"},
        "Tags": {
            "type": dict,
            "description": "Dictionary of tags to apply to the KMS key",
            "default": {
                "ck-costcenter": "N/A",
                "ck-confidentiality": "N/A",
                "ck-project": "N/A",
                "ck-dataowners": "N/A",
                "ck-codeowners": "N/A",
                "ck-privacyreview": "N/A",
                "ck-securityreview": "N/A",
                "ck-projectowners": "N/A",
                "ck-dataregulations": "N/A",
                "ck-availability": "N/A",
                "ck-deployer": "N/A",
                "ck-deletiondate": "N/A"
            }
        }
    }

    def create_security_groups(self, vpc_info):
        t = self.template
        variables = self.get_variables()
        
        # Create security group rules based on VPC information
        sg_rules = []
        
        # Allow all traffic within VPC CIDR
        sg_rules.append(
            ec2.SecurityGroupRule(
                IpProtocol='-1',  # All protocols
                FromPort=-1,
                ToPort=-1,
                CidrIp=vpc_info['vpc']['CidrBlock']
            )
        )

        # Allow HTTPS outbound to internet
        sg_rules.append(
            ec2.SecurityGroupRule(
                IpProtocol='tcp',
                FromPort=443,
                ToPort=443,
                CidrIp='0.0.0.0/0'
            )
        )
        
        # Create tags list from variables
        tags = []
        # Add default tags
        for key, value in variables["Tags"].items():
            tags.append({"Key": key, "Value": value})
        # Add Name tag
        tags.append({
            "Key": "Name", "Value": f"{variables['NamePrefix']}-sg",
            "Key": "ck-environment", "Value": f"{variables['Environment']}"
        })
        
        # Create the security group
        sg = t.add_resource(
            ec2.SecurityGroup(
                'BastionSecurityGroup',
                GroupDescription=f"Security group for {variables['NamePrefix']} bastion host.",
                SecurityGroupEgress=sg_rules,
                VpcId=Ref("VpcId"),
                Tags=tags
            )
        )

        # Add output for the security group
        t.add_output(
            Output(
                'SecurityGroup',
                Description='The ID of the bastion security group',
                Value=Ref(sg)
            )
        )

        # Add output for the security group name
        t.add_output(
            Output(
                'SecurityGroupName',
                Description='The name of the bastion security group',
                Value=GetAtt(sg, 'GroupName')
            )
        )

    def create_iam_role(self):
        t = self.template
        variables = self.get_variables()
        
        # Create tags list from variables
        tags = []
        # Add default tags
        for key, value in variables["Tags"].items():
            tags.append({"Key": key, "Value": value})
        # Add Name tag
        tags.append({
            "Key": "Name", "Value": f"{variables['NamePrefix']}-role",
            "Key": "ck-environment", "Value": f"{variables['Environment']}"
        })

        # Create IAM Role
        role = t.add_resource(
            iam.Role(
                'BastionRole',
                AssumeRolePolicyDocument={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "Service": ["ec2.amazonaws.com"]
                            },
                            "Action": ["sts:AssumeRole"]
                        }
                    ]
                },
                ManagedPolicyArns=[
                    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
                    "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
                ],
                Description=f"IAM role for {variables['NamePrefix']}",
                Tags=tags,
                Policies=[
                    iam.Policy(
                        PolicyName="KMSAccess",
                        PolicyDocument={
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "kms:Encrypt",
                                        "kms:Decrypt",
                                        "kms:ReEncrypt*",
                                        "kms:GenerateDataKey*",
                                        "kms:DescribeKey"
                                    ],
                                    "Resource": "*"
                                }
                            ]
                        }
                    )
                ]
            )
        )

        # Create Instance Profile
        instance_profile = t.add_resource(
            iam.InstanceProfile(
                'BastionInstanceProfile',
                Roles=[Ref(role)],
                Path="/"
            )
        )

        # Add Outputs
        t.add_output(
            Output(
                "BastionRoleArn",
                Description="The ARN of the bastion IAM role",
                Value=GetAtt(role, "Arn")
            )
        )

        t.add_output(
            Output(
                "BastionInstanceProfileArn",
                Description="The ARN of the bastion instance profile",
                Value=GetAtt(instance_profile, "Arn")
            )
        )

    def create_kms_key(self):
        t = self.template
        variables = self.get_variables()
        
        # Create tags list from variables
        tags = []
        # Add default tags
        for key, value in variables["Tags"].items():
            tags.append({"Key": key, "Value": value})
        # Add Name tag
        tags.append({
            "Key": "Name", "Value": f"{variables['NamePrefix']}-ssm",
            "Key": "ck-environment", "Value": f"{variables['Environment']}"
        })

        # Create KMS Key
        kms_key = t.add_resource(
            kms.Key(
                "KMSKey",
                UpdateReplacePolicy="Retain",
                DeletionPolicy="Delete",
                Origin="AWS_KMS",
                MultiRegion=False,
                Description="KMS key for SSM sessions",
                KeyPolicy={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Resource": "*",
                            "Action": "kms:*",
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": Join("", ["arn:aws:iam::", Ref(AWS_ACCOUNT_ID), ":root"])
                            }
                        }
                    ]
                },
                KeySpec="SYMMETRIC_DEFAULT",
                Enabled=True,
                EnableKeyRotation=True,
                KeyUsage="ENCRYPT_DECRYPT",
                Tags=tags
            )
        )

        # Create KMS Alias
        kms_alias = t.add_resource(
            kms.Alias(
                "BasitionKMSAlias",
                AliasName=f"alias/{variables['NamePrefix']}-ssm",
                TargetKeyId=Ref(kms_key)
            )
        )

        # Add Outputs
        t.add_output(
            Output(
                "KMSKeyId",
                Description="The ID of the KMS key",
                Value=Ref(kms_key)
            )
        )

        t.add_output(
            Output(
                "KMSKeyArn",
                Description="The ARN of the KMS key",
                Value=GetAtt(kms_key, "Arn")
            )
        )

        t.add_output(
            Output(
                "KMSAliasName",
                Description="The name of the KMS alias",
                Value=Ref(kms_alias)
            )
        )

    def generate_user_data(self):
        user_data = """#!/usr/bin/env bash
exec > >(tee /var/log/user-data.log | logger -t user-data -s 2>/dev/console) 2>&1

##
## Setup SSH Config
##
cat <<"__EOF__" > /home/ec2-user/.ssh/config
Host *
    StrictHostKeyChecking no
__EOF__
chmod 600 /home/ec2-user/.ssh/config
chown ec2-user:ec2-user /home/ec2-user/.ssh/config

##
## Enable SSM
##
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent
systemctl status amazon-ssm-agent

"""
        # Base64 encode the user data
        return base64.b64encode(user_data.encode()).decode()

    def lookup_vpc_info(self):
        """Lookup VPC information for the specified VPC ID."""
        ec2_client = boto3.client('ec2')
        
        try:
            # Get variables
            variables = self.get_variables()
            
            # Get the actual VPC ID value
            vpc_id = variables["VpcId"].to_parameter_value()
            
            # Get VPC information
            vpc_response = ec2_client.describe_vpcs(
                VpcIds=[vpc_id]
            )
            
            if not vpc_response['Vpcs']:
                raise ValueError(f"VPC {vpc_id} not found")
            
            vpc = vpc_response['Vpcs'][0]
            
            # Get subnet information
            subnet_response = ec2_client.describe_subnets(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}]
            )
            
            # Get security group information
            sg_response = ec2_client.describe_security_groups(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}]
            )
            
            return {
                'vpc': vpc,
                'subnets': subnet_response['Subnets'],
                'security_groups': sg_response['SecurityGroups']
            }
            
        except Exception as e:
            raise Exception(f"Error looking up VPC information: {str(e)}")

    def create_ec2_instance(self, vpc_info):
        t = self.template
        variables = self.get_variables()
        private_subnets = self.lookup_subnet_ids(vpc_info, 'private')
        
        # Create tags list from variables
        tags = []
        # Add default tags
        for key, value in variables["Tags"].items():
            tags.append({"Key": key, "Value": value})
        # Add Name tag
        tags.append({
            "Key": "Name", "Value": f"{variables['NamePrefix']}",
            "Key": "ck-environment", "Value": f"{variables['Environment']}"
        })

        # Create EC2 Instance
        instance = t.add_resource(
            ec2.Instance(
                'BastionInstance',
                ImageId=FindInMap(
                    'AmiMap', Ref("AWS::Region"), Ref("ImageName")),
                InstanceType=Ref("InstanceType"),
                UserData=self.generate_user_data(),
                SecurityGroupIds=[Ref('BastionSecurityGroup')],
                IamInstanceProfile=Ref('BastionInstanceProfile'),
                Tags=tags,
                SubnetId=private_subnets[0]  # Use first private subnet
            )
        )

        # Add Outputs
        t.add_output(
            Output(
                "InstanceId",
                Description="The ID of the EC2 instance",
                Value=Ref(instance)
            )
        )

        t.add_output(
            Output(
                "InstancePrivateIp",
                Description="The private IP address of the EC2 instance",
                Value=GetAtt(instance, "PrivateIp")
            )
        )

    def lookup_subnet_ids(self, vpc_info, network_tag):
        private_subnets = []
        subnets_info = vpc_info['subnets']
        for subnet in subnets_info:
            tags = subnet['Tags']
            # Find the tag with key 'ck-networktags'
            network_tag_value = next((tag['Value'] for tag in tags if tag['Key'] == 'ck-networktags'), None)
            if network_tag_value == network_tag:
                private_subnets.append(subnet['SubnetId'])
        return private_subnets

    def create_ebs_volume(self):
        t = self.template
        variables = self.get_variables()
        
        # Create tags list from variables
        tags = []
        # Add default tags
        for key, value in variables["Tags"].items():
            tags.append({"Key": key, "Value": value})
        # Add Name tag
        tags.append({
            "Key": "Name", "Value": f"{variables['NamePrefix']}-volume",
            "Key": "ck-environment", "Value": f"{variables['Environment']}"
        })

        # Create encrypted EBS volume
        volume = t.add_resource(
            ec2.Volume(
                'BastionVolume',
                Size=100,  # 100 GB
                VolumeType="gp3",
                Encrypted=True,
                KmsKeyId=Ref("KMSKey"),
                AvailabilityZone=GetAtt('BastionInstance', "AvailabilityZone"),
                Tags=tags
            )
        )

        # Attach volume to instance
        t.add_resource(
            ec2.VolumeAttachment(
                'BastionVolumeAttachment',
                Device="/dev/sdf",
                InstanceId=Ref('BastionInstance'),
                VolumeId=Ref(volume)
            )
        )

        # Add Outputs
        t.add_output(
            Output(
                "VolumeId",
                Description="The ID of the encrypted EBS volume",
                Value=Ref(volume)
            )
        )

    def create_ami_mapping(self):
        """Create the AMI mapping for different regions."""
        t = self.template
        
        t.add_mapping('AmiMap', {
            'us-east-1': {
                'bastion': 'ami-0c7217cdde317cfec'  # Amazon Linux 2023 AMI
            },
            'us-east-2': {
                'bastion': 'ami-0b0af3577fe5e3532'  # Amazon Linux 2023 AMI
            },
            'us-west-1': {
                'bastion': 'ami-0d382e80be7ffdae5'  # Amazon Linux 2023 AMI
            },
            'us-west-2': {
                'bastion': 'ami-0735c191cf914754d'  # Amazon Linux 2023 AMI
            }
        })

    def create_template(self):
        t = self.template
        
        # Add AMI mapping
        self.create_ami_mapping()
        
        # Lookup VPC information
        vpc_info = self.lookup_vpc_info()
        
        self.create_kms_key()
        self.create_iam_role()
        self.create_security_groups(vpc_info)
        self.create_ec2_instance(vpc_info)
        self.create_ebs_volume()
