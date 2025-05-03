# Bastion Stack
#
# These hosts are the only SSH entrypoint into the VPC. To SSH to a host inside
# the VPC you must first SSH to a bastion host, and then SSH from that host to
# another inside the VPC.

from troposphere import Ref, ec2, autoscaling, FindInMap, Output, kms, GetAtt, AWS_ACCOUNT_ID, Join, iam
from troposphere.autoscaling import Tag as ASTag
import boto3

from stacker.blueprints.base import Blueprint
from stacker.blueprints.variables.types import (
    CFNCommaDelimitedList,
    CFNNumber,
    CFNString,
    EC2KeyPairKeyName,
    EC2SecurityGroupId,
    EC2SubnetIdList,
    EC2VPCId,
)

CLUSTER_SG_NAME = "BastionSecurityGroup"


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
        "DefaultSG": {"type": EC2SecurityGroupId,
                      "description": "Top level security group."},
        "PrivateSubnets": {"type": EC2SubnetIdList,
                           "description": "Subnets to deploy private "
                                          "instances in."},
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
        for key, value in self.variables["Tags"].items():
            tags.append({"Key": key, "Value": value})
        # Add Name tag
        tags.append({
            "Key": "Name", "Value": f"{self.variables['NamePrefix']}-sg",
            "Key": "ck-environment", "Value": f"{self.variables['Environment']}"
        })
        
        # Create the security group
        sg = t.add_resource(
            ec2.SecurityGroup(
                f"{self.variables['NamePrefix']}-sg",
                GroupDescription=f"Security group for {self.variables['NamePrefix']} bastion host.",
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

        # Add output for the security group ARN
        t.add_output(
            Output(
                'SecurityGroupArn',
                Description='The ARN of the bastion security group',
                Value=GetAtt(sg, 'Arn')
            )
        )

    def create_iam_role(self):
        t = self.template
        
        # Create tags list from variables
        tags = []
        # Add default tags
        for key, value in self.variables["Tags"].items():
            tags.append({"Key": key, "Value": value})
        # Add Name tag
        tags.append({
            "Key": "Name", "Value": f"{self.variables['NamePrefix']}-role",
            "Key": "ck-environment", "Value": f"{self.variables['Environment']}"
        })

        # Create IAM Role
        role = t.add_resource(
            iam.Role(
                f"{self.variables['NamePrefix']}-role",
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
                Description=f"IAM role for {self.variables['NamePrefix']}",
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
                f"{self.variables['NamePrefix']}-instance-profile",
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
        # Create tags list from variables
        tags = []
        # Add default tags
        for key, value in self.variables["Tags"].items():
            tags.append({"Key": key, "Value": value})
        # Add Name tag
        tags.append({
            "Key": "Name", "Value": f"{self.variables['NamePrefix']}-ssm",
            "Key": "ck-environment", "Value": f"{self.variables['Environment']}"
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
                "KMSAlias",
                AliasName=f"alias/{self.variables['NamePrefix']}-ssm",
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
                "KMSAliasArn",
                Description="The ARN of the KMS alias",
                Value=GetAtt(kms_alias, "AliasArn")
            )
        )

    def generate_user_data(self):
        return """#!/usr/bin/env bash
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

    def lookup_vpc_info(self):
        """Lookup VPC information for the specified VPC ID."""
        ec2_client = boto3.client('ec2')
        
        try:
            # Get VPC information
            vpc_response = ec2_client.describe_vpcs(
                VpcIds=[f"{self.variables['VpcId']}"]
            )
            
            if not vpc_response['Vpcs']:
                raise ValueError(f"VPC {self.variables['VpcId']} not found")
            
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
        
        # Create tags list from variables
        tags = []
        # Add default tags
        for key, value in self.variables["Tags"].items():
            tags.append({"Key": key, "Value": value})
        # Add Name tag
        tags.append({
            "Key": "Name", "Value": f"{self.variables['NamePrefix']}",
            "Key": "ck-environment", "Value": f"{self.variables['Environment']}"
        })

        # Create EC2 Instance
        instance = t.add_resource(
            ec2.Instance(
                f"{self.variables['NamePrefix']}",
                ImageId=FindInMap(
                    'AmiMap', Ref("AWS::Region"), Ref("ImageName")),
                InstanceType=Ref("InstanceType"),
                UserData=self.generate_user_data(),
                SecurityGroupIds=[Ref(f"{self.variables['NamePrefix']}-sg")],
                IamInstanceProfile=Ref(f"{self.variables['NamePrefix']}-instance-profile"),
                Tags=tags,
                SubnetId=Ref("PrivateSubnets")[0]  # Use first private subnet
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

    def create_ebs_volume(self):
        t = self.template
        
        # Create tags list from variables
        tags = []
        # Add default tags
        for key, value in self.variables["Tags"].items():
            tags.append({"Key": key, "Value": value})
        # Add Name tag
        tags.append({
            "Key": "Name", "Value": f"{self.variables['NamePrefix']}-volume",
            "Key": "ck-environment", "Value": f"{self.variables['Environment']}"
        })

        # Create encrypted EBS volume
        volume = t.add_resource(
            ec2.Volume(
                f"{self.variables['NamePrefix']}-volume",
                Size=100,  # 100 GB
                VolumeType="gp3",
                Encrypted=True,
                KmsKeyId=Ref("KMSKey"),
                AvailabilityZone=GetAtt(f"{self.variables['NamePrefix']}", "AvailabilityZone"),
                Tags=tags
            )
        )

        # Attach volume to instance
        t.add_resource(
            ec2.VolumeAttachment(
                f"{self.variables['NamePrefix']}-volume-attachment",
                Device="/dev/sdf",
                InstanceId=Ref(f"{self.variables['NamePrefix']}"),
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

    def create_template(self):
        # Lookup VPC information
        vpc_info = self.lookup_vpc_info()
        
        self.create_kms_key()
        self.create_iam_role()
        self.create_security_groups(vpc_info)
        self.create_ec2_instance(vpc_info)
        self.create_ebs_volume()
