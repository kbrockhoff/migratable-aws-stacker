# Migratable AWS Stacker

Provides a stacker project which can be used to test migrations to other
infrastructure-as-code frameworks and languages.

## Cloud Resources Created

This project creates the following AWS resources through CloudFormation stacks:

### Bastion Stack (`blueprints/bastion.py`)

**Security Resources:**
- **KMS Key** - Customer-managed encryption key for SSM sessions with automatic rotation enabled
- **KMS Alias** - Named alias for the encryption key (`alias/{NamePrefix}-ssm`)
- **Security Group** - Network security group allowing:
  - All traffic within VPC CIDR block
  - HTTPS outbound (port 443) to internet

**Compute Resources:**
- **EC2 Instance** - Amazon Linux 2023 bastion host with:
  - SSM agent enabled for secure shell access
  - Custom user data for SSH configuration
  - Deployed in private subnet
- **EBS Volume** - 100GB encrypted GP3 volume attached to bastion instance

**IAM Resources:**  
- **IAM Role** - Service role for EC2 with managed policies:
  - `AmazonSSMManagedInstanceCore` - SSM session management
  - `CloudWatchAgentServerPolicy` - CloudWatch monitoring
  - Custom KMS policy for encryption key access
- **Instance Profile** - Allows EC2 instance to assume the IAM role

**Outputs:**
- Security group ID and name
- Instance ID and private IP address
- IAM role and instance profile ARNs
- KMS key ID, ARN, and alias name
- EBS volume ID

All resources are tagged with configurable metadata including cost center, environment, project ownership, and compliance information.

