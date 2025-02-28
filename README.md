# Easy CSPM - Cloud Security Posture Management for AWS

Easy CSPM is a command-line tool that helps you assess the security posture of your AWS environment. It scans your AWS resources, evaluates them against security best practices, and provides findings with remediation guidance.

## Features

- **Comprehensive Resource Scanning**: Discovers AWS resources across multiple regions
- **Security Posture Assessment**: Evaluates resources against security best practices
- **Flexible Output**: Exports findings to CSV and stores in a database
- **Extensible Framework**: Easily add new resource scanners and security findings

## Supported AWS Resource Types

The tool currently supports scanning the following AWS resource types:

1. **Compute**
   - EC2 Instances (Findings only)
   - EKS Clusters and Node Groups
   - Lambda Functions
   - EMR Clusters

2. **Storage**
   - S3 Buckets
   - ECR Repositories

3. **Database**
   - RDS DB Instances

4. **Network & Content Delivery**
   - CloudFront Distributions
   - SQS Queues
   - WAFv2 Web ACLs

5. **Security, Identity & Compliance**
   - Secrets Manager Secrets
   - GuardDuty Detectors

6. **Analytics**
   - Athena Workgroups

7. **Management & Governance**
   - CloudFormation Stacks

## Security Findings

The tool evaluates resources against security best practices and generates findings for issues such as:

1. **Compute Findings**
   - EC2 related security findings
   - EKS Cluster Endpoint Public Access
   - EKS Cluster Logging Disabled
   - EKS Cluster Old Version
   - EKS Node Group Unencrypted EBS

2. **Storage Findings**
   - ECR Repository Scan On Push Disabled
   - ECR Repository No Lifecycle Policy
   - ECR Repository Public Access

3. **Management Findings**
   - CloudFormation Stack Drift
   - CloudFormation Stack No Termination Protection
   - CloudFormation Stack Insecure Capabilities

4. **Analytics Findings**
   - Athena Workgroup Encryption Disabled
   - Athena Workgroup No Results Limit

5. **Network Findings**
   - CloudFront No WAF
   - CloudFront Insecure Protocols
   - CloudFront No Field Level Encryption

6. **Security Findings**
   - Secrets Manager Rotation Disabled
   - Secrets Manager No Encryption With Custom KMS
   - GuardDuty Detector Disabled
   - GuardDuty S3 Protection Disabled

7. **EMR Findings**
   - EMR Cluster No Encryption
   - EMR Cluster Publicly Accessible
   - EMR Cluster No Kerberos Or IAM

8. **Database Findings**
   - RDS related security findings

## Installation

### Prerequisites

- Python 3.8 or higher
- AWS account with appropriate IAM permissions
- AWS CLI configured (optional, but helpful)

### Option 1: Install from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/easy-cspm.git
cd easy-cspm

# Create and activate a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install the package in development mode
pip install -e .
```

### Verifying Installation

To verify that the tool is installed correctly:

```bash
easy-cspm --version
```

or

```bash
python -m easy_cspm.cli --version
```

## Configuration

Create a `.env` file with your AWS credentials and configuration:

```
# AWS Credentials
AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY=YOUR_SECRET_ACCESS_KEY
AWS_SESSION_TOKEN=YOUR_SESSION_TOKEN_IF_USING_TEMPORARY_CREDENTIALS

# AWS Account and Regions
AWS_ACCOUNT_ID=YOUR_AWS_ACCOUNT_ID
AWS_REGIONS=us-east-1,us-west-1,eu-west-1

# Database Configuration
DB_CONNECTION_STRING=sqlite:///easy_cspm.db
```

### Required AWS Permissions

The AWS credentials used should have read-only permissions for the services you want to scan. An example IAM policy with the minimum required permissions is:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "athena:ListWorkGroups",
                "athena:GetWorkGroup",
                "cloudformation:DescribeStacks",
                "cloudfront:ListDistributions",
                "cloudfront:GetDistribution",
                "ec2:DescribeInstances",
                "ecr:DescribeRepositories",
                "eks:ListClusters",
                "eks:DescribeCluster",
                "emr:ListClusters",
                "emr:DescribeCluster",
                "guardduty:ListDetectors",
                "lambda:ListFunctions",
                "rds:DescribeDBInstances",
                "s3:ListAllMyBuckets",
                "secretsmanager:ListSecrets",
                "sqs:ListQueues",
                "wafv2:ListWebACLs"
            ],
            "Resource": "*"
        }
    ]
}
```

## Usage

### Basic Usage

```bash
# Run the CSPM tool
easy-cspm
```

### Advanced Usage

```bash
# Run with debug logging and custom output file
easy-cspm --debug --output findings.csv

# Use a custom .env file
easy-cspm --env-file path/to/custom.env

# Run with Python module syntax
python -m easy_cspm.cli --debug --output findings.csv
```

## Database Schema

The tool stores resources and findings in a database with the following schema:

- **Resources Table**: Stores discovered AWS resources
- **Findings Table**: Stores security findings with references to resources

## Extending the Tool

### Adding a New Resource Scanner

1. Create a new file in `easy_cspm/scanners/resource_scanners/`
2. Define a scanner class that inherits from `BaseScanner`
3. Implement the required methods:
   - `get_service_name()`
   - `get_resource_type()`
   - `scan()`

### Adding a New Security Finding

1. Create a new file in `easy_cspm/findings/finding_types/`
2. Define a finding class that inherits from `BaseFinding`
3. Implement the required methods:
   - `get_finding_type()`
   - `get_title()`
   - `get_description()`
   - `get_remediation()`
   - `get_severity()`
   - `evaluate(resource)`

## Troubleshooting

### Common Issues

1. **AWS credential errors**: Ensure your AWS credentials in the .env file are correct and have the necessary permissions.
2. **Region errors**: Verify that the regions specified in your .env file are valid AWS regions.
3. **Database connection errors**: Check that the database connection string is correct and the database is accessible.

### Logging

For more detailed logging, use the `--debug` flag:

```bash
easy-cspm --debug
```

Log files are stored in the current working directory by default.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
