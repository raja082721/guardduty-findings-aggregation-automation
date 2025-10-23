import boto3
import json
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from botocore.exceptions import ClientError

def ensure_iam_role_multiple_trust(
    iam_client,
    role_name,
    trusted_role_arns,   # <--- LIST of trusted role ARNs
    trusted_role_sid,
    inline_policy_name,
    s3_bucket_arn,
    kms_key_arn
):
    """
    - trusted_role_arns: list of IAM role ARNs
    """
    # Trust relationship with multiple ARNs
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": trusted_role_sid,
                "Effect": "Allow",
                "Principal": {"AWS": trusted_role_arns},
                "Action": "sts:AssumeRole"
            }
        ]
    }

    try:
        iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="Role for Splunk to access S3 findings and decrypt with KMS"
        )
        print(f"Role '{role_name}' created.")
    except ClientError as e:
        if e.response['Error']['Code'] == 'EntityAlreadyExists':
            print(f"Role '{role_name}' already exists. Proceeding.")
        else:
            raise

    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowListingAllBuckets",
                "Effect": "Allow",
                "Action": "s3:ListAllMyBuckets",
                "Resource": "*"
            },
            {
                "Sid": "AllowNecessaryPermissions",
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:GetBucketLocation",
                    "kms:Decrypt",
                    "s3:ListBucket"
                ],
                "Resource": [
                    kms_key_arn,
                    s3_bucket_arn,
                    s3_bucket_arn + "/*"
                ]
            }
        ]
    }

    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_policy_name,
        PolicyDocument=json.dumps(inline_policy)
    )
    print(f"Inline policy '{inline_policy_name}' added to role '{role_name}'.")

# Example usage:
if __name__ == "__main__":
    parser = ArgumentParser(description="Prepare IAM trust relationship to SIEM roles",
                            formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument('-r', '--role_name', required=True,
                        help='Name of IAM role to create for SIEM service to read the GuardDuty export from S3')
    parser.add_argument('-s', '--s3_bucket_arn', required=True,
                        help='ARN of the S3 bucket containing the exported GuardDuty findings')
    parser.add_argument('-k', '--kms_key_arn', required=True,
                        help='ARN of the KMS key used to encrypt the exported GuardDuty findings')
    parser.add_argument('--trusted_role_sid', default="SIEMPRDRole",
                        help='SID for the SIEM roles trust relationship')
    parser.add_argument('--inline_policy_name', default="SplunkS3KMSReadPolicy",
                        help='Name for the inline policy for the SIEM role')
    parser.add_argument('-t', '--trusted_role_arns', nargs="*",
                        help='Comma separated list of ARNs of IAM roles to provide access to the S3 bucket', default=[
                           "arn:aws:iam::123456789012:role/prd-role",
                           "arn:aws:iam::987654321098:role/acc-role"])
    args = parser.parse_args()

    iam = boto3.client("iam")
    ensure_iam_role_multiple_trust(
        iam,
        args['role_name'],
        args['trusted_role_arns'],
        args['trusted_role_sid'],
        args['inline_policy_name'],
        args['s3_bucket_arn'],
        args['kms_key_arn']
    )
