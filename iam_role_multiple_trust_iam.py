import boto3
import json
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
            Description=f"Role for Splunk to access S3 findings and decrypt with KMS"
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

    # ----- Variables to set -----
    role_name = "ROLENAME"
    trusted_role_arns = [
        "arn:aws:iam::123456789012:role/prd-role",
        "arn:aws:iam::987654321098:role/acc-role"
    ]
    trusted_role_sid = "SIEMPRDRole"
    inline_policy_name = "SplunkS3KMSReadPolicy"
    s3_bucket_arn = "S3:ARN"
    kms_key_arn = "KMS:ARN"  

    iam = boto3.client("iam")
    ensure_iam_role_multiple_trust(
        iam,
        role_name,
        trusted_role_arns,
        trusted_role_sid,
        inline_policy_name,
        s3_bucket_arn,
        kms_key_arn
    )
