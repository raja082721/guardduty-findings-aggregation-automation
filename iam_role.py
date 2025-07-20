import boto3
import json
from botocore.exceptions import ClientError

def ensure_iam_role(
    iam_client,
    role_name,
    trusted_role_arn,
    trusted_role_sid,
    inline_policy_name,
    s3_bucket_arn,
    kms_key_arn
):
    """
    - iam_client: boto3.client('iam')
    - role_name: desired role name
    - trusted_role_arn: the Splunk IAM role ARN to trust
    - trusted_role_sid: the 'Sid' you want in the trust relationship
    - inline_policy_name: name for the inline policy
    - s3_bucket_arn: base S3 bucket arn (e.g. arn:aws:s3:::guardduty-findings-9a0e87ff)
    - kms_key_arn: KMS key arn
    """

    # 1. Build the trust relationship
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": trusted_role_sid,
                "Effect": "Allow",
                "Principal": {"AWS": trusted_role_arn},
                "Action": "sts:AssumeRole"
            }
        ]
    }

    # 2. Create the role if not exists
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

    # 3. Build inline policy
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

    # 4. Attach inline policy
    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_policy_name,
        PolicyDocument=json.dumps(inline_policy)
    )
    print(f"Inline policy '{inline_policy_name}' added to role '{role_name}'.")

if __name__ == "__main__":

    # ----- Variables to set -----
    role_name = "ROLENAME"
    trusted_role_arn = "SPLUNK ARN"
    trusted_role_sid = "SIEMPRDRole"
    inline_policy_name = "SplunkS3KMSReadPolicy"
    s3_bucket_arn = "S3:ARN"
    kms_key_arn = "KMS:ARN"

    iam = boto3.client("iam")

    ensure_iam_role(
        iam,
        role_name,
        trusted_role_arn,
        trusted_role_sid,
        inline_policy_name,
        s3_bucket_arn,
        kms_key_arn
    )

    print("IAM role automation complete.")
