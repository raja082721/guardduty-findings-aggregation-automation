import boto3
import json
from botocore.exceptions import ClientError

# CONFIGURATION
region_kms_and_bucket = 'eu-west-1'
bucket_name = 'guardduty-findings-9a0e87ff'  # must be globally unique
kms_alias = 'alias/GuardDutyFindingsKey'
account_id = boto3.client('sts').get_caller_identity()['Account']

def get_guardduty_detectors():
    """Return dict of region -> detector_id for all GuardDuty enabled regions in the account."""
    session = boto3.Session()
    regions = session.get_available_regions('guardduty')
    detectors = {}
    for region in regions:
        gd = session.client('guardduty', region_name=region)
        try:
            detector_list = gd.list_detectors()
            if detector_list['DetectorIds']:
                detectors[region] = detector_list['DetectorIds'][0]
        except Exception as e:
            continue  # ignore regions where GuardDuty is disabled
    return detectors

def create_kms_key_and_alias(kms_client, alias_name):
    """
    Create a KMS CMK and assign the alias, or return details if alias already exists.
    Returns:
      key_id, key_arn
    """
    aliases = kms_client.list_aliases()['Aliases']
    matched = [a for a in aliases if a['AliasName'] == alias_name]
    if matched and 'TargetKeyId' in matched[0]:
        # Alias exists, describe key to get ARN
        key_id = matched[0]['TargetKeyId']
        key = kms_client.describe_key(KeyId=key_id)['KeyMetadata']
        print(f"KMS Alias {alias_name} already exists, key id: {key_id}")
        return key_id, key['Arn']
    else:
        # Create new key and alias
        print(f"Creating KMS CMK and alias {alias_name} ...")
        key_resp = kms_client.create_key(
            Description='KMS key for GuardDuty findings encryption',
            KeyUsage='ENCRYPT_DECRYPT',
            Origin='AWS_KMS',
        )
        key_id = key_resp['KeyMetadata']['KeyId']
        key_arn = key_resp['KeyMetadata']['Arn']
        kms_client.create_alias(AliasName=alias_name, TargetKeyId=key_id)
        print(f"Created KMS key {key_id} with alias {alias_name}")
        return key_id, key_arn

def generate_guardduty_kms_policy(account_id, detector_region_map):
    """
    Generate a KMS key policy strictly for GuardDuty findings encryption.
    """
    base_statements = [{
        "Sid": "Enable IAM User Permissions",
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
        "Action": "kms:*",
        "Resource": "*"
    }]
    # Per-region GuardDuty permissions
    gd_statements = []
    for region, detector_id in detector_region_map.items():
        gd_statements.append({
            "Sid": f"Allow GuardDuty to encrypt findings {region}",
            "Effect": "Allow",
            "Principal": {
                "Service": f"guardduty.{region}.amazonaws.com"
            },
            "Action": "kms:GenerateDataKey",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:SourceAccount": account_id,
                    "aws:SourceArn": f"arn:aws:guardduty:{region}:{account_id}:detector/{detector_id}"
                }
            }
        })
    policy = {
        "Version": "2012-10-17",
        "Id": "key-default-1",
        "Statement": base_statements + gd_statements
    }
    return policy

def generate_guardduty_s3_policy(
    bucket_name: str, kms_key_arn: str, account_id: str, detector_region_map: dict
):
    """
    Generate an S3 bucket policy for any N GuardDuty regions as per your provided template.
    """
    bucket_arn = f"arn:aws:s3:::{bucket_name}"
    object_arn = f"{bucket_arn}/*"
    statements = []

    for region, detector_id in detector_region_map.items():
        service_principal = f"guardduty.{region}.amazonaws.com"
        detector_arn = f"arn:aws:guardduty:{region}:{account_id}:detector/{detector_id}"
        # 1. Deny non-HTTPS access
        statements.append({
            "Sid": f"Deny non-HTTPS access {region}",
            "Effect": "Deny",
            "Principal": {"Service": service_principal},
            "Action": "s3:*",
            "Resource": object_arn,
            "Condition": {"Bool": {"aws:SecureTransport": "false"}}
        })
        # 2. Deny if incorrect encryption key header
        statements.append({
            "Sid": f"Deny incorrect encryption header {region}",
            "Effect": "Deny",
            "Principal": {"Service": service_principal},
            "Action": "s3:PutObject",
            "Resource": object_arn,
            "Condition": {"StringNotEquals": {
                "s3:x-amz-server-side-encryption-aws-kms-key-id": kms_key_arn
            }}
        })
        # 3. Deny unencrypted uploads
        statements.append({
            "Sid": f"Deny unencrypted object uploads {region}",
            "Effect": "Deny",
            "Principal": {"Service": service_principal},
            "Action": "s3:PutObject",
            "Resource": object_arn,
            "Condition": {"StringNotEquals": {
                "s3:x-amz-server-side-encryption": "aws:kms"
            }}
        })
        # 4. Allow PutObject with correct SourceAccount and SourceArn
        statements.append({
            "Sid": f"Allow PutObject {region}",
            "Effect": "Allow",
            "Principal": {"Service": service_principal},
            "Action": "s3:PutObject",
            "Resource": object_arn,
            "Condition": {"StringEquals": {
                "aws:SourceAccount": account_id,
                "aws:SourceArn": detector_arn
            }}
        })
        # 5. Allow GetBucketLocation with correct SourceAccount and SourceArn
        statements.append({
            "Sid": f"Allow GetBucketLocation {region}",
            "Effect": "Allow",
            "Principal": {"Service": service_principal},
            "Action": "s3:GetBucketLocation",
            "Resource": bucket_arn,
            "Condition": {"StringEquals": {
                "aws:SourceAccount": account_id,
                "aws:SourceArn": detector_arn
            }}
        })
    return {"Version": "2012-10-17", "Statement": statements}

def create_s3_bucket(s3_client, bucket_name, region):
    if region == 'us-east-1':
        s3_client.create_bucket(Bucket=bucket_name)
    else:
        s3_client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={'LocationConstraint': region}
        )
    print(f"Created S3 bucket {bucket_name} in {region}")


def put_bucket_encryption(s3_client, bucket_name, key_arn):
    try:
        s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [{
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'aws:kms',
                        'KMSMasterKeyID': key_arn
                    }
                }]
            }
        )
        print(f"SSE-KMS encryption enforced on bucket {bucket_name} using {key_arn}")
    except Exception as e:
        print(f"Failed to apply encryption: {e}")
        raise

def put_kms_key_policy(kms_client, key_id, policy):
    try:
        kms_client.put_key_policy(KeyId=key_id, PolicyName='default', Policy=json.dumps(policy))
        print("Updated KMS key policy.")
    except Exception as e:
        print(f"KMS key policy update failed: {e}")
        raise

def put_s3_bucket_policy(s3_client, bucket_name, policy):
    try:
        s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
        print("Updated S3 bucket policy.")
    except Exception as e:
        print(f"S3 bucket policy update failed: {e}")
        raise

def add_guardduty_s3_destinations(detector_map, s3_bucket_arn, kms_key_arn, export_prefix=None):
    """
    Configure GuardDuty in all enabled regions to export findings to the given S3 bucket.
    """
    for region, detector_id in detector_map.items():
        gd = boto3.client('guardduty', region_name=region)
        dest_arn = s3_bucket_arn
        if export_prefix:
            if not s3_bucket_arn.endswith('/'):
                dest_arn += '/'
            dest_arn += export_prefix
            if not dest_arn.endswith('/'):
                dest_arn += '/'
        try:
            dests = gd.list_publishing_destinations(DetectorId=detector_id)
            already_configured = any(
                d.get('DestinationProperties', {}).get('DestinationArn', '').startswith(dest_arn)
                for d in dests.get('Destinations', [])
            )
            if already_configured:
                print(f"Region {region}: Publishing destination already configured for this S3 bucket.")
                continue

            resp = gd.create_publishing_destination(
                DetectorId=detector_id,
                DestinationType='S3',
                DestinationProperties={
                    'DestinationArn': dest_arn,
                    'KmsKeyArn': kms_key_arn
                }
            )
            print(f"Region {region}: Publishing destination created: {resp.get('DestinationId')}")
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'BadRequestException' and 'Destination already exists' in str(e):
                print(f"Region {region}: Destination already exists.")
            else:
                print(f"Region {region}: Error configuring publishing destination: {e}")


if __name__ == "__main__":
    detectors = get_guardduty_detectors()
    print("Detected GuardDuty in regions and detector-ids:", detectors)

    # 1. Create KMS in eu-west-1 (or use existing alias)
    kms_client = boto3.client('kms', region_name=region_kms_and_bucket)
    key_id, key_arn = create_kms_key_and_alias(kms_client, kms_alias)
    print(f"KMS key arn for policy: {key_arn}")

    # 2. Create S3 if not exists
    s3_client = boto3.client('s3', region_name=region_kms_and_bucket)
    #create_s3_bucket_if_not_exists(s3_client, bucket_name, region_kms_and_bucket)
    create_s3_bucket(s3_client, bucket_name, region_kms_and_bucket)

    # 3. Set bucket encryption
    put_bucket_encryption(s3_client, bucket_name, key_arn)

    # 4. Update bucket policy for all GuardDuty-enabled regions
    s3_policy = generate_guardduty_s3_policy(bucket_name, key_arn, account_id, detectors)
    put_s3_bucket_policy(s3_client, bucket_name, s3_policy)
    
    # 5. Update KMS policy for all GuardDuty-enabled regions
    kms_policy = generate_guardduty_kms_policy(account_id, detectors)
    put_kms_key_policy(kms_client, key_id, kms_policy)

    # 6. Configure GuardDuty S3 export destination in every region
    s3_bucket_arn = f"arn:aws:s3:::{bucket_name}"
    add_guardduty_s3_destinations(detectors, s3_bucket_arn, key_arn)

    print("\nDONE. GuardDuty findings export is fully automated to your secure centralized bucket!")
