import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class S3BucketScanner(BaseScanner):
    """Scanner for S3 Buckets"""
    
    def get_service_name(self):
        return "s3"
    
    def get_resource_type(self):
        return "bucket"
    
    def scan(self):
        """Scan S3 Buckets in the account"""
        try:
            s3_client = self.aws_client.get_client('s3')
            
            bucket_count = 0
            resource_ids = []
            
            # List buckets (global API call)
            response = s3_client.list_buckets()
            
            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']
                
                # Get bucket location (region)
                try:
                    location = s3_client.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location.get('LocationConstraint') or 'us-east-1'
                    
                    # Skip if the bucket is not in the current region
                    if bucket_region != self.region:
                        logger.debug(f"Skipping bucket {bucket_name} in region {bucket_region} (current region: {self.region})")
                        continue
                except botocore.exceptions.ClientError as e:
                    logger.warning(f"Unable to determine region for bucket {bucket_name}: {str(e)}")
                    continue
                
                # Get bucket properties
                bucket_props = {
                    'Name': bucket_name,
                    'CreationDate': bucket['CreationDate'].isoformat(),
                    'Region': bucket_region
                }
                
                # Get bucket policy
                try:
                    policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                    bucket_props['Policy'] = policy.get('Policy')
                except botocore.exceptions.ClientError:
                    bucket_props['Policy'] = None
                
                # Get bucket ACL
                try:
                    acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                    bucket_props['ACL'] = acl
                except botocore.exceptions.ClientError:
                    bucket_props['ACL'] = None
                
                # Get encryption configuration
                try:
                    encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                    bucket_props['Encryption'] = encryption.get('ServerSideEncryptionConfiguration')
                except botocore.exceptions.ClientError:
                    bucket_props['Encryption'] = None
                
                # Get versioning status
                try:
                    versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                    bucket_props['Versioning'] = versioning
                except botocore.exceptions.ClientError:
                    bucket_props['Versioning'] = None
                
                # Get public access block configuration
                try:
                    public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
                    bucket_props['PublicAccessBlock'] = public_access_block.get('PublicAccessBlockConfiguration')
                except botocore.exceptions.ClientError:
                    bucket_props['PublicAccessBlock'] = None
                
                # Store bucket in database
                db_resource_id = self.store_resource(
                    resource_id=bucket_name,
                    name=bucket_name,
                    properties=bucket_props
                )
                
                resource_ids.append((db_resource_id, bucket_name))
                bucket_count += 1
            
            logger.info(f"Discovered {bucket_count} S3 buckets in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning S3 buckets: {error_msg}")
            raise ResourceScanError("bucket", self.account_id, self.region, error_msg) 