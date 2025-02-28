import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class SecretsManagerSecretScanner(BaseScanner):
    """Scanner for Secrets Manager Secrets"""
    
    def get_service_name(self):
        return "secretsmanager"
    
    def get_resource_type(self):
        return "secret"
    
    def scan(self):
        """Scan Secrets Manager Secrets in the current region"""
        try:
            sm_client = self.aws_client.get_client('secretsmanager')
            paginator = sm_client.get_paginator('list_secrets')
            
            secret_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for secret in page.get('SecretList', []):
                    secret_name = secret.get('Name')
                    secret_arn = secret.get('ARN')
                    
                    try:
                        # Get resource policy if it exists
                        try:
                            policy_response = sm_client.get_resource_policy(SecretId=secret_name)
                            secret['ResourcePolicy'] = policy_response.get('ResourcePolicy')
                        except botocore.exceptions.ClientError as e:
                            if 'ResourceNotFoundException' not in str(e):
                                logger.warning(f"Failed to get resource policy for secret {secret_name}: {str(e)}")
                        
                        # Note: We DO NOT fetch the actual secret value for security reasons
                        
                        # Get rotation configuration
                        secret['RotationEnabled'] = secret.get('RotationEnabled', False)
                        secret['RotationRules'] = secret.get('RotationRules', {})
                        
                        # Store secret metadata in database (not the secret value)
                        db_resource_id = self.store_resource(
                            resource_id=secret_arn,
                            name=secret_name,
                            properties=secret
                        )
                        
                        resource_ids.append((db_resource_id, secret_name))
                        secret_count += 1
                        
                    except botocore.exceptions.ClientError as e:
                        logger.error(f"Failed to get details for secret {secret_name}: {str(e)}")
            
            logger.info(f"Discovered {secret_count} secrets in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning Secrets Manager secrets: {error_msg}")
            raise ResourceScanError("secret", self.account_id, self.region, error_msg) 