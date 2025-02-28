import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class KMSKeyScanner(BaseScanner):
    """Scanner for KMS Keys"""
    
    def get_service_name(self):
        return "kms"
    
    def get_resource_type(self):
        return "key"
    
    def scan(self):
        """Scan KMS Keys in the current region"""
        try:
            kms_client = self.aws_client.get_client('kms')
            paginator = kms_client.get_paginator('list_keys')
            
            key_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for key in page.get('Keys', []):
                    key_id = key['KeyId']
                    
                    try:
                        # Get detailed information about the key
                        key_info = kms_client.describe_key(KeyId=key_id)
                        key_metadata = key_info.get('KeyMetadata', {})
                        
                        # Skip AWS managed keys if we want to focus on customer keys
                        if key_metadata.get('KeyManager') == 'AWS' and self.config.get('skip_aws_managed_keys'):
                            logger.debug(f"Skipping AWS managed KMS key {key_id}")
                            continue
                        
                        key_state = key_metadata.get('KeyState')
                        if key_state in ['PendingDeletion', 'Disabled']:
                            logger.debug(f"Skipping KMS key {key_id} in state {key_state}")
                            continue
                        
                        # Get key aliases
                        aliases_response = kms_client.list_aliases(KeyId=key_id)
                        aliases = aliases_response.get('Aliases', [])
                        
                        # Get key rotation status
                        try:
                            rotation_response = kms_client.get_key_rotation_status(KeyId=key_id)
                            key_metadata['RotationEnabled'] = rotation_response.get('KeyRotationEnabled', False)
                        except botocore.exceptions.ClientError as e:
                            # Some keys don't support rotation (like AWS managed keys)
                            if 'AccessDeniedException' in str(e) or 'UnsupportedOperationException' in str(e):
                                key_metadata['RotationEnabled'] = False
                            else:
                                raise
                        
                        # Get key policy
                        try:
                            policy_response = kms_client.get_key_policy(KeyId=key_id, PolicyName='default')
                            key_metadata['Policy'] = policy_response.get('Policy')
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get policy for KMS key {key_id}: {str(e)}")
                        
                        # Get key tags
                        try:
                            tags_response = kms_client.list_resource_tags(KeyId=key_id)
                            key_metadata['Tags'] = tags_response.get('Tags', [])
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get tags for KMS key {key_id}: {str(e)}")
                        
                        # Get key grants
                        try:
                            grants_paginator = kms_client.get_paginator('list_grants')
                            grants = []
                            
                            for grants_page in grants_paginator.paginate(KeyId=key_id):
                                grants.extend(grants_page.get('Grants', []))
                            
                            key_metadata['Grants'] = grants
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get grants for KMS key {key_id}: {str(e)}")
                        
                        # Add aliases to key metadata
                        key_metadata['Aliases'] = aliases
                        
                        # Determine key name from aliases or use key ID
                        key_name = key_id
                        for alias in aliases:
                            alias_name = alias.get('AliasName', '')
                            if alias_name.startswith('alias/'):
                                key_name = alias_name[6:]  # Remove 'alias/' prefix
                                break
                        
                        # Store key in database
                        db_resource_id = self.store_resource(
                            resource_id=key_id,
                            name=key_name,
                            properties=key_metadata
                        )
                        
                        resource_ids.append((db_resource_id, key_name))
                        key_count += 1
                        
                    except botocore.exceptions.ClientError as e:
                        logger.error(f"Failed to get details for KMS key {key_id}: {str(e)}")
            
            logger.info(f"Discovered {key_count} KMS keys in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning KMS keys: {error_msg}")
            raise ResourceScanError("key", self.account_id, self.region, error_msg) 