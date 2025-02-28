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
        client = self.aws_client.get_client('kms')
        try:
            # Get all keys in the account that are not AWS managed
            paginator = client.get_paginator('list_keys')
            resources = []
            
            for page in paginator.paginate():
                for key in page.get('Keys', []):
                    key_id = key.get('KeyId')
                    
                    # Get detailed info for the key
                    try:
                        key_info = client.describe_key(KeyId=key_id)
                        key_metadata = key_info.get('KeyMetadata', {})
                        
                        # Skip AWS managed keys
                        if key_metadata.get('KeyManager') == 'AWS':
                            continue
                            
                        key_id = key_metadata.get('KeyId')
                        alias = self.get_key_alias(client, key_id)
                        key_name = alias if alias else key_id
                        
                        resources.append((key_id, key_name))
                    except Exception as e:
                        logger.warning(f"Error getting details for KMS key {key_id}: {str(e)}")
                
            logger.info(f"Discovered {len(resources)} KMS keys in account {self.account_id} region {self.region}")
            return resources
        except Exception as e:
            logger.error(f"Error scanning KMS keys: {str(e)}")
            return []
            
    def get_key_alias(self, client, key_id):
        """Get an alias for a KMS key if one exists"""
        try:
            response = client.list_aliases(KeyId=key_id)
            aliases = response.get('Aliases', [])
            if aliases:
                return aliases[0].get('AliasName', '').replace('alias/', '')
            return None
        except Exception:
            return None 