from ...scanners.base_scanner import BaseScanner
from ...core.logging_config import logger

class WAFv2WebACLScanner(BaseScanner):
    """Scanner for WAFv2 Web ACLs"""
    
    def get_service_name(self):
        return "wafv2"
    
    def get_resource_type(self):
        return "web_acl"
    
    def scan_resource(self, client, account_id, region):
        """Scan WAFv2 Web ACLs in the account"""
        try:
            # WAFv2 list_web_acls doesn't support pagination
            response = client.list_web_acls(Scope='REGIONAL')
            web_acls = response.get('WebACLs', [])
            
            resources = []
            for acl in web_acls:
                # Get detailed information about each Web ACL
                detail = client.get_web_acl(
                    Name=acl['Name'],
                    Scope='REGIONAL',
                    Id=acl['Id']
                )
                
                properties = {
                    'WebACLId': acl['Id'],
                    'Name': acl['Name'],
                    'ARN': acl['ARN'],
                    'DefaultAction': detail.get('WebACL', {}).get('DefaultAction', {}),
                    'Rules': detail.get('WebACL', {}).get('Rules', []),
                    'VisibilityConfig': detail.get('WebACL', {}).get('VisibilityConfig', {})
                }
                
                resource_id = acl['Id']
                resources.append(self.create_resource(resource_id, acl['ARN'], properties))
            
            return resources
        except client.exceptions.WAFNonexistentItemException:
            logger.warning(f"No WAFv2 Web ACLs found in {region}")
            return []
        except Exception as e:
            logger.error(f"Error scanning WAFv2 Web ACLs: {str(e)}")
            return [] 