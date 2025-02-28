import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class WAFv2WebACLScanner(BaseScanner):
    """Scanner for WAFv2 Web ACLs"""
    
    def get_service_name(self):
        return "wafv2"
    
    def get_resource_type(self):
        return "web_acl"
    
    def scan(self):
        client = self.aws_client.get_client('wafv2')
        resources = []
        
        # Scopes to check
        scopes = ['REGIONAL']
        
        # Only check CloudFront in us-east-1
        if self.region == 'us-east-1':
            scopes.append('CLOUDFRONT')
        
        for scope in scopes:
            try:
                # Use direct API call instead of paginator
                response = client.list_web_acls(Scope=scope, Limit=100)
                web_acls = response.get('WebACLs', [])
                
                # Manual pagination
                while 'NextMarker' in response and response['NextMarker']:
                    next_marker = response['NextMarker']
                    response = client.list_web_acls(Scope=scope, Limit=100, NextMarker=next_marker)
                    web_acls.extend(response.get('WebACLs', []))
                
                # Process the results
                for acl in web_acls:
                    acl_id = acl.get('Id')
                    acl_name = acl.get('Name')
                    resources.append((acl_id, acl_name))
                
            except Exception as e:
                logger.error(f"Error scanning WAFv2 Web ACLs with scope {scope}: {str(e)}")
        
        logger.info(f"Discovered {len(resources)} WAFv2 Web ACLs in account {self.account_id} region {self.region}")
        return resources 