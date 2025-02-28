import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class WAFv2WebACLScanner(BaseScanner):
    """Scanner for WAFv2 Web ACLs"""
    
    def get_service_name(self):
        return "wafv2"
    
    def get_resource_type(self):
        return "webacl"
    
    def scan(self):
        """Scan WAFv2 Web ACLs in the current region"""
        try:
            wafv2_client = self.aws_client.get_client('wafv2')
            
            webacl_count = 0
            resource_ids = []
            
            # Scan for Regional Web ACLs
            try:
                regional_paginator = wafv2_client.get_paginator('list_web_acls')
                
                for page in regional_paginator.paginate(Scope='REGIONAL'):
                    for webacl in page.get('WebACLs', []):
                        webacl_name = webacl.get('Name')
                        webacl_id = webacl.get('Id')
                        
                        try:
                            # Get detailed information about the Web ACL
                            detail_response = wafv2_client.get_web_acl(
                                Name=webacl_name,
                                Id=webacl_id,
                                Scope='REGIONAL'
                            )
                            webacl_detail = detail_response.get('WebACL', {})
                            
                            # Get logging configuration
                            try:
                                logging_response = wafv2_client.get_logging_configuration(
                                    ResourceArn=webacl_detail.get('ARN')
                                )
                                webacl_detail['LoggingConfiguration'] = logging_response.get('LoggingConfiguration')
                            except botocore.exceptions.ClientError as e:
                                if 'WAFNonexistentItemException' not in str(e):
                                    logger.warning(f"Failed to get logging configuration for WAFv2 Web ACL {webacl_name}: {str(e)}")
                            
                            # Get resources for the Web ACL
                            try:
                                resources_response = wafv2_client.list_resources_for_web_acl(
                                    WebACLArn=webacl_detail.get('ARN'),
                                    ResourceType='APPLICATION_LOAD_BALANCER'
                                )
                                webacl_detail['ResourceArns'] = resources_response.get('ResourceArns', [])
                            except botocore.exceptions.ClientError as e:
                                logger.warning(f"Failed to get resources for WAFv2 Web ACL {webacl_name}: {str(e)}")
                            
                            # Store Web ACL in database
                            db_resource_id = self.store_resource(
                                resource_id=webacl_detail.get('ARN'),
                                name=webacl_name,
                                properties=webacl_detail
                            )
                            
                            resource_ids.append((db_resource_id, webacl_name))
                            webacl_count += 1
                            
                        except botocore.exceptions.ClientError as e:
                            logger.error(f"Failed to get details for WAFv2 Web ACL {webacl_name}: {str(e)}")
            except botocore.exceptions.ClientError as e:
                logger.error(f"Failed to list regional WAFv2 Web ACLs: {str(e)}")
            
            # If this is the us-east-1 region, also scan for CloudFront (global) Web ACLs
            if self.region == 'us-east-1':
                try:
                    cloudfront_paginator = wafv2_client.get_paginator('list_web_acls')
                    
                    for page in cloudfront_paginator.paginate(Scope='CLOUDFRONT'):
                        for webacl in page.get('WebACLs', []):
                            webacl_name = webacl.get('Name')
                            webacl_id = webacl.get('Id')
                            
                            try:
                                # Get detailed information about the Web ACL
                                detail_response = wafv2_client.get_web_acl(
                                    Name=webacl_name,
                                    Id=webacl_id,
                                    Scope='CLOUDFRONT'
                                )
                                webacl_detail = detail_response.get('WebACL', {})
                                
                                # Get logging configuration
                                try:
                                    logging_response = wafv2_client.get_logging_configuration(
                                        ResourceArn=webacl_detail.get('ARN')
                                    )
                                    webacl_detail['LoggingConfiguration'] = logging_response.get('LoggingConfiguration')
                                except botocore.exceptions.ClientError as e:
                                    if 'WAFNonexistentItemException' not in str(e):
                                        logger.warning(f"Failed to get logging configuration for WAFv2 Web ACL {webacl_name}: {str(e)}")
                                
                                # Store Web ACL in database
                                db_resource_id = self.store_resource(
                                    resource_id=webacl_detail.get('ARN'),
                                    name=webacl_name,
                                    properties=webacl_detail
                                )
                                
                                resource_ids.append((db_resource_id, webacl_name))
                                webacl_count += 1
                                
                            except botocore.exceptions.ClientError as e:
                                logger.error(f"Failed to get details for WAFv2 Web ACL {webacl_name}: {str(e)}")
                except botocore.exceptions.ClientError as e:
                    logger.error(f"Failed to list global WAFv2 Web ACLs: {str(e)}")
            
            logger.info(f"Discovered {webacl_count} WAFv2 web ACLs in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning WAFv2 web ACLs: {error_msg}")
            raise ResourceScanError("webacl", self.account_id, self.region, error_msg) 