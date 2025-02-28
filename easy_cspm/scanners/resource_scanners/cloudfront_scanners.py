import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class CloudFrontDistributionScanner(BaseScanner):
    """Scanner for CloudFront Distributions"""
    
    def get_service_name(self):
        return "cloudfront"
    
    def get_resource_type(self):
        return "distribution"
    
    def scan(self):
        """Scan CloudFront Distributions (global resource, but we scan only from us-east-1)"""
        # CloudFront is a global service, so we only need to scan it from one region
        if self.region != 'us-east-1':
            logger.info(f"Skipping CloudFront distribution scan in region {self.region} (only scanning from us-east-1)")
            return []
        
        try:
            cf_client = self.aws_client.get_client('cloudfront')
            paginator = cf_client.get_paginator('list_distributions')
            
            distribution_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                distribution_list = page.get('DistributionList', {})
                for distribution in distribution_list.get('Items', []):
                    distribution_id = distribution.get('Id')
                    
                    try:
                        # Get detailed information about the distribution
                        distribution_response = cf_client.get_distribution(
                            Id=distribution_id
                        )
                        distribution_detail = distribution_response.get('Distribution', {})
                        
                        # Get origin access identities if they exist
                        try:
                            oai_paginator = cf_client.get_paginator('list_cloud_front_origin_access_identities')
                            oais = []
                            
                            for oai_page in oai_paginator.paginate():
                                oai_list = oai_page.get('CloudFrontOriginAccessIdentityList', {})
                                oais.extend(oai_list.get('Items', []))
                            
                            distribution_detail['OriginAccessIdentities'] = oais
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get origin access identities for CloudFront distribution {distribution_id}: {str(e)}")
                        
                        # Get tags
                        try:
                            tags_response = cf_client.list_tags_for_resource(
                                Resource=distribution_detail.get('ARN')
                            )
                            distribution_detail['Tags'] = tags_response.get('Tags', {}).get('Items', [])
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get tags for CloudFront distribution {distribution_id}: {str(e)}")
                        
                        # Get field-level encryption configurations
                        try:
                            fle_response = cf_client.list_field_level_encryption_configs()
                            distribution_detail['FieldLevelEncryptionConfigs'] = fle_response.get('FieldLevelEncryptionList', {}).get('Items', [])
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get field-level encryption configs for CloudFront: {str(e)}")
                        
                        # Store distribution in database
                        distribution_name = f"Distribution-{distribution_id}"
                        db_resource_id = self.store_resource(
                            resource_id=distribution_id,
                            name=distribution_name,
                            properties=distribution_detail
                        )
                        
                        resource_ids.append((db_resource_id, distribution_name))
                        distribution_count += 1
                        
                    except botocore.exceptions.ClientError as e:
                        logger.error(f"Failed to get details for CloudFront distribution {distribution_id}: {str(e)}")
            
            logger.info(f"Discovered {distribution_count} CloudFront distributions in account {self.account_id}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning CloudFront distributions: {error_msg}")
            raise ResourceScanError("distribution", self.account_id, self.region, error_msg) 