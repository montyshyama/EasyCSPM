import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class CloudTrailTrailScanner(BaseScanner):
    """Scanner for CloudTrail Trails"""
    
    def get_service_name(self):
        return "cloudtrail"
    
    def get_resource_type(self):
        return "trail"
    
    def scan(self):
        """Scan CloudTrail Trails in the current region"""
        try:
            cloudtrail_client = self.aws_client.get_client('cloudtrail')
            
            trail_count = 0
            resource_ids = []
            
            # List trails
            trails_response = cloudtrail_client.describe_trails()
            
            for trail in trails_response.get('trailList', []):
                trail_name = trail['Name']
                trail_arn = trail['TrailARN']
                
                # Check if the trail belongs to the current region
                home_region = trail.get('HomeRegion', '')
                if home_region and home_region != self.region:
                    logger.debug(f"Skipping trail {trail_name} in region {self.region} (home region: {home_region})")
                    continue
                
                # Enhance trail with additional information
                try:
                    # Get trail status
                    status_response = cloudtrail_client.get_trail_status(Name=trail_name)
                    trail['Status'] = status_response
                    
                    # Get event selectors
                    selectors_response = cloudtrail_client.get_event_selectors(TrailName=trail_name)
                    trail['EventSelectors'] = selectors_response.get('EventSelectors', [])
                    trail['AdvancedEventSelectors'] = selectors_response.get('AdvancedEventSelectors', [])
                    
                    # Check if the trail is logging
                    is_logging = status_response.get('IsLogging', False)
                    trail['IsLogging'] = is_logging
                    
                    # Get tags
                    try:
                        tags_response = cloudtrail_client.list_tags(ResourceIdList=[trail_arn])
                        for resource_tag in tags_response.get('ResourceTagList', []):
                            if resource_tag.get('ResourceId') == trail_arn:
                                trail['Tags'] = resource_tag.get('TagsList', [])
                    except botocore.exceptions.ClientError as e:
                        logger.warning(f"Failed to get tags for CloudTrail trail {trail_name}: {str(e)}")
                    
                    # Store trail in database
                    db_resource_id = self.store_resource(
                        resource_id=trail_arn,
                        name=trail_name,
                        properties=trail
                    )
                    
                    resource_ids.append((db_resource_id, trail_name))
                    trail_count += 1
                    
                except botocore.exceptions.ClientError as e:
                    logger.error(f"Failed to get details for CloudTrail trail {trail_name}: {str(e)}")
            
            logger.info(f"Discovered {trail_count} CloudTrail trails in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning CloudTrail trails: {error_msg}")
            raise ResourceScanError("trail", self.account_id, self.region, error_msg) 