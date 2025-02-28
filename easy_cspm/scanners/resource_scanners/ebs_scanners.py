import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class EBSVolumeScanner(BaseScanner):
    """Scanner for EBS Volumes"""
    
    def get_service_name(self):
        return "ec2"
    
    def get_resource_type(self):
        return "volume"
    
    def scan(self):
        """Scan EBS Volumes in the current region"""
        try:
            ec2_client = self.aws_client.get_client('ec2')
            paginator = ec2_client.get_paginator('describe_volumes')
            
            volume_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for volume in page.get('Volumes', []):
                    volume_id = volume['VolumeId']
                    
                    try:
                        # Get volume tags
                        volume_name = volume_id
                        if 'Tags' in volume:
                            for tag in volume['Tags']:
                                if tag['Key'] == 'Name':
                                    volume_name = tag['Value']
                                    break
                        
                        # Store volume in database
                        db_resource_id = self.store_resource(
                            resource_id=volume_id,
                            name=volume_name,
                            properties=volume
                        )
                        
                        resource_ids.append((db_resource_id, volume_name))
                        volume_count += 1
                        
                    except botocore.exceptions.ClientError as e:
                        logger.error(f"Failed to get details for EBS volume {volume_id}: {str(e)}")
            
            logger.info(f"Discovered {volume_count} EBS volumes in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning EBS volumes: {error_msg}")
            raise ResourceScanError("volume", self.account_id, self.region, error_msg) 