import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class RedshiftClusterScanner(BaseScanner):
    """Scanner for Redshift Clusters"""
    
    def get_service_name(self):
        return "redshift"
    
    def get_resource_type(self):
        return "cluster"
    
    def scan(self):
        """Scan Redshift Clusters in the current region"""
        try:
            redshift_client = self.aws_client.get_client('redshift')
            paginator = redshift_client.get_paginator('describe_clusters')
            
            cluster_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for cluster in page.get('Clusters', []):
                    cluster_id = cluster['ClusterIdentifier']
                    
                    try:
                        # Get logging status
                        try:
                            logging_response = redshift_client.describe_logging_status(ClusterIdentifier=cluster_id)
                            cluster['LoggingStatus'] = logging_response
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get logging status for Redshift cluster {cluster_id}: {str(e)}")
                        
                        # Get cluster snapshot
                        try:
                            snapshot_paginator = redshift_client.get_paginator('describe_cluster_snapshots')
                            snapshots = []
                            
                            for snapshot_page in snapshot_paginator.paginate(ClusterIdentifier=cluster_id):
                                snapshots.extend(snapshot_page.get('Snapshots', []))
                            
                            cluster['Snapshots'] = snapshots
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get snapshots for Redshift cluster {cluster_id}: {str(e)}")
                        
                        # Get tags
                        try:
                            tags_response = redshift_client.describe_tags(ResourceName=cluster['ClusterNamespaceArn'])
                            cluster['Tags'] = tags_response.get('TaggedResources', [])
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get tags for Redshift cluster {cluster_id}: {str(e)}")
                        
                        # Store cluster in database
                        db_resource_id = self.store_resource(
                            resource_id=cluster_id,
                            name=cluster_id,
                            properties=cluster
                        )
                        
                        resource_ids.append((db_resource_id, cluster_id))
                        cluster_count += 1
                        
                    except botocore.exceptions.ClientError as e:
                        logger.error(f"Failed to get details for Redshift cluster {cluster_id}: {str(e)}")
            
            logger.info(f"Discovered {cluster_count} Redshift clusters in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning Redshift clusters: {error_msg}")
            raise ResourceScanError("cluster", self.account_id, self.region, error_msg) 