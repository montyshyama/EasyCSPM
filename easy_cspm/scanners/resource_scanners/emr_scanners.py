import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class EMRClusterScanner(BaseScanner):
    """Scanner for EMR Clusters"""
    
    def get_service_name(self):
        return "emr"
    
    def get_resource_type(self):
        return "cluster"
    
    def scan(self):
        """Scan EMR Clusters in the current region"""
        try:
            emr_client = self.aws_client.get_client('emr')
            paginator = emr_client.get_paginator('list_clusters')
            
            cluster_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for cluster in page.get('Clusters', []):
                    cluster_id = cluster.get('Id')
                    cluster_name = cluster.get('Name')
                    
                    try:
                        # Get detailed information about the cluster
                        cluster_response = emr_client.describe_cluster(ClusterId=cluster_id)
                        cluster_detail = cluster_response.get('Cluster', {})
                        
                        # Get security configuration if exists
                        if 'SecurityConfiguration' in cluster_detail:
                            sec_config_name = cluster_detail.get('SecurityConfiguration')
                            try:
                                sec_config_response = emr_client.describe_security_configuration(
                                    Name=sec_config_name
                                )
                                cluster_detail['SecurityConfigurationDetails'] = sec_config_response.get('SecurityConfiguration')
                            except botocore.exceptions.ClientError as e:
                                logger.warning(f"Failed to get security configuration for EMR cluster {cluster_name}: {str(e)}")
                        
                        # Get instance groups
                        try:
                            groups_paginator = emr_client.get_paginator('list_instance_groups')
                            instance_groups = []
                            
                            for groups_page in groups_paginator.paginate(ClusterId=cluster_id):
                                instance_groups.extend(groups_page.get('InstanceGroups', []))
                            
                            cluster_detail['InstanceGroups'] = instance_groups
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get instance groups for EMR cluster {cluster_name}: {str(e)}")
                        
                        # Get managed scaling policy if exists
                        try:
                            scaling_response = emr_client.get_managed_scaling_policy(
                                ClusterId=cluster_id
                            )
                            cluster_detail['ManagedScalingPolicy'] = scaling_response.get('ManagedScalingPolicy')
                        except botocore.exceptions.ClientError as e:
                            if 'InvalidRequestException' not in str(e):
                                logger.warning(f"Failed to get managed scaling policy for EMR cluster {cluster_name}: {str(e)}")
                        
                        # Store cluster in database
                        db_resource_id = self.store_resource(
                            resource_id=cluster_id,
                            name=cluster_name,
                            properties=cluster_detail
                        )
                        
                        resource_ids.append((db_resource_id, cluster_name))
                        cluster_count += 1
                        
                    except botocore.exceptions.ClientError as e:
                        logger.error(f"Failed to get details for EMR cluster {cluster_name}: {str(e)}")
            
            logger.info(f"Discovered {cluster_count} EMR clusters in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning EMR clusters: {error_msg}")
            raise ResourceScanError("cluster", self.account_id, self.region, error_msg) 