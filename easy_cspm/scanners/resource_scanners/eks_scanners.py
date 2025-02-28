import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class EKSClusterScanner(BaseScanner):
    """Scanner for EKS Clusters"""
    
    def get_service_name(self):
        return "eks"
    
    def get_resource_type(self):
        return "cluster"
    
    def scan(self):
        """Scan EKS Clusters in the current region"""
        try:
            eks_client = self.aws_client.get_client('eks')
            paginator = eks_client.get_paginator('list_clusters')
            
            cluster_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for cluster_name in page.get('clusters', []):
                    try:
                        # Get detailed information about the cluster
                        cluster_response = eks_client.describe_cluster(name=cluster_name)
                        cluster = cluster_response.get('cluster', {})
                        
                        # Get cluster add-ons
                        try:
                            addons_response = eks_client.list_addons(clusterName=cluster_name)
                            cluster['addons'] = addons_response.get('addons', [])
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get addons for EKS cluster {cluster_name}: {str(e)}")
                        
                        # Get node groups
                        try:
                            nodegroups_paginator = eks_client.get_paginator('list_nodegroups')
                            nodegroups = []
                            
                            for nodegroups_page in nodegroups_paginator.paginate(clusterName=cluster_name):
                                nodegroups.extend(nodegroups_page.get('nodegroups', []))
                            
                            cluster['nodegroups'] = nodegroups
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get nodegroups for EKS cluster {cluster_name}: {str(e)}")
                        
                        # Store cluster in database
                        db_resource_id = self.store_resource(
                            resource_id=cluster.get('arn'),
                            name=cluster_name,
                            properties=cluster
                        )
                        
                        resource_ids.append((db_resource_id, cluster_name))
                        cluster_count += 1
                        
                    except botocore.exceptions.ClientError as e:
                        logger.error(f"Failed to get details for EKS cluster {cluster_name}: {str(e)}")
            
            logger.info(f"Discovered {cluster_count} EKS clusters in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning EKS clusters: {error_msg}")
            raise ResourceScanError("cluster", self.account_id, self.region, error_msg)

class EKSNodeGroupScanner(BaseScanner):
    """Scanner for EKS Node Groups"""
    
    def get_service_name(self):
        return "eks"
    
    def get_resource_type(self):
        return "nodegroup"
    
    def scan(self):
        """Scan EKS Node Groups in the current region"""
        try:
            eks_client = self.aws_client.get_client('eks')
            clusters_paginator = eks_client.get_paginator('list_clusters')
            
            nodegroup_count = 0
            resource_ids = []
            
            for clusters_page in clusters_paginator.paginate():
                for cluster_name in clusters_page.get('clusters', []):
                    try:
                        nodegroups_paginator = eks_client.get_paginator('list_nodegroups')
                        
                        for nodegroups_page in nodegroups_paginator.paginate(clusterName=cluster_name):
                            for nodegroup_name in nodegroups_page.get('nodegroups', []):
                                try:
                                    # Get detailed information about the nodegroup
                                    nodegroup_response = eks_client.describe_nodegroup(
                                        clusterName=cluster_name,
                                        nodegroupName=nodegroup_name
                                    )
                                    nodegroup = nodegroup_response.get('nodegroup', {})
                                    
                                    # Store nodegroup in database
                                    db_resource_id = self.store_resource(
                                        resource_id=nodegroup.get('nodegroupArn'),
                                        name=nodegroup_name,
                                        properties=nodegroup
                                    )
                                    
                                    resource_ids.append((db_resource_id, nodegroup_name))
                                    nodegroup_count += 1
                                    
                                except botocore.exceptions.ClientError as e:
                                    logger.error(f"Failed to get details for EKS nodegroup {nodegroup_name} in cluster {cluster_name}: {str(e)}")
                    except botocore.exceptions.ClientError as e:
                        logger.error(f"Failed to list nodegroups for EKS cluster {cluster_name}: {str(e)}")
            
            logger.info(f"Discovered {nodegroup_count} EKS nodegroups in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning EKS nodegroups: {error_msg}")
            raise ResourceScanError("nodegroup", self.account_id, self.region, error_msg) 