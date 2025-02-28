import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class RDSInstanceScanner(BaseScanner):
    """Scanner for RDS DB Instances"""
    
    def get_service_name(self):
        return "rds"
    
    def get_resource_type(self):
        return "db_instance"
    
    def scan(self):
        """Scan RDS DB Instances in the current region"""
        try:
            rds_client = self.aws_client.get_client('rds')
            paginator = rds_client.get_paginator('describe_db_instances')
            
            instance_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for db_instance in page.get('DBInstances', []):
                    db_id = db_instance['DBInstanceIdentifier']
                    
                    # Store DB instance in database
                    db_resource_id = self.store_resource(
                        resource_id=db_id,
                        name=db_id,
                        properties=db_instance
                    )
                    
                    resource_ids.append((db_resource_id, db_id))
                    instance_count += 1
            
            logger.info(f"Discovered {instance_count} RDS DB Instances in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning RDS DB Instances: {error_msg}")
            raise ResourceScanError("db_instance", self.account_id, self.region, error_msg)

class RDSClusterScanner(BaseScanner):
    """Scanner for RDS DB Clusters"""
    
    def get_service_name(self):
        return "rds"
    
    def get_resource_type(self):
        return "db_cluster"
    
    def scan(self):
        """Scan RDS DB Clusters in the current region"""
        try:
            rds_client = self.aws_client.get_client('rds')
            paginator = rds_client.get_paginator('describe_db_clusters')
            
            cluster_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for db_cluster in page.get('DBClusters', []):
                    cluster_id = db_cluster['DBClusterIdentifier']
                    
                    # Store DB cluster in database
                    db_resource_id = self.store_resource(
                        resource_id=cluster_id,
                        name=cluster_id,
                        properties=db_cluster
                    )
                    
                    resource_ids.append((db_resource_id, cluster_id))
                    cluster_count += 1
            
            logger.info(f"Discovered {cluster_count} RDS DB Clusters in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning RDS DB Clusters: {error_msg}")
            raise ResourceScanError("db_cluster", self.account_id, self.region, error_msg)

class RDSSnapshotScanner(BaseScanner):
    """Scanner for RDS DB Snapshots"""
    
    def get_service_name(self):
        return "rds"
    
    def get_resource_type(self):
        return "db_snapshot"
    
    def scan(self):
        """Scan RDS DB Snapshots in the current region"""
        try:
            rds_client = self.aws_client.get_client('rds')
            paginator = rds_client.get_paginator('describe_db_snapshots')
            
            snapshot_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for snapshot in page.get('DBSnapshots', []):
                    snapshot_id = snapshot['DBSnapshotIdentifier']
                    
                    # Store DB snapshot in database
                    db_resource_id = self.store_resource(
                        resource_id=snapshot_id,
                        name=snapshot_id,
                        properties=snapshot
                    )
                    
                    resource_ids.append((db_resource_id, snapshot_id))
                    snapshot_count += 1
            
            logger.info(f"Discovered {snapshot_count} RDS DB Snapshots in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning RDS DB Snapshots: {error_msg}")
            raise ResourceScanError("db_snapshot", self.account_id, self.region, error_msg) 