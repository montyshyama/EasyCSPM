from ...core.logging_config import logger
from ..base_finding import BaseFinding

class ElastiCacheRedisClusterEncryptionDisabledFinding(BaseFinding):
    """Finding for ElastiCache Redis clusters without encryption"""
    
    def get_finding_type(self):
        return "elasticache-redis-encryption-disabled"
    
    def get_title(self):
        return "ElastiCache Redis Cluster Not Encrypted"
    
    def get_description(self):
        return "The ElastiCache Redis cluster does not have encryption enabled. " \
               "Unencrypted Redis clusters may expose sensitive data and do not " \
               "meet security best practices or compliance requirements for data " \
               "protection."
    
    def get_remediation(self):
        return "Enable encryption for the ElastiCache Redis cluster. Note that " \
               "encryption cannot be enabled for an existing cluster, so you will " \
               "need to create a new cluster with encryption enabled and migrate " \
               "your data. Choose both encryption in transit and encryption at rest."
    
    def get_severity(self):
        return "high"
    
    def evaluate(self, resource):
        """
        Check if ElastiCache Redis cluster has encryption enabled
        """
        if resource.service != "elasticache" or resource.resource_type != "cluster":
            return False, {}
        
        # Skip if not Redis
        properties = resource.properties
        if properties.get('Engine') != 'redis':
            return False, {}
        
        # Check if encryption is enabled
        is_transit_encrypted = properties.get('TransitEncryptionEnabled', False)
        is_at_rest_encrypted = properties.get('AtRestEncryptionEnabled', False)
        
        if is_transit_encrypted and is_at_rest_encrypted:
            return False, {}
        
        details = {
            "ClusterId": properties.get('CacheClusterId'),
            "Engine": properties.get('Engine'),
            "EngineVersion": properties.get('EngineVersion'),
            "TransitEncryptionEnabled": is_transit_encrypted,
            "AtRestEncryptionEnabled": is_at_rest_encrypted
        }
        
        return True, details

class ElastiCacheRedisClusterAutomaticBackupsDisabledFinding(BaseFinding):
    """Finding for ElastiCache Redis clusters without automatic backups"""
    
    def get_finding_type(self):
        return "elasticache-redis-automatic-backups-disabled"
    
    def get_title(self):
        return "ElastiCache Redis Cluster Automatic Backups Not Enabled"
    
    def get_description(self):
        return "The ElastiCache Redis cluster does not have automatic backups enabled, " \
               "or the retention period is too short. Automatic backups are important for " \
               "data recovery in case of failure and should be enabled for production " \
               "workloads."
    
    def get_remediation(self):
        return "Enable automatic backups for the ElastiCache Redis cluster and set an " \
               "appropriate retention period (e.g., 7 days). This can be done from the " \
               "AWS Management Console, AWS CLI, or SDK."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if ElastiCache Redis cluster has automatic backups enabled with sufficient retention period
        """
        if resource.service != "elasticache" or resource.resource_type != "cluster":
            return False, {}
        
        # Skip if not Redis
        properties = resource.properties
        if properties.get('Engine') != 'redis':
            return False, {}
        
        # Check if automatic backups are enabled with sufficient retention period
        snapshot_retention_limit = properties.get('SnapshotRetentionLimit', 0)
        
        if snapshot_retention_limit >= 7:
            return False, {}
        
        details = {
            "ClusterId": properties.get('CacheClusterId'),
            "Engine": properties.get('Engine'),
            "SnapshotRetentionLimit": snapshot_retention_limit,
            "RecommendedRetentionLimit": 7
        }
        
        return True, details 