from ...core.logging_config import logger
from ..base_finding import BaseFinding

class RDSInstancePubliclyAccessibleFinding(BaseFinding):
    """Finding for RDS instances that are publicly accessible"""
    
    def get_finding_type(self):
        return "rds-instance-publicly-accessible"
    
    def get_title(self):
        return "RDS Instance Is Publicly Accessible"
    
    def get_description(self):
        return "The RDS database instance is configured to be publicly accessible. " \
               "This means it has a public IP address and can potentially be accessed from the internet, " \
               "which increases the attack surface and risk of unauthorized access."
    
    def get_remediation(self):
        return "Modify the RDS instance to disable public accessibility. This will remove the public IP " \
               "address and make the instance accessible only from within its VPC. If the database needs " \
               "to be accessed from outside the VPC, consider using AWS VPN, Direct Connect, or a bastion host."
    
    def get_severity(self):
        return "high"
    
    def evaluate(self, resource):
        """
        Check if RDS instance is publicly accessible
        """
        if resource.service != "rds" or resource.resource_type != "db_instance":
            return False, {}
        
        properties = resource.properties
        
        # Check if instance is publicly accessible
        is_publicly_accessible = properties.get('PubliclyAccessible', False)
        
        if not is_publicly_accessible:
            return False, {}
        
        details = {
            "DBInstanceIdentifier": properties.get('DBInstanceIdentifier'),
            "Engine": properties.get('Engine'),
            "PubliclyAccessible": is_publicly_accessible,
            "VpcId": properties.get('DBSubnetGroup', {}).get('VpcId')
        }
        
        return True, details

class RDSInstanceEncryptionDisabledFinding(BaseFinding):
    """Finding for RDS instances without encryption enabled"""
    
    def get_finding_type(self):
        return "rds-instance-encryption-disabled"
    
    def get_title(self):
        return "RDS Instance Storage Not Encrypted"
    
    def get_description(self):
        return "The RDS database instance does not have storage encryption enabled. " \
               "Unencrypted database storage could lead to data exposure if the underlying " \
               "physical storage is compromised or if snapshots are accessed by unauthorized users."
    
    def get_remediation(self):
        return "Encryption can only be configured when creating a new RDS instance. To encrypt an existing " \
               "database, create an encrypted snapshot of the database, and then restore the database from " \
               "the encrypted snapshot. This will create a new encrypted database instance."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if RDS instance has encryption enabled
        """
        if resource.service != "rds" or resource.resource_type != "db_instance":
            return False, {}
        
        properties = resource.properties
        
        # Check if storage is encrypted
        is_encrypted = properties.get('StorageEncrypted', False)
        
        if is_encrypted:
            return False, {}
        
        details = {
            "DBInstanceIdentifier": properties.get('DBInstanceIdentifier'),
            "Engine": properties.get('Engine'),
            "StorageEncrypted": is_encrypted
        }
        
        return True, details

class RDSInstanceBackupDisabledFinding(BaseFinding):
    """Finding for RDS instances without automated backups enabled"""
    
    def get_finding_type(self):
        return "rds-instance-backup-disabled"
    
    def get_title(self):
        return "RDS Instance Automated Backups Not Enabled"
    
    def get_description(self):
        return "The RDS database instance does not have automated backups enabled or has a very short " \
               "retention period. Automated backups are essential for point-in-time recovery in case of " \
               "accidental data loss, corruption, or a ransomware attack."
    
    def get_remediation(self):
        return "Modify the RDS instance to enable automated backups and set an appropriate retention period " \
               "(typically 7 days or more). Consider also taking manual snapshots for long-term retention."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if RDS instance has automated backups enabled with adequate retention
        """
        if resource.service != "rds" or resource.resource_type != "db_instance":
            return False, {}
        
        properties = resource.properties
        
        # Check backup retention period (0 means disabled)
        backup_retention_period = properties.get('BackupRetentionPeriod', 0)
        
        # Backups disabled or retention too short (less than 7 days)
        if backup_retention_period >= 7:
            return False, {}
        
        details = {
            "DBInstanceIdentifier": properties.get('DBInstanceIdentifier'),
            "Engine": properties.get('Engine'),
            "BackupRetentionPeriod": backup_retention_period,
            "BackupsEnabled": backup_retention_period > 0
        }
        
        return True, details

class RDSInstanceMultiAZDisabledFinding(BaseFinding):
    """Finding for RDS instances without Multi-AZ enabled"""
    
    def get_finding_type(self):
        return "rds-instance-multi-az-disabled"
    
    def get_title(self):
        return "RDS Instance Multi-AZ Not Enabled"
    
    def get_description(self):
        return "The RDS database instance does not have Multi-AZ deployment enabled. " \
               "Multi-AZ provides enhanced availability and durability by automatically " \
               "maintaining a synchronous standby replica in a different Availability Zone."
    
    def get_remediation(self):
        return "Modify the RDS instance to enable Multi-AZ deployment. This will create a " \
               "standby replica in a different AZ and automatically fail over to it if the " \
               "primary instance becomes unavailable. Note that enabling Multi-AZ may cause " \
               "a brief outage and will increase costs."
    
    def get_severity(self):
        return "low"
    
    def evaluate(self, resource):
        """
        Check if RDS instance has Multi-AZ enabled
        """
        if resource.service != "rds" or resource.resource_type != "db_instance":
            return False, {}
        
        properties = resource.properties
        
        # Skip read replicas
        if properties.get('ReadReplicaSource'):
            return False, {}
        
        # Check if Multi-AZ is enabled
        is_multi_az = properties.get('MultiAZ', False)
        
        if is_multi_az:
            return False, {}
        
        details = {
            "DBInstanceIdentifier": properties.get('DBInstanceIdentifier'),
            "Engine": properties.get('Engine'),
            "MultiAZ": is_multi_az
        }
        
        return True, details

class RDSSnapshotPublicFinding(BaseFinding):
    """Finding for RDS snapshots that are publicly accessible"""
    
    def get_finding_type(self):
        return "rds-snapshot-public"
    
    def get_title(self):
        return "RDS Snapshot Is Publicly Accessible"
    
    def get_description(self):
        return "The RDS database snapshot is shared publicly, making it accessible to all AWS accounts. " \
               "Public snapshots expose your database schema and potentially sensitive configuration " \
               "details, which could be used by an attacker to target your database."
    
    def get_remediation(self):
        return "Modify the snapshot's sharing settings to remove public accessibility. " \
               "If the snapshot needs to be shared, share it only with specific AWS accounts."
    
    def get_severity(self):
        return "critical"
    
    def evaluate(self, resource):
        """
        Check if RDS snapshot is publicly accessible
        """
        if resource.service != "rds" or resource.resource_type != "db_snapshot":
            return False, {}
        
        properties = resource.properties
        
        # Check if snapshot is public
        is_public = False
        
        # In the actual properties, this might be in different format
        if 'AttributeValues' in properties:
            for attribute in properties['AttributeValues']:
                if attribute.get('AttributeName') == 'restore' and 'all' in attribute.get('AttributeValue', ''):
                    is_public = True
                    break
        
        # Alternative check
        if properties.get('SnapshotAttributes'):
            for attribute in properties.get('SnapshotAttributes', []):
                if attribute.get('AttributeName') == 'restore' and 'all' in attribute.get('AttributeValues', []):
                    is_public = True
                    break
        
        if not is_public:
            return False, {}
        
        details = {
            "DBSnapshotIdentifier": properties.get('DBSnapshotIdentifier'),
            "Engine": properties.get('Engine'),
            "IsPublic": is_public
        }
        
        return True, details 