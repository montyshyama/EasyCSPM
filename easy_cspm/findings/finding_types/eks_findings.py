from ...core.logging_config import logger
from ..base_finding import BaseFinding

class EKSClusterEndpointPublicAccessFinding(BaseFinding):
    """Finding for EKS clusters with public endpoint access"""
    
    def get_finding_type(self):
        return "eks-cluster-endpoint-public-access"
    
    def get_title(self):
        return "EKS Cluster Endpoint Has Public Access"
    
    def get_description(self):
        return "The EKS cluster has public endpoint access enabled without restricted CIDRs. " \
               "This configuration allows anyone on the internet to make API calls to your " \
               "cluster's Kubernetes API server, which could lead to unauthorized access if " \
               "combined with authentication issues."
    
    def get_remediation(self):
        return "Disable public access to the EKS cluster endpoint or restrict access to specific " \
               "CIDR blocks. You can configure this through the AWS Management Console, AWS CLI, " \
               "or SDK. Ensure that private endpoint access is enabled for your cluster."
    
    def get_severity(self):
        return "high"
    
    def evaluate(self, resource):
        """
        Check if EKS cluster has public endpoint access without restrictions
        """
        if resource.service != "eks" or resource.resource_type != "cluster":
            return False, {}
        
        properties = resource.properties
        
        # Check if the cluster has public endpoint access
        vpc_config = properties.get('resourcesVpcConfig', {})
        public_access = vpc_config.get('endpointPublicAccess', False)
        public_access_cidrs = vpc_config.get('publicAccessCidrs', [])
        
        # If public access is enabled and no CIDR restrictions (or 0.0.0.0/0)
        if public_access and ('0.0.0.0/0' in public_access_cidrs or not public_access_cidrs):
            details = {
                "ClusterName": properties.get('name'),
                "EndpointPublicAccess": public_access,
                "PublicAccessCIDRs": public_access_cidrs,
                "EndpointPrivateAccess": vpc_config.get('endpointPrivateAccess', False)
            }
            return True, details
        
        return False, {}

class EKSClusterLoggingDisabledFinding(BaseFinding):
    """Finding for EKS clusters with logging disabled"""
    
    def get_finding_type(self):
        return "eks-cluster-logging-disabled"
    
    def get_title(self):
        return "EKS Cluster Control Plane Logging Not Enabled"
    
    def get_description(self):
        return "Control plane logging is not fully enabled for the EKS cluster. " \
               "Without these logs, it's difficult to audit and troubleshoot issues " \
               "with your cluster's control plane components (API server, audit, " \
               "authenticator, controller manager, scheduler)."
    
    def get_remediation(self):
        return "Enable all control plane logging types for your EKS cluster. " \
               "This can be done through the AWS Management Console, AWS CLI, " \
               "or SDK. Consider sending these logs to a centralized logging solution."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if EKS cluster has all control plane logging enabled
        """
        if resource.service != "eks" or resource.resource_type != "cluster":
            return False, {}
        
        properties = resource.properties
        
        # Check if logging is enabled for all control plane components
        logging = properties.get('logging', {})
        cluster_logging = logging.get('clusterLogging', [])
        
        all_log_types = ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler']
        enabled_log_types = []
        
        for log_config in cluster_logging:
            if log_config.get('enabled', False):
                enabled_log_types.extend(log_config.get('types', []))
        
        missing_log_types = [log_type for log_type in all_log_types if log_type not in enabled_log_types]
        
        if missing_log_types:
            details = {
                "ClusterName": properties.get('name'),
                "EnabledLogTypes": enabled_log_types,
                "MissingLogTypes": missing_log_types
            }
            return True, details
        
        return False, {}

class EKSClusterOldVersionFinding(BaseFinding):
    """Finding for EKS clusters running outdated Kubernetes versions"""
    
    def get_finding_type(self):
        return "eks-cluster-old-version"
    
    def get_title(self):
        return "EKS Cluster Running Outdated Kubernetes Version"
    
    def get_description(self):
        return "The EKS cluster is running an outdated version of Kubernetes. " \
               "Older versions may have known security vulnerabilities, missing " \
               "features, and will eventually reach end-of-support from AWS."
    
    def get_remediation(self):
        return "Upgrade your EKS cluster to a supported Kubernetes version. " \
               "AWS recommends staying within two versions of the latest supported " \
               "Kubernetes version. Plan upgrades carefully, test in a non-production " \
               "environment first, and follow the AWS EKS upgrade documentation."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if EKS cluster is running an outdated K8s version
        """
        if resource.service != "eks" or resource.resource_type != "cluster":
            return False, {}
        
        properties = resource.properties
        
        # Check the Kubernetes version
        current_version = properties.get('version')
        
        # This would need to be regularly updated as new EKS versions are released
        # Example of supported versions as of writing (hypothetical)
        supported_versions = ['1.23', '1.24', '1.25', '1.26', '1.27']
        
        if not current_version:
            return False, {}
        
        # Check if the major.minor version is in the supported list
        version_prefix = '.'.join(current_version.split('.')[:2])
        
        if version_prefix not in supported_versions:
            details = {
                "ClusterName": properties.get('name'),
                "CurrentVersion": current_version,
                "SupportedVersions": supported_versions
            }
            return True, details
        
        return False, {}

class EKSNodeGroupUnencryptedEBSFinding(BaseFinding):
    """Finding for EKS node groups with unencrypted EBS volumes"""
    
    def get_finding_type(self):
        return "eks-nodegroup-unencrypted-ebs"
    
    def get_title(self):
        return "EKS Node Group EBS Volumes Not Encrypted"
    
    def get_description(self):
        return "The EKS node group is configured with unencrypted EBS volumes. " \
               "Unencrypted volumes could expose sensitive data if physical access " \
               "to the storage is obtained or in the event of improper decommissioning."
    
    def get_remediation(self):
        return "Enable EBS volume encryption for the EKS node group. Note that this " \
               "requires creating a new node group, as you cannot modify encryption " \
               "settings for existing nodes. Use AWS KMS for managing the encryption keys."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if EKS node group has encrypted EBS volumes
        """
        if resource.service != "eks" or resource.resource_type != "nodegroup":
            return False, {}
        
        properties = resource.properties
        
        # Check if disk encryption is enabled
        disk_size = properties.get('diskSize')
        encryption_config = properties.get('diskEncryptionConfig', {})
        encryption_enabled = encryption_config.get('enabled', False) if encryption_config else False
        
        # Only applicable for node groups with EBS volumes
        if disk_size and not encryption_enabled:
            details = {
                "NodeGroupName": properties.get('nodegroupName'),
                "ClusterName": properties.get('clusterName'),
                "DiskSize": disk_size,
                "EncryptionEnabled": encryption_enabled
            }
            return True, details
        
        return False, {} 