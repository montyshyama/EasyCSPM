from ...core.logging_config import logger
from ..base_finding import BaseFinding

class EMRClusterNoEncryptionFinding(BaseFinding):
    """Finding for EMR clusters without encryption"""
    
    def get_finding_type(self):
        return "emr-cluster-no-encryption"
    
    def get_title(self):
        return "EMR Cluster Without Encryption"
    
    def get_description(self):
        return "The EMR cluster does not have encryption enabled for data at rest or in transit. " \
               "Unencrypted data can be exposed if unauthorized access to the cluster or its " \
               "underlying storage is obtained, potentially compromising sensitive information."
    
    def get_remediation(self):
        return "Configure encryption for both data at rest and in transit for the EMR cluster. " \
               "This can be done by creating a security configuration that specifies encryption " \
               "settings and applying it to the cluster. Note that encryption must be configured " \
               "when creating a cluster; you cannot enable it for an existing cluster."
    
    def get_severity(self):
        return "high"
    
    def evaluate(self, resource):
        """
        Check if EMR cluster has encryption enabled
        """
        if resource.service != "emr" or resource.resource_type != "cluster":
            return False, {}
        
        properties = resource.properties
        
        # Check if security configuration exists and includes encryption
        sec_config = properties.get('SecurityConfiguration')
        sec_config_details = properties.get('SecurityConfigurationDetails')
        
        # Assume no encryption if no security configuration is specified
        if not sec_config:
            details = {
                "ClusterId": properties.get('Id'),
                "ClusterName": properties.get('Name'),
                "EncryptionEnabled": False,
                "SecurityConfigurationPresent": False
            }
            return True, details
        
        # If we have security config details, check for encryption settings
        if sec_config_details:
            try:
                # Parse the JSON if it's a string
                if isinstance(sec_config_details, str):
                    import json
                    sec_config_details = json.loads(sec_config_details)
                
                # Check if encryption is configured
                encryption_config = sec_config_details.get('EncryptionConfiguration', {})
                at_rest_encryption = encryption_config.get('EnableAtRestEncryption', False)
                in_transit_encryption = encryption_config.get('EnableInTransitEncryption', False)
                
                if not (at_rest_encryption and in_transit_encryption):
                    details = {
                        "ClusterId": properties.get('Id'),
                        "ClusterName": properties.get('Name'),
                        "EncryptionEnabled": False,
                        "SecurityConfigurationPresent": True,
                        "AtRestEncryption": at_rest_encryption,
                        "InTransitEncryption": in_transit_encryption
                    }
                    return True, details
            except Exception as e:
                logger.warning(f"Failed to parse security configuration for EMR cluster: {str(e)}")
        
        return False, {}

class EMRClusterPubliclyAccessibleFinding(BaseFinding):
    """Finding for EMR clusters that are publicly accessible"""
    
    def get_finding_type(self):
        return "emr-cluster-publicly-accessible"
    
    def get_title(self):
        return "EMR Cluster Is Publicly Accessible"
    
    def get_description(self):
        return "The EMR cluster appears to be publicly accessible, which increases the " \
               "attack surface and risk of unauthorized access. EMR clusters should be " \
               "deployed in private subnets where possible, with controlled access through " \
               "bastion hosts or VPN."
    
    def get_remediation(self):
        return "Reconfigure the EMR cluster to use private subnets only, and ensure that " \
               "access to the cluster is restricted through security groups, network ACLs, " \
               "and other network controls. Consider using an EMR-compatible VPC endpoint " \
               "for AWS service access without requiring public internet connectivity."
    
    def get_severity(self):
        return "high"
    
    def evaluate(self, resource):
        """
        Check if EMR cluster is potentially publicly accessible
        """
        if resource.service != "emr" or resource.resource_type != "cluster":
            return False, {}
        
        properties = resource.properties
        
        # Check EC2 attributes to determine network configuration
        ec2_attributes = properties.get('Ec2InstanceAttributes', {})
        
        # Check if the cluster is in a VPC
        is_in_vpc = ec2_attributes.get('Ec2AvailabilityZone') is not None
        
        # If not in a VPC, it's using EC2-Classic, which is inherently more publicly accessible
        if not is_in_vpc:
            details = {
                "ClusterId": properties.get('Id'),
                "ClusterName": properties.get('Name'),
                "IsInVpc": False,
                "PubliclyAccessible": True,
                "ReasonForFinding": "Cluster is using EC2-Classic networking, which is inherently less secure"
            }
            return True, details
        
        # No direct way to determine if a subnet is public from EMR properties
        # Instead, check if master and core nodes are assigned public IP addresses
        instances = properties.get('Instances', {})
        master_public_dns = instances.get('MasterPublicDnsName')
        
        if master_public_dns:
            details = {
                "ClusterId": properties.get('Id'),
                "ClusterName": properties.get('Name'),
                "IsInVpc": True,
                "PubliclyAccessible": True,
                "MasterPublicDnsName": master_public_dns,
                "ReasonForFinding": "Master node has a public DNS name"
            }
            return True, details
        
        return False, {}

class EMRClusterNoKerberosOrIAMFinding(BaseFinding):
    """Finding for EMR clusters without Kerberos or IAM authentication"""
    
    def get_finding_type(self):
        return "emr-cluster-no-kerberos-or-iam"
    
    def get_title(self):
        return "EMR Cluster Without Kerberos or IAM Authentication"
    
    def get_description(self):
        return "The EMR cluster is not configured with Kerberos or IAM authentication. " \
               "Without these authentication mechanisms, access to the cluster and its " \
               "services may not be properly controlled, which can lead to unauthorized " \
               "access and potential data breaches."
    
    def get_remediation(self):
        return "Configure Kerberos or IAM authentication for the EMR cluster. For Kerberos, " \
               "set up a Kerberos realm and configure the cluster to use it. For IAM authentication, " \
               "enable IAM roles for EMRFS. Note that authentication methods must be configured " \
               "when creating a cluster; you cannot enable them for an existing cluster."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if EMR cluster has Kerberos or IAM authentication enabled
        """
        if resource.service != "emr" or resource.resource_type != "cluster":
            return False, {}
        
        properties = resource.properties
        
        # Check for Kerberos configuration
        kerberos_attributes = properties.get('KerberosAttributes', {})
        has_kerberos = kerberos_attributes is not None and len(kerberos_attributes) > 0
        
        # Check for IAM roles for EMRFS
        configurations = properties.get('Configurations', [])
        has_iam_emrfs = False
        
        for config in configurations:
            if config.get('Classification') == 'emrfs-site':
                properties_dict = config.get('Properties', {})
                if 'fs.s3.enableServerSideEncryption' in properties_dict or 'fs.s3.awsIamRole' in properties_dict:
                    has_iam_emrfs = True
                    break
        
        if not (has_kerberos or has_iam_emrfs):
            details = {
                "ClusterId": properties.get('Id'),
                "ClusterName": properties.get('Name'),
                "HasKerberos": has_kerberos,
                "HasIAMForEMRFS": has_iam_emrfs
            }
            return True, details
        
        return False, {} 