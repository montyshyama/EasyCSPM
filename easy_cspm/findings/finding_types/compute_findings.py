import ipaddress
from ...core.logging_config import logger
from ..base_finding import BaseFinding
from ...findings.finding_utils import get_property

class EC2PubliclyExposedInstanceFinding(BaseFinding):
    """Finding for EC2 instances that are publicly exposed"""
    
    def get_finding_type(self):
        return "ec2-publicly-exposed-instance"
    
    def get_title(self):
        return "EC2 Instance is Publicly Accessible"
    
    def get_description(self):
        return "The EC2 instance has a public IP address and is potentially accessible from the internet. " \
               "Publicly accessible instances can be a security risk if not properly secured, as they " \
               "are exposed to potential attacks from the internet."
    
    def get_remediation(self):
        return "If the instance does not need to be publicly accessible, modify the instance to use only " \
               "private IP addresses. If public access is required, ensure that security groups and network " \
               "ACLs are configured to restrict access to only necessary ports and source IP addresses. " \
               "Consider using a bastion host or VPN for administrative access."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if EC2 instance has a public IP address
        """
        if resource.service != "ec2" or resource.resource_type != "instance":
            return False, {}
        
        properties = resource.properties
        
        # Check if instance has a public IP
        has_public_ip = False
        public_ip = None
        
        if properties.get('PublicIpAddress'):
            has_public_ip = True
            public_ip = properties.get('PublicIpAddress')
        
        if not has_public_ip:
            return False, {}
        
        details = {
            "PublicIpAddress": public_ip,
            "InstanceId": properties.get('InstanceId'),
            "SubnetId": properties.get('SubnetId'),
            "VpcId": properties.get('VpcId')
        }
        
        return True, details

class EC2UnencryptedVolumesFinding(BaseFinding):
    """Finding for EC2 instances with unencrypted EBS volumes"""
    
    def get_finding_type(self):
        return "ec2-unencrypted-volumes"
    
    def get_title(self):
        return "EC2 Instance Has Unencrypted EBS Volumes"
    
    def get_description(self):
        return "The EC2 instance has one or more EBS volumes that are not encrypted. " \
               "Unencrypted data volumes can pose a security risk as the data is stored in clear text, " \
               "which could be accessed if the physical media is compromised."
    
    def get_remediation(self):
        return "Enable EBS encryption for all volumes. For existing volumes, create a snapshot, " \
               "encrypt the snapshot, and create a new volume from the encrypted snapshot. " \
               "For new volumes, enable encryption by default at the account level or specify encryption " \
               "when creating volumes."
    
    def get_severity(self):
        return "high"
    
    def evaluate(self, resource):
        """
        Check if EC2 instance has unencrypted EBS volumes
        """
        if resource.service != "ec2" or resource.resource_type != "instance":
            return False, {}
        
        properties = resource.properties
        
        unencrypted_volumes = []
        
        for mapping in properties.get('BlockDeviceMappings', []):
            if 'Ebs' in mapping and mapping['Ebs'].get('Status') == 'attached':
                volume_id = mapping['Ebs'].get('VolumeId')
                if not mapping['Ebs'].get('Encrypted', False):
                    unencrypted_volumes.append(volume_id)
        
        if not unencrypted_volumes:
            return False, {}
        
        details = {
            "InstanceId": properties.get('InstanceId'),
            "UnencryptedVolumes": unencrypted_volumes
        }
        
        return True, details

class EC2SecurityGroupIngressAllProtocolsFinding(BaseFinding):
    """Finding for security groups allowing all protocols"""
    
    def get_finding_type(self):
        return "ec2-security-group-ingress-all-protocols"
    
    def get_title(self):
        return "Security Group Allows All Protocols from Any Source"
    
    def get_description(self):
        return "The security group allows inbound traffic for all protocols from any source. " \
               "This is a significant security risk as it allows any kind of traffic from anywhere to reach the instances."
    
    def get_remediation(self):
        return "Modify the security group to allow only specific protocols (TCP, UDP) on specific ports " \
               "from trusted source IP ranges. Apply the principle of least privilege by only allowing " \
               "necessary protocols and ports required for your applications to function."
    
    def get_severity(self):
        return "critical"
    
    def evaluate(self, resource):
        """
        Check if security group allows all protocols from any source
        """
        if resource.service != "ec2" or resource.resource_type != "security_group":
            return False, {}
        
        properties = resource.properties
        risky_rules = []
        
        for rule in properties.get('IpPermissions', []):
            # Check if rule allows all protocols
            if rule.get('IpProtocol', '') == '-1':
                for iprange in rule.get('IpRanges', []):
                    cidr = iprange.get('CidrIp', '')
                    
                    # Check if the CIDR represents a wide range
                    try:
                        network = ipaddress.IPv4Network(cidr)
                        if network.prefixlen < 24 and (cidr == '0.0.0.0/0' or network.is_global):
                            risky_rules.append({
                                'Protocol': 'All',
                                'CidrIp': cidr
                            })
                    except ValueError:
                        # Invalid CIDR
                        pass
        
        if not risky_rules:
            return False, {}
        
        details = {
            "SecurityGroupId": properties.get('GroupId'),
            "SecurityGroupName": properties.get('GroupName'),
            "VpcId": properties.get('VpcId'),
            "RiskyRules": risky_rules
        }
        
        return True, details

class EC2SecurityGroupIngressUnrestrictedSshFinding(BaseFinding):
    """Finding for security groups allowing unrestricted SSH access"""
    
    def get_finding_type(self):
        return "ec2-security-group-ingress-unrestricted-ssh"
    
    def get_title(self):
        return "Security Group Allows Unrestricted SSH Access"
    
    def get_description(self):
        return "The security group allows inbound SSH traffic (TCP port 22) from any source. " \
               "This is a security risk as it potentially allows any IP address on the internet to attempt " \
               "SSH connections to your instances, making them vulnerable to brute force attacks."
    
    def get_remediation(self):
        return "Modify the security group to allow SSH access only from trusted IP addresses or ranges, " \
               "such as your corporate network or VPN. Consider implementing a bastion host or using " \
               "AWS Systems Manager Session Manager for secure instance access instead of direct SSH."
    
    def get_severity(self):
        return "high"
    
    def evaluate(self, resource):
        """Evaluate if a security group allows unrestricted SSH access"""
        try:
            # Skip if not a security group
            if resource.service != "ec2" or resource.resource_type != "security_group":
                return False, {}
                
            # Use the get_property helper 
            ip_permissions = resource.get_property("IpPermissions", [])
            
            for permission in ip_permissions:
                # Check if port 22 is in the range
                from_port = permission.get("FromPort", 0)
                to_port = permission.get("ToPort", 0) 
                
                if (from_port <= 22 <= to_port) or (from_port == 0 and to_port == 0):
                    # Check for unrestricted access
                    for ip_range in permission.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            return True, {
                                "unrestricted_ssh": True,
                                "cidr_ip": "0.0.0.0/0",
                                "protocol": permission.get("IpProtocol"),
                                "port_range": f"{from_port}-{to_port}"
                            }
            
            return False, {"unrestricted_ssh": False}
        except Exception as e:
            logger.error(f"Error evaluating security group {resource.resource_id}: {str(e)}")
            raise

class EC2SecurityGroupIngressUnrestrictedRdpFinding(BaseFinding):
    """Finding for security groups allowing unrestricted RDP access"""
    
    def get_finding_type(self):
        return "ec2-security-group-ingress-unrestricted-rdp"
    
    def get_title(self):
        return "Security Group Allows Unrestricted RDP Access"
    
    def get_description(self):
        return "The security group allows inbound RDP traffic (TCP port 3389) from any source. " \
               "This is a security risk as it potentially allows any IP address on the internet to attempt " \
               "RDP connections to your instances, making them vulnerable to brute force attacks."
    
    def get_remediation(self):
        return "Modify the security group to allow RDP access only from trusted IP addresses or ranges, " \
               "such as your corporate network or VPN. Consider implementing a bastion host or using " \
               "AWS Systems Manager Session Manager for secure instance access instead of direct RDP."
    
    def get_severity(self):
        return "high"
    
    def evaluate(self, resource):
        """
        Check if security group allows unrestricted RDP access
        """
        if resource.service != "ec2" or resource.resource_type != "security_group":
            return False, {}
        
        properties = resource.properties
        risky_rules = []
        
        for rule in properties.get('IpPermissions', []):
            # Check for TCP protocol with port 3389
            if rule.get('IpProtocol') == 'tcp':
                from_port = rule.get('FromPort', 0)
                to_port = rule.get('ToPort', 65535)
                
                if (from_port <= 3389 <= to_port):
                    for iprange in rule.get('IpRanges', []):
                        cidr = iprange.get('CidrIp', '')
                        
                        # Check if CIDR is unrestricted or very broad
                        if cidr == '0.0.0.0/0':
                            risky_rules.append({
                                'Protocol': 'TCP',
                                'PortRange': f"{from_port}-{to_port}",
                                'CidrIp': cidr
                            })
        
        if not risky_rules:
            return False, {}
        
        details = {
            "SecurityGroupId": properties.get('GroupId'),
            "SecurityGroupName": properties.get('GroupName'),
            "VpcId": properties.get('VpcId'),
            "RiskyRules": risky_rules
        }
        
        return True, details

class EC2EBSVolumeUnencryptedFinding(BaseFinding):
    """Finding for unencrypted EBS volumes"""
    
    def get_finding_type(self):
        return "ec2-ebs-volume-unencrypted"
    
    def get_title(self):
        return "EBS Volume is Not Encrypted"
    
    def get_description(self):
        return "The EBS volume is not encrypted. Unencrypted data volumes can pose a security risk as " \
               "the data is stored in clear text, which could be accessed if the physical media is compromised."
    
    def get_remediation(self):
        return "Enable encryption for the volume by creating a snapshot, encrypting the snapshot, " \
               "and creating a new volume from the encrypted snapshot. Then, detach the unencrypted volume " \
               "and attach the encrypted volume to the instance. For new volumes, enable encryption by default " \
               "at the account level or specify encryption when creating volumes."
    
    def get_severity(self):
        return "high"
    
    def evaluate(self, resource):
        """
        Check if EBS volume is unencrypted
        """
        if resource.service != "ec2" or resource.resource_type != "volume":
            return False, {}
        
        properties = resource.properties
        
        # Check if volume is encrypted
        if properties.get('Encrypted', False):
            return False, {}
        
        details = {
            "VolumeId": properties.get('VolumeId'),
            "Size": properties.get('Size'),
            "VolumeType": properties.get('VolumeType'),
            "State": properties.get('State'),
            "AttachedInstances": [attachment.get('InstanceId') for attachment in properties.get('Attachments', [])]
        }
        
        return True, details

class EC2DefaultSecurityGroupInUseFinding(BaseFinding):
    """Finding for default security groups with rules"""
    
    def get_finding_type(self):
        return "ec2-default-security-group-in-use"
    
    def get_title(self):
        return "Default Security Group Has Rules and May Be In Use"
    
    def get_description(self):
        return "The default security group for the VPC has inbound or outbound rules defined, which indicates " \
               "it may be in use. Default security groups are automatically created with each VPC and often " \
               "allow unrestricted outbound traffic and inbound traffic from other resources in the same group. " \
               "Using the default security group is not a best practice from a security perspective."
    
    def get_remediation(self):
        return "Create purpose-specific security groups for your resources rather than using the default " \
               "security group. Remove all rules from the default security group and ensure no resources are " \
               "associated with it. Consider implementing a preventive control using AWS Organizations SCPs or " \
               "AWS Config Rules to prevent the use of default security groups."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if default security group has rules
        """
        if resource.service != "ec2" or resource.resource_type != "security_group":
            return False, {}
        
        properties = resource.properties
        
        # Check if this is a default security group
        if properties.get('GroupName') != 'default':
            return False, {}
        
        # Check if it has any rules
        has_ingress_rules = len(properties.get('IpPermissions', [])) > 0
        has_egress_rules = len(properties.get('IpPermissionsEgress', [])) > 0
        
        if not (has_ingress_rules or has_egress_rules):
            return False, {}
        
        details = {
            "SecurityGroupId": properties.get('GroupId'),
            "VpcId": properties.get('VpcId'),
            "HasIngressRules": has_ingress_rules,
            "HasEgressRules": has_egress_rules
        }
        
        return True, details

class EC2InstanceNoIMDSv2Finding(BaseFinding):
    """Finding for EC2 instances not using IMDSv2"""
    
    def get_finding_type(self):
        return "ec2-instance-no-imdsv2"
    
    def get_title(self):
        return "EC2 Instance Not Configured to Require IMDSv2"
    
    def get_description(self):
        return "The EC2 instance is not configured to require the more secure Instance Metadata Service " \
               "Version 2 (IMDSv2). IMDSv2 provides additional protection against vulnerabilities that " \
               "could be used to access the IMDS, such as server-side request forgery (SSRF)."
    
    def get_remediation(self):
        return "Modify the instance to require IMDSv2 by setting the HttpTokens parameter to 'required'. " \
               "This can be done through the AWS Management Console, AWS CLI, or AWS SDKs. For example, " \
               "using the AWS CLI: aws ec2 modify-instance-metadata-options --instance-id <instance-id> " \
               "--http-tokens required --http-endpoint enabled"
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if EC2 instance requires IMDSv2
        """
        if resource.service != "ec2" or resource.resource_type != "instance":
            return False, {}
        
        properties = resource.properties
        
        # Check if instance has metadata options
        metadata_options = properties.get('MetadataOptions', {})
        
        # Check if IMDSv2 is required
        if metadata_options.get('HttpTokens') == 'required':
            return False, {}
        
        details = {
            "InstanceId": properties.get('InstanceId'),
            "MetadataOptions": metadata_options
        }
        
        return True, details

class EC2PublicAMIFinding(BaseFinding):
    """Finding for public AMIs"""
    
    def get_finding_type(self):
        return "ec2-public-ami"
    
    def get_title(self):
        return "AMI Has Public Launch Permissions"
    
    def get_description(self):
        return "The Amazon Machine Image (AMI) has public launch permissions, allowing anyone with an AWS " \
               "account to launch instances using this AMI. This could potentially expose sensitive data or " \
               "configurations contained within the AMI to unauthorized parties."
    
    def get_remediation(self):
        return "Remove public launch permissions from the AMI using the AWS Management Console, AWS CLI, or AWS SDKs. " \
               "For example, using the AWS CLI: aws ec2 modify-image-attribute --image-id <ami-id> " \
               "--launch-permission '{\"Remove\":[{\"Group\":\"all\"}]}'"
    
    def get_severity(self):
        return "high"
    
    def evaluate(self, resource):
        """
        Check if AMI is public
        """
        if resource.service != "ec2" or resource.resource_type != "ami":
            return False, {}
        
        properties = resource.properties
        
        # Check if AMI is public
        public = False
        
        # Look for public launch permissions
        launch_permissions = properties.get('LaunchPermissions', [])
        for permission in launch_permissions:
            if permission.get('Group') == 'all':
                public = True
                break
        
        if not public:
            return False, {}
        
        details = {
            "ImageId": properties.get('ImageId'),
            "Name": properties.get('Name'),
            "Description": properties.get('Description'),
            "Public": public
        }
        
        return True, details

class EC2EBSOptimizedNotEnabledFinding(BaseFinding):
    """Finding for EC2 instances without EBS optimization enabled"""
    
    def get_finding_type(self):
        return "ec2-ebs-optimization-not-enabled"
    
    def get_title(self):
        return "EC2 Instance Does Not Have EBS Optimization Enabled"
    
    def get_description(self):
        return "The EC2 instance does not have EBS optimization enabled. EBS-optimized instances provide " \
               "dedicated capacity for Amazon EBS I/O, which can improve both the performance of the EBS " \
               "volumes and the reliability of the data transfer."
    
    def get_remediation(self):
        return "Enable EBS optimization for the instance. This can be done by stopping the instance, " \
               "modifying it to enable EBS optimization, and then starting it again. Note that this " \
               "feature is only available for certain instance types, and it is enabled by default " \
               "for many newer instance types."
    
    def get_severity(self):
        return "low"
    
    def evaluate(self, resource):
        """Check if EC2 instance has EBS optimization enabled"""
        # Skip non-EC2 instances
        if resource.service != "ec2" or resource.resource_type != "instance":
            return False
        
        # Get the instance type
        instance_type = get_property(resource, 'properties.instanceType')
        
        # Safety check - if instanceType is None, we can't evaluate this finding
        if instance_type is None:
            logger.warning(f"Could not determine instance type for resource {resource.resource_id}")
            return False
        
        # Check if optimization is enabled
        ebs_optimized = get_property(resource, 'properties.ebsOptimized', False)
        
        # Only evaluate instances that support EBS optimization
        # These instance types include most modern instance types
        if instance_type.startswith('m4.') or instance_type.startswith('c4.') or \
           instance_type.startswith('r4.') or instance_type.startswith('d2.') or \
           instance_type.startswith('m5.') or instance_type.startswith('c5.') or \
           instance_type.startswith('r5.') or instance_type.startswith('t3.') or \
           instance_type.startswith('m6.') or instance_type.startswith('c6.') or \
           instance_type.startswith('r6.'):
            
            # If optimization is not enabled, return a finding
            if not ebs_optimized:
                return {
                    "instance_id": resource.resource_id,
                    "instance_type": instance_type,
                    "ebs_optimized": False
                }
        
        # No finding if optimization is enabled or instance type doesn't support it
        return False 