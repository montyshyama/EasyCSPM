import ipaddress
from ...core.logging_config import logger
from ..base_finding import BaseFinding

class VPCFlowLogsDisabledFinding(BaseFinding):
    """Finding for VPCs without flow logs enabled"""
    
    def get_finding_type(self):
        return "vpc-flow-logs-disabled"
    
    def get_title(self):
        return "VPC Flow Logs Not Enabled"
    
    def get_description(self):
        return "VPC Flow Logs are not enabled for the VPC. Flow logs capture information about the IP traffic " \
               "going to and from network interfaces in your VPC, which can be valuable for troubleshooting, " \
               "security analysis, and compliance verification."
    
    def get_remediation(self):
        return "Enable VPC Flow Logs for the VPC. You can configure flow logs to be delivered to Amazon CloudWatch " \
               "Logs or Amazon S3. When creating flow logs, you can specify whether to capture accepted traffic, " \
               "rejected traffic, or all traffic."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if VPC has flow logs enabled
        """
        if resource.service != "ec2" or resource.resource_type != "vpc":
            return False, {}
        
        properties = resource.properties
        
        # In a real implementation, you would need to query for flow logs
        # This is a simplified check based on available properties
        has_flow_logs = False
        if 'FlowLogs' in properties and properties['FlowLogs']:
            has_flow_logs = True
        
        if has_flow_logs:
            return False, {}
        
        details = {
            "VpcId": properties.get('VpcId'),
            "CidrBlock": properties.get('CidrBlock')
        }
        
        return True, details

class PublicSubnetRouteToIGWFinding(BaseFinding):
    """Finding for public subnets with routes to Internet Gateway"""
    
    def get_finding_type(self):
        return "subnet-public-route-to-igw"
    
    def get_title(self):
        return "Subnet Has Public Route to Internet Gateway"
    
    def get_description(self):
        return "The subnet has a route table entry that directs traffic to an Internet Gateway, making it a " \
               "public subnet. Resources in this subnet, if assigned a public IP address, will be accessible " \
               "from the internet."
    
    def get_remediation(self):
        return "If the subnet should not be public, remove the route to the Internet Gateway from the associated " \
               "route table. If internet access is required but direct inbound access is not, consider using a NAT " \
               "Gateway instead, which allows outbound internet access while preventing inbound connections."
    
    def get_severity(self):
        return "informational"
    
    def evaluate(self, resource):
        """
        Check if subnet has a route to an Internet Gateway
        """
        if resource.service != "ec2" or resource.resource_type != "subnet":
            return False, {}
        
        # This check requires additional context about route tables
        # In a real implementation, you would get the associated route table and check its routes
        # For this example, we'll assume we have route table information in the properties
        
        properties = resource.properties
        has_igw_route = False
        
        # Example to simulate checking route table associations
        if 'RouteTableAssociations' in properties:
            for association in properties['RouteTableAssociations']:
                for route in association.get('Routes', []):
                    if route.get('GatewayId', '').startswith('igw-'):
                        has_igw_route = True
                        break
        
        if not has_igw_route:
            return False, {}
        
        details = {
            "SubnetId": properties.get('SubnetId'),
            "VpcId": properties.get('VpcId'),
            "CidrBlock": properties.get('CidrBlock'),
            "IsPublic": True
        }
        
        return True, details

class VPCPeeringUnrestrictedAccessFinding(BaseFinding):
    """Finding for VPC peering connections with unrestricted access"""
    
    def get_finding_type(self):
        return "vpc-peering-unrestricted-access"
    
    def get_title(self):
        return "VPC Peering Connection Has Unrestricted Access"
    
    def get_description(self):
        return "The VPC has a peering connection that allows unrestricted access between VPCs. " \
               "This could potentially allow resources in one VPC to access all resources in the peered VPC, " \
               "which may violate the principle of least privilege."
    
    def get_remediation(self):
        return "Modify the route tables for the VPC peering connection to only allow traffic to " \
               "specific subnets or IP ranges that are required for your use case. Update network ACLs " \
               "and security groups to further restrict traffic between VPCs."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if VPC has peering connections with unrestricted access
        """
        if resource.service != "ec2" or resource.resource_type != "vpc":
            return False, {}
        
        properties = resource.properties
        overly_permissive_peering = False
        
        # Check for VPC peering connections (simulated)
        if 'VpcPeeringConnections' in properties:
            for peering in properties['VpcPeeringConnections']:
                # Check if routes allow full CIDR block access between VPCs
                if peering.get('AllowsFullCidrBlockAccess', False):
                    overly_permissive_peering = True
                    break
        
        if not overly_permissive_peering:
            return False, {}
        
        details = {
            "VpcId": properties.get('VpcId'),
            "CidrBlock": properties.get('CidrBlock')
        }
        
        return True, details

class DefaultNetworkACLAllowAllFinding(BaseFinding):
    """Finding for default Network ACLs with allow all rules"""
    
    def get_finding_type(self):
        return "default-network-acl-allow-all"
    
    def get_title(self):
        return "Default Network ACL Allows All Traffic"
    
    def get_description(self):
        return "The default Network ACL for the VPC allows all inbound and/or outbound traffic. This could " \
               "potentially allow unauthorized access to resources if a subnet is intentionally or accidentally " \
               "associated with the default Network ACL."
    
    def get_remediation(self):
        return "Modify the default Network ACL to deny all traffic and create custom Network ACLs with specific " \
               "allow rules for your subnets. Ensure all subnets are associated with appropriate custom Network ACLs."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if default Network ACL allows all traffic
        """
        # This would need access to Network ACL resources which we haven't scanned yet
        # For example purposes, we'll simulate a check
        if resource.service != "ec2" or resource.resource_type != "vpc":
            return False, {}
        
        properties = resource.properties
        default_acl_allows_all = False
        
        # Check if default ACL allows all traffic (simulated)
        if 'DefaultNetworkAcl' in properties:
            default_acl = properties['DefaultNetworkAcl']
            if default_acl.get('AllowsAllTraffic', False):
                default_acl_allows_all = True
        
        if not default_acl_allows_all:
            return False, {}
        
        details = {
            "VpcId": properties.get('VpcId'),
            "CidrBlock": properties.get('CidrBlock')
        }
        
        return True, details

class InternetGatewayUnrestrictedFinding(BaseFinding):
    """Finding for Internet Gateways with unrestricted routing"""
    
    def get_finding_type(self):
        return "internet-gateway-unrestricted"
    
    def get_title(self):
        return "Internet Gateway Has Unrestricted Routing"
    
    def get_description(self):
        return "The Internet Gateway is associated with a VPC that has unrestricted routing to the gateway. " \
               "This configuration could potentially allow all subnets in the VPC to have direct internet access, " \
               "which may not be intended for private or isolated subnets."
    
    def get_remediation(self):
        return "Review the route tables in the VPC and ensure that only subnets that require internet access " \
               "have routes to the Internet Gateway. Consider implementing a network design with public and " \
               "private subnets, where private subnets access the internet through a NAT Gateway."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if Internet Gateway has unrestricted routing
        """
        if resource.service != "ec2" or resource.resource_type != "internet_gateway":
            return False, {}
        
        # This requires additional context about route tables
        # For example purposes, we'll simulate a check
        properties = resource.properties
        unrestricted_routing = False
        
        # Check attached VPCs and their route tables (simulated)
        for attachment in properties.get('Attachments', []):
            vpc_id = attachment.get('VpcId')
            if not vpc_id:
                continue
                
            # Simulate checking route tables for this VPC
            if 'RouteTableAccess' in properties and vpc_id in properties['RouteTableAccess']:
                if properties['RouteTableAccess'][vpc_id].get('AllSubnetsHaveIgwRoute', False):
                    unrestricted_routing = True
                    break
        
        if not unrestricted_routing:
            return False, {}
        
        details = {
            "InternetGatewayId": properties.get('InternetGatewayId'),
            "AttachedVpcs": [att.get('VpcId') for att in properties.get('Attachments', [])]
        }
        
        return True, details 