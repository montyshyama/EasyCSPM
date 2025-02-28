import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class VPCScanner(BaseScanner):
    """Scanner for VPCs"""
    
    def get_service_name(self):
        return "ec2"
    
    def get_resource_type(self):
        return "vpc"
    
    def scan(self):
        """Scan VPCs in the current region"""
        try:
            ec2_client = self.aws_client.get_client('ec2')
            paginator = ec2_client.get_paginator('describe_vpcs')
            
            vpc_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for vpc in page.get('Vpcs', []):
                    vpc_id = vpc['VpcId']
                    
                    # Get VPC name from tags
                    vpc_name = None
                    for tag in vpc.get('Tags', []):
                        if tag['Key'] == 'Name':
                            vpc_name = tag['Value']
                            break
                    
                    # Store VPC in database
                    db_resource_id = self.store_resource(
                        resource_id=vpc_id,
                        name=vpc_name or vpc_id,
                        properties=vpc
                    )
                    
                    resource_ids.append((db_resource_id, vpc_id))
                    vpc_count += 1
            
            logger.info(f"Discovered {vpc_count} VPCs in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning VPCs: {error_msg}")
            raise ResourceScanError("vpc", self.account_id, self.region, error_msg)

class SubnetScanner(BaseScanner):
    """Scanner for Subnets"""
    
    def get_service_name(self):
        return "ec2"
    
    def get_resource_type(self):
        return "subnet"
    
    def scan(self):
        """Scan Subnets in the current region"""
        try:
            ec2_client = self.aws_client.get_client('ec2')
            paginator = ec2_client.get_paginator('describe_subnets')
            
            subnet_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for subnet in page.get('Subnets', []):
                    subnet_id = subnet['SubnetId']
                    
                    # Get Subnet name from tags
                    subnet_name = None
                    for tag in subnet.get('Tags', []):
                        if tag['Key'] == 'Name':
                            subnet_name = tag['Value']
                            break
                    
                    # Store Subnet in database
                    db_resource_id = self.store_resource(
                        resource_id=subnet_id,
                        name=subnet_name or subnet_id,
                        properties=subnet
                    )
                    
                    resource_ids.append((db_resource_id, subnet_id))
                    subnet_count += 1
            
            logger.info(f"Discovered {subnet_count} Subnets in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning Subnets: {error_msg}")
            raise ResourceScanError("subnet", self.account_id, self.region, error_msg)

class RouteTableScanner(BaseScanner):
    """Scanner for Route Tables"""
    
    def get_service_name(self):
        return "ec2"
    
    def get_resource_type(self):
        return "route_table"
    
    def scan(self):
        """Scan Route Tables in the current region"""
        try:
            ec2_client = self.aws_client.get_client('ec2')
            paginator = ec2_client.get_paginator('describe_route_tables')
            
            rtb_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for rtb in page.get('RouteTables', []):
                    rtb_id = rtb['RouteTableId']
                    
                    # Get Route Table name from tags
                    rtb_name = None
                    for tag in rtb.get('Tags', []):
                        if tag['Key'] == 'Name':
                            rtb_name = tag['Value']
                            break
                    
                    # Store Route Table in database
                    db_resource_id = self.store_resource(
                        resource_id=rtb_id,
                        name=rtb_name or rtb_id,
                        properties=rtb
                    )
                    
                    resource_ids.append((db_resource_id, rtb_id))
                    rtb_count += 1
            
            logger.info(f"Discovered {rtb_count} Route Tables in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning Route Tables: {error_msg}")
            raise ResourceScanError("route_table", self.account_id, self.region, error_msg)

class InternetGatewayScanner(BaseScanner):
    """Scanner for Internet Gateways"""
    
    def get_service_name(self):
        return "ec2"
    
    def get_resource_type(self):
        return "internet_gateway"
    
    def scan(self):
        """Scan Internet Gateways in the current region"""
        try:
            ec2_client = self.aws_client.get_client('ec2')
            paginator = ec2_client.get_paginator('describe_internet_gateways')
            
            igw_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for igw in page.get('InternetGateways', []):
                    igw_id = igw['InternetGatewayId']
                    
                    # Get IGW name from tags
                    igw_name = None
                    for tag in igw.get('Tags', []):
                        if tag['Key'] == 'Name':
                            igw_name = tag['Value']
                            break
                    
                    # Store IGW in database
                    db_resource_id = self.store_resource(
                        resource_id=igw_id,
                        name=igw_name or igw_id,
                        properties=igw
                    )
                    
                    resource_ids.append((db_resource_id, igw_id))
                    igw_count += 1
            
            logger.info(f"Discovered {igw_count} Internet Gateways in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning Internet Gateways: {error_msg}")
            raise ResourceScanError("internet_gateway", self.account_id, self.region, error_msg)

class NATGatewayScanner(BaseScanner):
    """Scanner for NAT Gateways"""
    
    def get_service_name(self):
        return "ec2"
    
    def get_resource_type(self):
        return "nat_gateway"
    
    def scan(self):
        """Scan NAT Gateways in the current region"""
        try:
            ec2_client = self.aws_client.get_client('ec2')
            paginator = ec2_client.get_paginator('describe_nat_gateways')
            
            ngw_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for ngw in page.get('NatGateways', []):
                    ngw_id = ngw['NatGatewayId']
                    
                    # Get NGW name from tags
                    ngw_name = None
                    for tag in ngw.get('Tags', []):
                        if tag['Key'] == 'Name':
                            ngw_name = tag['Value']
                            break
                    
                    # Store NGW in database
                    db_resource_id = self.store_resource(
                        resource_id=ngw_id,
                        name=ngw_name or ngw_id,
                        properties=ngw
                    )
                    
                    resource_ids.append((db_resource_id, ngw_id))
                    ngw_count += 1
            
            logger.info(f"Discovered {ngw_count} NAT Gateways in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning NAT Gateways: {error_msg}")
            raise ResourceScanError("nat_gateway", self.account_id, self.region, error_msg) 