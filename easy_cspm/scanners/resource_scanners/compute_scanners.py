import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class EC2InstanceScanner(BaseScanner):
    """Scanner for EC2 instances"""
    
    def get_service_name(self):
        return "ec2"
    
    def get_resource_type(self):
        return "instance"
    
    def scan(self):
        """Scan EC2 instances in the current region"""
        try:
            ec2_client = self.aws_client.get_client('ec2')
            paginator = ec2_client.get_paginator('describe_instances')
            
            instance_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for reservation in page.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        instance_id = instance['InstanceId']
                        
                        # Get instance name from tags
                        instance_name = None
                        for tag in instance.get('Tags', []):
                            if tag['Key'] == 'Name':
                                instance_name = tag['Value']
                                break
                        
                        # Store instance in database
                        db_resource_id = self.store_resource(
                            resource_id=instance_id,
                            name=instance_name or instance_id,
                            properties=instance
                        )
                        
                        resource_ids.append((db_resource_id, instance_id))
                        instance_count += 1
            
            logger.info(f"Discovered {instance_count} EC2 instances in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning EC2 instances: {error_msg}")
            raise ResourceScanError("instance", self.account_id, self.region, error_msg)

class EC2SecurityGroupScanner(BaseScanner):
    """Scanner for EC2 security groups"""
    
    def get_service_name(self):
        return "ec2"
    
    def get_resource_type(self):
        return "security_group"
    
    def scan(self):
        """Scan EC2 security groups in the current region"""
        try:
            ec2_client = self.aws_client.get_client('ec2')
            paginator = ec2_client.get_paginator('describe_security_groups')
            
            sg_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for sg in page.get('SecurityGroups', []):
                    sg_id = sg['GroupId']
                    sg_name = sg['GroupName']
                    
                    # Store security group in database
                    db_resource_id = self.store_resource(
                        resource_id=sg_id,
                        name=sg_name,
                        properties=sg
                    )
                    
                    resource_ids.append((db_resource_id, sg_id))
                    sg_count += 1
            
            logger.info(f"Discovered {sg_count} EC2 security groups in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning EC2 security groups: {error_msg}")
            raise ResourceScanError("security_group", self.account_id, self.region, error_msg)

class EC2VolumeScanner(BaseScanner):
    """Scanner for EC2 EBS volumes"""
    
    def get_service_name(self):
        return "ec2"
    
    def get_resource_type(self):
        return "volume"
    
    def scan(self):
        """Scan EC2 EBS volumes in the current region"""
        try:
            ec2_client = self.aws_client.get_client('ec2')
            paginator = ec2_client.get_paginator('describe_volumes')
            
            volume_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for volume in page.get('Volumes', []):
                    volume_id = volume['VolumeId']
                    
                    # Get volume name from tags
                    volume_name = None
                    for tag in volume.get('Tags', []):
                        if tag['Key'] == 'Name':
                            volume_name = tag['Value']
                            break
                    
                    # Store volume in database
                    db_resource_id = self.store_resource(
                        resource_id=volume_id,
                        name=volume_name or volume_id,
                        properties=volume
                    )
                    
                    resource_ids.append((db_resource_id, volume_id))
                    volume_count += 1
            
            logger.info(f"Discovered {volume_count} EC2 EBS volumes in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning EC2 EBS volumes: {error_msg}")
            raise ResourceScanError("volume", self.account_id, self.region, error_msg)

class EC2AMIScanner(BaseScanner):
    """Scanner for EC2 AMIs owned by the account"""
    
    def get_service_name(self):
        return "ec2"
    
    def get_resource_type(self):
        return "ami"
    
    def scan(self):
        """Scan EC2 AMIs owned by the account in the current region"""
        try:
            ec2_client = self.aws_client.get_client('ec2')
            
            ami_count = 0
            resource_ids = []
            
            # Get AMIs owned by self
            response = ec2_client.describe_images(Owners=['self'])
            
            for ami in response.get('Images', []):
                ami_id = ami['ImageId']
                ami_name = ami.get('Name', ami_id)
                
                # Store AMI in database
                db_resource_id = self.store_resource(
                    resource_id=ami_id,
                    name=ami_name,
                    properties=ami
                )
                
                resource_ids.append((db_resource_id, ami_id))
                ami_count += 1
            
            logger.info(f"Discovered {ami_count} EC2 AMIs owned by account {self.account_id} in region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning EC2 AMIs: {error_msg}")
            raise ResourceScanError("ami", self.account_id, self.region, error_msg)

class EC2KeyPairScanner(BaseScanner):
    """Scanner for EC2 Key Pairs"""
    
    def get_service_name(self):
        return "ec2"
    
    def get_resource_type(self):
        return "key_pair"
    
    def scan(self):
        """Scan EC2 Key Pairs in the current region"""
        try:
            ec2_client = self.aws_client.get_client('ec2')
            
            key_count = 0
            resource_ids = []
            
            response = ec2_client.describe_key_pairs()
            
            for key_pair in response.get('KeyPairs', []):
                key_name = key_pair['KeyName']
                key_fingerprint = key_pair['KeyFingerprint']
                
                # Store key pair in database
                db_resource_id = self.store_resource(
                    resource_id=key_name,
                    name=key_name,
                    properties=key_pair
                )
                
                resource_ids.append((db_resource_id, key_name))
                key_count += 1
            
            logger.info(f"Discovered {key_count} EC2 Key Pairs in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning EC2 Key Pairs: {error_msg}")
            raise ResourceScanError("key_pair", self.account_id, self.region, error_msg) 