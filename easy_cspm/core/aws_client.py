import boto3
import botocore
from ..core.logging_config import logger
from ..core.exceptions import CredentialError
from botocore.config import Config
from botocore.exceptions import ClientError

class AWSClient:
    """AWS Client class for making API calls"""
    
    def __init__(self, aws_access_key_id=None, aws_secret_access_key=None, aws_session_token=None, region='us-east-1'):
        """Initialize AWS client with credentials"""
        self.session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            region_name=region
        )
        self.region = region
        self.clients = {}
        
        # Set default retry configuration for API calls
        self.boto_config = Config(
            retries={
                'max_attempts': 3,
                'mode': 'standard'
            },
            # For faster parallel execution
            max_pool_connections=50,
            connect_timeout=5,
            read_timeout=15
        )
        
        # Get account ID from STS and store it
        try:
            self.account_id = self.get_account_id()
            logger.info(f"AWS client initialized for account {self.account_id} in region {self.region}")
        except Exception as e:
            logger.error(f"Failed to initialize AWS client: {str(e)}")
            raise CredentialError(f"Failed to initialize AWS client: {str(e)}")
    
    def get_client(self, service_name):
        """Get a boto3 client for the specified service"""
        if service_name not in self.clients:
            try:
                self.clients[service_name] = self.session.client(service_name, config=self.boto_config)
            except Exception as e:
                logger.error(f"Failed to create client for service {service_name}: {str(e)}")
                raise e
        
        return self.clients[service_name]
    
    def get_resource(self, service_name):
        """Get a boto3 resource for the specified service"""
        try:
            resource = self.session.resource(
                service_name,
                config=self.boto_config
            )
            logger.debug(f"Created resource for service {service_name}")
            return resource
        except botocore.exceptions.ClientError as e:
            logger.error(f"Failed to create resource for {service_name}: {str(e)}")
            raise CredentialError(f"Failed to create resource for {service_name}: {str(e)}")
    
    def get_paginator(self, service_name, operation_name):
        """Get a paginator for the specified service operation"""
        client = self.get_client(service_name)
        try:
            paginator = client.get_paginator(operation_name)
            return paginator
        except botocore.exceptions.ClientError as e:
            logger.error(f"Failed to create paginator for {service_name}.{operation_name}: {str(e)}")
            raise CredentialError(f"Failed to create paginator for {service_name}.{operation_name}: {str(e)}")
    
    def get_account_regions(self, service_name=None):
        """Get available regions for the account or for a specific service"""
        ec2_client = self.get_client('ec2')
        try:
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
            
            # If service_name is provided, filter regions where the service is available
            if service_name:
                available_regions = []
                for region in regions:
                    regional_session = boto3.Session(
                        aws_access_key_id=self.session.client.meta.endpoint_params['aws_access_key_id'],
                        aws_secret_access_key=self.session.client.meta.endpoint_params['aws_secret_access_key'],
                        region_name=region
                    )
                    
                    try:
                        # Try to create a client for the service in this region
                        regional_session.client(service_name)
                        available_regions.append(region)
                    except botocore.exceptions.EndpointConnectionError:
                        # Service not available in this region
                        pass
                
                logger.debug(f"Found {len(available_regions)} regions for service {service_name}")
                return available_regions
            
            logger.debug(f"Found {len(regions)} AWS regions")
            return regions
            
        except botocore.exceptions.ClientError as e:
            logger.error(f"Failed to get regions: {str(e)}")
            raise CredentialError(f"Failed to get regions: {str(e)}")
    
    def get_account_id(self):
        """Get the account ID for the current session"""
        sts_client = self.get_client('sts')
        try:
            response = sts_client.get_caller_identity()
            return response.get('Account')
        except ClientError as e:
            logger.error(f"Failed to get account ID: {str(e)}")
            raise e 