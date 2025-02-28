from abc import ABC, abstractmethod
import traceback
from ..core.logging_config import logger
from ..core.exceptions import ResourceScanError

class BaseScanner(ABC):
    """Base class for all resource scanners"""
    
    def __init__(self, aws_client, account_id, region):
        """Initialize scanner with AWS client and account/region info"""
        self.aws_client = aws_client
        self.account_id = account_id
        self.region = region
        self.service_name = self.get_service_name()
        self.resource_type = self.get_resource_type()
        
        logger.debug(f"Initialized {self.__class__.__name__} for account {self.account_id} region {self.region}")
    
    @abstractmethod
    def get_service_name(self):
        """Return the AWS service name (e.g., 'ec2', 's3')"""
        pass
    
    @abstractmethod
    def get_resource_type(self):
        """Return the resource type (e.g., 'instance', 'bucket')"""
        pass
    
    @abstractmethod
    def scan(self):
        """
        Scan for resources of the specific type.
        
        Returns:
            List of tuples: (resource_id, resource_name)
        """
        pass
    
    def execute(self):
        """Execute the scanner and handle exceptions"""
        try:
            logger.info(f"Scanning {self.service_name} {self.resource_type} in account {self.account_id} region {self.region}")
            result = self.scan()
            logger.info(f"Completed scanning {self.service_name} {self.resource_type} in account {self.account_id} region {self.region}")
            return result
        except Exception as e:
            error_msg = str(e)
            stack_trace = traceback.format_exc()
            logger.error(f"Error scanning {self.service_name} {self.resource_type} in account {self.account_id} region {self.region}: {error_msg}\n{stack_trace}")
            raise ResourceScanError(self.resource_type, self.account_id, self.region, error_msg)
    
    def store_resource(self, resource_id, name, properties=None):
        """Store resource in the database"""
        # This is a stub - the actual implementation would be in the CLI
        # since we've removed the db_manager dependency from scanners
        return resource_id 