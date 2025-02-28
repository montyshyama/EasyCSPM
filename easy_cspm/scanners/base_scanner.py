from abc import ABC, abstractmethod
import traceback
from ..core.logging_config import logger
from ..core.exceptions import ResourceScanError

class BaseScanner(ABC):
    """Base class for all resource scanners"""
    
    def __init__(self, aws_client, db_operations, scan_id):
        """Initialize scanner with AWS client and database operations"""
        self.aws_client = aws_client
        self.db_operations = db_operations
        self.scan_id = scan_id
        self.account_id = aws_client.account_id
        self.region = aws_client.region
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
        """Perform the actual resource scanning"""
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
    
    def store_resource(self, resource_id, name, properties):
        """Store a resource in the database"""
        try:
            db_resource_id = self.db_operations.store_resource(
                scan_id=self.scan_id,
                resource_id=resource_id,
                account_id=self.account_id,
                region=self.region,
                service=self.service_name,
                resource_type=self.resource_type,
                name=name,
                properties=properties
            )
            logger.debug(f"Stored {self.service_name} {self.resource_type} {resource_id} in database")
            return db_resource_id
        except Exception as e:
            logger.error(f"Failed to store resource {resource_id}: {str(e)}")
            raise 