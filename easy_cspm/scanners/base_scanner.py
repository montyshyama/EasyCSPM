from abc import ABC, abstractmethod
import traceback
from ..core.logging_config import logger
from ..core.exceptions import ResourceScanError
import json
import datetime

class BaseScanner(ABC):
    """Base class for all resource scanners"""
    
    def __init__(self, aws_client, account_id, region, db_manager=None, scan_id=None):
        """Initialize scanner with AWS client and account/region info"""
        self.aws_client = aws_client
        self.account_id = account_id
        self.region = region
        self.service_name = self.get_service_name()
        self.resource_type = self.get_resource_type()
        self.db_manager = db_manager
        self.scan_id = scan_id
        
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
    
    def _serialize_properties(self, properties):
        """Helper to serialize properties with datetime handling"""
        if properties is None:
            return None
        
        if isinstance(properties, dict):
            result = {}
            for key, value in properties.items():
                result[key] = self._serialize_value(value)
            return result
        else:
            return self._serialize_value(properties)

    def _serialize_value(self, value):
        """Helper to serialize a single value, handling complex types"""
        if isinstance(value, datetime.datetime):
            return value.isoformat()
        elif isinstance(value, dict):
            return self._serialize_properties(value)
        elif isinstance(value, list):
            return [self._serialize_value(item) for item in value]
        else:
            return value

    def store_resource(self, resource_id, name, properties=None, **kwargs):
        """
        Store a resource in the database with proper JSON formatting
        
        Supports both old and new argument patterns:
        - Old: (resource_id, name, properties)
        - New: (resource_id, account_id, region, service, resource_type, name, properties)
        """
        try:
            # Check if db_manager is initialized
            if self.db_manager is None:
                logger.warning(f"DB Manager not initialized. Resource {resource_id} will not be stored.")
                # Just log success but don't attempt to store
                logger.info(f"Found {self.get_resource_type()} resource: {name}")
                return None
            
            # Get account_id, region, service, and resource_type from kwargs or class attributes
            account_id = kwargs.get('account_id', self.account_id)
            region = kwargs.get('region', self.region)
            service = kwargs.get('service', self.get_service_name())
            resource_type = kwargs.get('resource_type', self.get_resource_type())
            
            # Ensure we have a valid resource_id
            if resource_id is None:
                resource_id = name  # Use name as fallback
                if resource_id is None:
                    # Generate a unique ID as last resort
                    resource_id = f"{service}-{resource_type}-{int(datetime.datetime.now().timestamp())}"
                    logger.warning(f"Generated fallback resource_id: {resource_id}")
            
            # Create or update properties dictionary
            if properties is None:
                properties = {}
            elif isinstance(properties, str):
                try:
                    properties = json.loads(properties)
                except:
                    properties = {"raw": properties}
            
            # Ensure properties is a dictionary and add resource_id
            if isinstance(properties, dict):
                properties['resource_id'] = resource_id
                properties['name'] = name
            
            # Serialize properties
            serialized_properties = self._serialize_properties(properties)
            
            # Ensure we have a JSON string
            if not isinstance(serialized_properties, str):
                serialized_properties = json.dumps(serialized_properties)
            
            # Log that we found a resource
            logger.info(f"Found {resource_type} resource: {name}")
            
            # Store in database
            return self.db_manager.store_resource(
                scan_id=self.scan_id,
                resource_id=resource_id,  # Ensure this is not None
                account_id=account_id,
                region=region,
                service=service,
                resource_type=resource_type,
                name=name,
                properties=serialized_properties
            )
        except Exception as e:
            logger.error(f"Error storing resource {resource_id}: {str(e)}")
            raise 