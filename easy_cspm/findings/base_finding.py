import json
from abc import ABC, abstractmethod
from ..core.logging_config import logger
from ..core.exceptions import FindingEvaluationError
from .finding_utils import get_property
import datetime

class BaseFinding(ABC):
    """Base class for all security findings"""
    
    def __init__(self, db_manager, scan_id):
        """Initialize the finding with a DB manager and scan ID"""
        self.db_manager = db_manager
        self.scan_id = scan_id
        self.finding_type = self.get_finding_type()
        self.title = self.get_title()
        self.description = self.get_description()
        self.remediation = self.get_remediation()
        self.severity = self.get_severity()
        
        logger.debug(f"Initialized {self.__class__.__name__}")
    
    @abstractmethod
    def get_finding_type(self):
        """Get the finding type identifier"""
        raise NotImplementedError("Subclasses must implement get_finding_type")
    
    @abstractmethod
    def get_title(self):
        """Get the finding title"""
        raise NotImplementedError("Subclasses must implement get_title")
    
    @abstractmethod
    def get_description(self):
        """Get the finding description"""
        raise NotImplementedError("Subclasses must implement get_description")
    
    @abstractmethod
    def get_remediation(self):
        """Get the remediation steps"""
        raise NotImplementedError("Subclasses must implement get_remediation")
    
    @abstractmethod
    def get_severity(self):
        """Get the finding severity level"""
        raise NotImplementedError("Subclasses must implement get_severity")
    
    def evaluate(self, resource):
        """
        Evaluate a resource against this finding.
        
        Args:
            resource: The resource to evaluate
            
        Returns:
            tuple: (is_finding, details)
                is_finding: Boolean indicating whether the finding applies
                details: Dictionary with details about the finding
        """
        try:
            # First ensure resource.properties is usable
            if hasattr(resource, 'properties'):
                # Parse properties if needed
                if isinstance(resource.properties, str):
                    try:
                        if not hasattr(resource, 'properties_dict'):
                            resource.properties_dict = json.loads(resource.properties)
                    except Exception as e:
                        logger.error(f"Failed to parse properties for resource {resource.resource_id}: {str(e)}")
                        resource.properties_dict = {}
                elif isinstance(resource.properties, dict):
                    if not hasattr(resource, 'properties_dict'):
                        resource.properties_dict = resource.properties
                else:
                    resource.properties_dict = {}
            
            # Add the get_property helper method to the resource object for findings to use
            if not hasattr(resource, 'get_property'):
                resource.get_property = lambda key, default=None: self.get_resource_property(resource, key, default)
            
            # For subclasses that haven't been updated to use _evaluate, call their evaluate method directly
            if hasattr(self, '_evaluate'):
                return self._evaluate(resource)
            else:
                # This will call the subclass's implementation of evaluate
                return super(BaseFinding, self).evaluate(resource)
                
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error evaluating {self.finding_type} for resource {resource.resource_id}: {error_msg}")
            raise FindingEvaluationError(self.finding_type, resource.resource_id, error_msg)
    
    def _evaluate(self, resource):
        """
        Implementation-specific evaluation logic.
        This will be overridden by subclasses that implement _evaluate,
        or the base evaluate method will use the subclass's evaluate method.
        """
        # Default implementation calls the subclass's evaluate method
        raise NotImplementedError("Subclasses must implement either evaluate or _evaluate")
    
    def execute(self, resource):
        """Execute the finding and handle exceptions"""
        try:
            resource_id = resource.resource_id
            logger.debug(f"Evaluating {self.finding_type} for resource {resource_id}")
            
            is_finding, details = self.evaluate(resource)
            
            if is_finding:
                # Store finding in database
                self.db_manager.store_finding(
                    scan_id=self.scan_id,
                    resource_id=resource.id,
                    finding_type=self.finding_type,
                    severity=self.severity,
                    title=self.title,
                    description=self.description,
                    remediation=self.remediation,
                    properties=details
                )
                logger.info(f"Found {self.severity} severity finding: {self.finding_type} for resource {resource_id}")
                return True
            
            logger.debug(f"No {self.finding_type} finding for resource {resource_id}")
            return False
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error evaluating {self.finding_type} for resource {resource.resource_id}: {error_msg}")
            raise FindingEvaluationError(self.finding_type, resource.resource_id, error_msg)
    
    def get_resource_property(self, resource, property_path, default=None):
        """
        Safely get a property from a resource using dot notation
        
        Args:
            resource: The resource object
            property_path: The path to the property (e.g., 'Configuration.State')
            default: Default value to return if property not found
            
        Returns:
            The property value or default
        """
        try:
            # Get the properties
            if hasattr(resource, 'get_properties'):
                props = resource.get_properties()
            elif hasattr(resource, 'properties'):
                props = resource.properties
            else:
                return default
            
            # If properties is a string, try to parse it as JSON
            if isinstance(props, str):
                try:
                    props = json.loads(props)
                except json.JSONDecodeError:
                    return default
            
            # If properties is not a dict after all that, return default
            if not isinstance(props, dict):
                return default
            
            # Split the path and traverse the dictionary
            parts = property_path.split('.')
            current = props
            
            for part in parts:
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    return default
                
            return current
        except Exception as e:
            logger.error(f"Error getting property {property_path} from resource: {str(e)}")
            return default

    def evaluate_resource(self, resource):
        """
        Evaluate a resource and store a finding if applicable
        
        Args:
            resource: The resource to evaluate
            
        Returns:
            bool: True if a finding was created, False otherwise
        """
        try:
            # Skip evaluation if resource doesn't match the required type
            if not self.applies_to_resource(resource):
                return False
            
            # Evaluate the resource
            result = self.evaluate(resource)
            
            # If evaluation returns a finding, store it
            if result:
                finding_props = {
                    "details": result if isinstance(result, dict) else {},
                    "resource_type": resource.resource_type,
                    "evaluation_time": datetime.datetime.utcnow().isoformat()
                }
                
                # Store the finding
                self.db_manager.store_finding(
                    scan_id=self.scan_id,
                    resource_id=resource.resource_id,
                    finding_type=self.finding_type,
                    severity=self.get_severity(),
                    title=self.title,
                    description=self.description,
                    remediation=self.remediation,
                    properties=finding_props
                )
                
                logger.info(f"Found {self.finding_type} issue for resource {resource.resource_id}")
                return True
                
            return False
        except Exception as e:
            logger.error(f"Error evaluating {self.finding_type} for resource {resource.resource_id}: {str(e)}")
            raise FindingEvaluationError(self.finding_type, resource.resource_id, str(e)) 