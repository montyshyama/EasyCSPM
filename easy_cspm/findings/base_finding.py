import json
from abc import ABC, abstractmethod
from ..core.logging_config import logger
from ..core.exceptions import FindingEvaluationError

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
        """Get the remediation guidance for the finding"""
        raise NotImplementedError("Subclasses must implement get_remediation")
    
    @abstractmethod
    def get_severity(self):
        """Get the finding severity (critical, high, medium, low, informational)"""
        raise NotImplementedError("Subclasses must implement get_severity")
    
    @abstractmethod
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
            # Get parsed properties
            properties = resource.get_properties() if hasattr(resource, 'get_properties') else {}
            
            # Add the parsed properties to the resource if it doesn't have them
            if not hasattr(resource, 'properties_dict'):
                resource.properties_dict = properties
            
            # Now call the actual evaluation logic
            return self._evaluate(resource)
        except Exception as e:
            logger.error(f"Error evaluating {self.get_finding_type()} for resource {resource.resource_id}: {str(e)}")
            raise
    
    @abstractmethod
    def _evaluate(self, resource):
        """
        Implementation-specific evaluation logic.
        Must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement _evaluate")
    
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