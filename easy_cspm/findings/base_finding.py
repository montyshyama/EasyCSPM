import json
from abc import ABC, abstractmethod
from ..core.logging_config import logger
from ..core.exceptions import FindingEvaluationError

class BaseFinding(ABC):
    """Base class for all security findings"""
    
    def __init__(self, db_operations, scan_id):
        """Initialize finding with DB operations and scan ID"""
        self.db_operations = db_operations
        self.scan_id = scan_id
        self.finding_type = self.get_finding_type()
        self.title = self.get_title()
        self.description = self.get_description()
        self.remediation = self.get_remediation()
        self.severity = self.get_severity()
        
        logger.debug(f"Initialized {self.__class__.__name__}")
    
    @abstractmethod
    def get_finding_type(self):
        """Return the finding type (e.g., 'ec2-security-group-open-access')"""
        pass
    
    @abstractmethod
    def get_title(self):
        """Return the finding title"""
        pass
    
    @abstractmethod
    def get_description(self):
        """Return the finding description"""
        pass
    
    @abstractmethod
    def get_remediation(self):
        """Return the finding remediation steps"""
        pass
    
    @abstractmethod
    def get_severity(self):
        """Return the finding severity (critical, high, medium, low, informational)"""
        pass
    
    @abstractmethod
    def evaluate(self, resource):
        """
        Evaluate a resource for this finding
        
        Args:
            resource: Resource object from the database
            
        Returns:
            (bool, dict): Tuple of (is_finding_present, details_dict)
        """
        pass
    
    def execute(self, resource):
        """Execute the finding and handle exceptions"""
        try:
            resource_id = resource.resource_id
            logger.debug(f"Evaluating {self.finding_type} for resource {resource_id}")
            
            is_finding, details = self.evaluate(resource)
            
            if is_finding:
                # Store finding in database
                self.db_operations.store_finding(
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