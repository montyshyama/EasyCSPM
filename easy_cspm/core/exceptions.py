class EasyCSPMException(Exception):
    """Base exception for all Easy CSPM errors"""
    pass

class CredentialError(EasyCSPMException):
    """Exception raised for AWS credential issues"""
    pass

class ResourceScanError(EasyCSPMException):
    """Exception raised during resource scanning"""
    def __init__(self, resource_type, account_id, region, message):
        self.resource_type = resource_type
        self.account_id = account_id
        self.region = region
        self.message = message
        super().__init__(f"Error scanning {resource_type} in account {account_id} region {region}: {message}")

class FindingEvaluationError(EasyCSPMException):
    """Exception raised during security finding evaluation"""
    def __init__(self, finding_type, resource_id, message):
        self.finding_type = finding_type
        self.resource_id = resource_id
        self.message = message
        super().__init__(f"Error evaluating {finding_type} for resource {resource_id}: {message}")

class DatabaseError(EasyCSPMException):
    """Exception raised for database operations"""
    pass

class ParallelExecutionError(EasyCSPMException):
    """Exception raised during parallel execution"""
    pass 