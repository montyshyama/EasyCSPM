from ...core.logging_config import logger
from ..base_finding import BaseFinding

class AthenaWorkgroupEncryptionDisabledFinding(BaseFinding):
    """Finding for Athena workgroups without encryption enabled"""
    
    def get_finding_type(self):
        return "athena-workgroup-encryption-disabled"
    
    def get_title(self):
        return "Athena Workgroup Encryption Not Enabled"
    
    def get_description(self):
        return "The Athena workgroup does not have encryption enabled for query results. " \
               "When encryption is not enabled, query results stored in S3 are not automatically " \
               "encrypted, which could lead to exposure of sensitive data."
    
    def get_remediation(self):
        return "Enable encryption for the Athena workgroup. This can be done by modifying the " \
               "workgroup configuration to enable encryption for query results and specifying " \
               "a KMS key. You can use the AWS-managed key for Amazon S3 or a customer-managed key."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if Athena workgroup has encryption enabled
        """
        if resource.service != "athena" or resource.resource_type != "workgroup":
            return False, {}
        
        properties = resource.properties
        
        # Check workgroup configuration for encryption settings
        workgroup_config = properties.get('Configuration', {})
        result_config = workgroup_config.get('ResultConfiguration', {})
        encryption_config = result_config.get('EncryptionConfiguration', {})
        
        # Check if encryption is configured
        encryption_option = encryption_config.get('EncryptionOption')
        
        if not encryption_option:
            details = {
                "WorkgroupName": properties.get('Name'),
                "EncryptionEnabled": False
            }
            return True, details
        
        return False, {}

class AthenaWorkgroupNoResultsLimitFinding(BaseFinding):
    """Finding for Athena workgroups without query results size limit"""
    
    def get_finding_type(self):
        return "athena-workgroup-no-results-limit"
    
    def get_title(self):
        return "Athena Workgroup Has No Query Results Size Limit"
    
    def get_description(self):
        return "The Athena workgroup does not have a query results size limit configured. " \
               "Without this limit, users can execute queries that return very large result " \
               "sets, potentially leading to excessive S3 usage, increased costs, and " \
               "performance issues."
    
    def get_remediation(self):
        return "Configure a query results size limit for the Athena workgroup. This can be " \
               "done by modifying the workgroup configuration and setting an appropriate " \
               "data usage limit. Consider setting both per-query and workgroup-wide limits."
    
    def get_severity(self):
        return "low"
    
    def evaluate(self, resource):
        """
        Check if Athena workgroup has a query results size limit
        """
        if resource.service != "athena" or resource.resource_type != "workgroup":
            return False, {}
        
        properties = resource.properties
        
        # Check workgroup configuration for byte limit
        workgroup_config = properties.get('Configuration', {})
        result_config = workgroup_config.get('ResultConfiguration', {})
        output_location = result_config.get('OutputLocation')
        
        # Check if enforced and if byte limit is set
        enforced = workgroup_config.get('EnforceWorkGroupConfiguration', False)
        bytes_scanned_cutoff_per_query = workgroup_config.get('BytesScannedCutoffPerQuery')
        
        if not bytes_scanned_cutoff_per_query and enforced:
            details = {
                "WorkgroupName": properties.get('Name'),
                "EnforceWorkGroupConfiguration": enforced,
                "BytesScannedCutoffPerQuery": "Not Set",
                "OutputLocation": output_location
            }
            return True, details
        
        return False, {} 