from ...core.logging_config import logger
from ..base_finding import BaseFinding

class CloudTrailNotEnabledFinding(BaseFinding):
    """Finding for CloudTrail not enabled in the account/region"""
    
    def get_finding_type(self):
        return "cloudtrail-not-enabled"
    
    def get_title(self):
        return "CloudTrail Not Enabled"
    
    def get_description(self):
        return "CloudTrail is not enabled in the account/region. CloudTrail records AWS API calls " \
               "and delivers log files for audit and governance purposes. Without CloudTrail, you " \
               "cannot track user activity and API usage, which is essential for security monitoring " \
               "and compliance."
    
    def get_remediation(self):
        return "Enable CloudTrail in all regions by creating a new trail or updating an existing one. " \
               "Configure the trail to apply to all regions, log all management events, and store logs " \
               "in a dedicated S3 bucket with appropriate access controls."
    
    def get_severity(self):
        return "critical"
    
    def evaluate(self, resource):
        """
        Check if CloudTrail is enabled
        Note: This finding is account/region-level, not specific to a trail
        """
        # Special case for account-level check
        # This finding evaluates whether there are any active trails in the account/region
        if resource.service != "cloudtrail" or resource.resource_type != "trail":
            return False, {}
        
        # In a real implementation, we would check all trails in the account
        # For this example, we'll check this specific trail
        properties = resource.properties
        
        # Check if the trail is a multi-region trail
        is_multi_region = properties.get('IsMultiRegionTrail', False)
        
        # Check if the trail is logging
        is_logging = False
        if 'Status' in properties:
            is_logging = properties['Status'].get('IsLogging', False)
        
        # At least one trail should be multi-region and actively logging
        if is_multi_region and is_logging:
            return False, {}
        
        details = {
            "AccountId": resource.account_id,
            "Region": resource.region,
            "TrailName": properties.get('Name'),
            "IsMultiRegionTrail": is_multi_region,
            "IsLogging": is_logging
        }
        
        return True, details

class CloudTrailLogFileValidationDisabledFinding(BaseFinding):
    """Finding for CloudTrail trail without log file validation"""
    
    def get_finding_type(self):
        return "cloudtrail-log-file-validation-disabled"
    
    def get_title(self):
        return "CloudTrail Log File Validation Not Enabled"
    
    def get_description(self):
        return "CloudTrail log file validation is not enabled for the trail. Log file validation creates " \
               "a digitally signed digest file containing hashes of each log, which helps you determine " \
               "whether a log file was modified, deleted, or unchanged after CloudTrail delivered it."
    
    def get_remediation(self):
        return "Enable log file validation for the CloudTrail trail. This can be done from the AWS Management " \
               "Console or by using the AWS CLI or SDK. Enabling log file validation helps ensure the integrity " \
               "of your logs for security and compliance purposes."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if CloudTrail log file validation is enabled
        """
        if resource.service != "cloudtrail" or resource.resource_type != "trail":
            return False, {}
        
        properties = resource.properties
        
        # Check if log file validation is enabled
        log_validation_enabled = properties.get('LogFileValidationEnabled', False)
        
        if log_validation_enabled:
            return False, {}
        
        details = {
            "TrailName": properties.get('Name'),
            "TrailARN": properties.get('TrailARN'),
            "LogFileValidationEnabled": log_validation_enabled
        }
        
        return True, details

class CloudTrailDataEventsDisabledFinding(BaseFinding):
    """Finding for CloudTrail trail without data events logging"""
    
    def get_finding_type(self):
        return "cloudtrail-data-events-disabled"
    
    def get_title(self):
        return "CloudTrail Data Events Not Logged"
    
    def get_description(self):
        return "CloudTrail is not configured to log data events. Data events provide visibility into " \
               "the resource operations performed on or within a resource, such as S3 object-level " \
               "activities or Lambda function executions. Without data events, you have reduced " \
               "visibility into potential security issues."
    
    def get_remediation(self):
        return "Configure CloudTrail to log data events for critical resources such as S3 buckets " \
               "containing sensitive data and Lambda functions. You can select specific resources " \
               "to log or log events for all resources of a specific type. Note that logging data " \
               "events may increase CloudTrail costs."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if CloudTrail is logging data events
        """
        if resource.service != "cloudtrail" or resource.resource_type != "trail":
            return False, {}
        
        properties = resource.properties
        
        # Check event selectors for data events
        has_data_events = False
        
        # Check standard event selectors
        event_selectors = properties.get('EventSelectors', [])
        for selector in event_selectors:
            if selector.get('IncludeManagementEvents', True):
                data_resources = selector.get('DataResources', [])
                if data_resources:
                    has_data_events = True
                    break
        
        # Check advanced event selectors
        if not has_data_events:
            advanced_selectors = properties.get('AdvancedEventSelectors', [])
            for selector in advanced_selectors:
                field_selectors = selector.get('FieldSelectors', [])
                for field in field_selectors:
                    if field.get('Field') == 'eventCategory' and 'Data' in field.get('Equals', []):
                        has_data_events = True
                        break
                if has_data_events:
                    break
        
        if has_data_events:
            return False, {}
        
        details = {
            "TrailName": properties.get('Name'),
            "TrailARN": properties.get('TrailARN'),
            "HasEventSelectors": len(event_selectors) > 0,
            "HasAdvancedEventSelectors": len(properties.get('AdvancedEventSelectors', [])) > 0,
            "LogsDataEvents": False
        }
        
        return True, details

class CloudTrailEncryptionDisabledFinding(BaseFinding):
    """Finding for CloudTrail trail without encryption"""
    
    def get_finding_type(self):
        return "cloudtrail-encryption-disabled"
    
    def get_title(self):
        return "CloudTrail Logs Not Encrypted with KMS"
    
    def get_description(self):
        return "CloudTrail logs are not encrypted using a KMS key. Encrypting CloudTrail logs " \
               "provides an additional layer of security by protecting the log files from unauthorized " \
               "access and helps satisfy compliance requirements for sensitive data."
    
    def get_remediation(self):
        return "Configure CloudTrail to use KMS encryption for log files. Create a KMS key with " \
               "appropriate permissions or use an existing key, and update the trail settings to " \
               "use this key for encryption. Ensure the CloudTrail service has permissions to use " \
               "the KMS key."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if CloudTrail is using KMS encryption
        """
        if resource.service != "cloudtrail" or resource.resource_type != "trail":
            return False, {}
        
        properties = resource.properties
        
        # Check if KMS encryption is enabled
        kms_key_id = properties.get('KmsKeyId')
        
        if kms_key_id:
            return False, {}
        
        details = {
            "TrailName": properties.get('Name'),
            "TrailARN": properties.get('TrailARN'),
            "KmsKeyIdConfigured": False,
            "S3BucketName": properties.get('S3BucketName')
        }
        
        return True, details 