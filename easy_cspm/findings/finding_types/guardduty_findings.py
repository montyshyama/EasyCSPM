from ...core.logging_config import logger
from ..base_finding import BaseFinding

class GuardDutyDetectorDisabledFinding(BaseFinding):
    """Finding for disabled GuardDuty detectors"""
    
    def get_finding_type(self):
        return "guardduty-detector-disabled"
    
    def get_title(self):
        return "GuardDuty Detector is Disabled"
    
    def get_description(self):
        return "The GuardDuty detector in this region is not enabled. GuardDuty provides " \
               "threat detection by continuously monitoring for malicious or unauthorized " \
               "behavior to help protect your AWS accounts and workloads. When disabled, " \
               "you lose visibility into potential security threats."
    
    def get_remediation(self):
        return "Enable GuardDuty in all regions where you operate AWS resources. This can " \
               "be done through the AWS Management Console, AWS CLI, or SDK. Consider using " \
               "AWS Organizations and delegated administrator to centrally manage GuardDuty " \
               "across multiple accounts."
    
    def get_severity(self):
        return "high"
    
    def evaluate(self, resource):
        """
        Check if GuardDuty detector is enabled
        """
        if resource.service != "guardduty" or resource.resource_type != "detector":
            return False, {}
        
        properties = resource.properties
        
        # Check if the detector is enabled
        status = properties.get('Status')
        
        if status != 'ENABLED':
            details = {
                "DetectorId": properties.get('DetectorId'),
                "Status": status
            }
            return True, details
        
        return False, {}

class GuardDutyS3ProtectionDisabledFinding(BaseFinding):
    """Finding for GuardDuty detectors with S3 protection disabled"""
    
    def get_finding_type(self):
        return "guardduty-s3-protection-disabled"
    
    def get_title(self):
        return "GuardDuty S3 Protection is Disabled"
    
    def get_description(self):
        return "The GuardDuty detector does not have S3 Protection enabled. S3 Protection " \
               "allows GuardDuty to monitor object-level API operations to identify potential " \
               "security risks for data within your S3 buckets."
    
    def get_remediation(self):
        return "Enable S3 Protection for the GuardDuty detector. This can be done through " \
               "the AWS Management Console, AWS CLI, or SDK. When enabled, GuardDuty will " \
               "analyze CloudTrail management events and CloudTrail S3 data events for the " \
               "account."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if GuardDuty S3 Protection is enabled
        """
        if resource.service != "guardduty" or resource.resource_type != "detector":
            return False, {}
        
        properties = resource.properties
        
        # Only check enabled detectors
        if properties.get('Status') != 'ENABLED':
            return False, {}
        
        # Check if S3 Protection is enabled
        data_sources = properties.get('DataSources', {})
        s3_logs = data_sources.get('S3Logs', {})
        s3_protection_enabled = s3_logs.get('Status') == 'ENABLED'
        
        if not s3_protection_enabled:
            details = {
                "DetectorId": properties.get('DetectorId'),
                "S3ProtectionEnabled": False
            }
            return True, details
        
        return False, {}

class GuardDutyNoAutomatedResponseFinding(BaseFinding):
    """Finding for GuardDuty detectors without automated response"""
    
    def get_finding_type(self):
        return "guardduty-no-automated-response"
    
    def get_title(self):
        return "GuardDuty Has No Automated Response Configured"
    
    def get_description(self):
        return "The GuardDuty detector does not have automated response configured, such as " \
               "EventBridge rules to respond to findings. Without automated response, security " \
               "findings may not be addressed promptly, increasing the potential impact of " \
               "security issues."
    
    def get_remediation(self):
        return "Configure automated responses for GuardDuty findings using Amazon EventBridge " \
               "rules. Set up notifications through SNS or remediation actions through Lambda " \
               "functions or AWS Security Hub. Consider different automated responses based on " \
               "the severity of findings."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if GuardDuty has automated response configured
        Note: This is a simplistic check since we don't have direct access to EventBridge rules
        """
        if resource.service != "guardduty" or resource.resource_type != "detector":
            return False, {}
        
        properties = resource.properties
        
        # Only check enabled detectors
        if properties.get('Status') != 'ENABLED':
            return False, {}
        
        # Check for findings statistics - if there are findings but no Evidence of EventBridge rules
        # This is a simplistic approach since we don't have direct evidence of EventBridge rules
        findings_statistics = properties.get('FindingsStatistics', {})
        count_by_severity = findings_statistics.get('CountBySeverity', {})
        
        # If there are findings, especially high or medium severity
        high_findings = int(count_by_severity.get('High', 0))
        medium_findings = int(count_by_severity.get('Medium', 0))
        
        if high_findings > 0 or medium_findings > 0:
            # Check for evidence of automated response (this is a very simplified check)
            # In a real scenario, you would need to check EventBridge rules or other integration points
            findings_sample = properties.get('FindingsSample', [])
            has_evidence_of_automation = any('workflow' in finding and finding['workflow']['status'] != 'NEW' for finding in findings_sample)
            
            if not has_evidence_of_automation:
                details = {
                    "DetectorId": properties.get('DetectorId'),
                    "HighSeverityFindings": high_findings,
                    "MediumSeverityFindings": medium_findings,
                    "AutomatedResponseEvidence": False
                }
                return True, details
        
        return False, {} 