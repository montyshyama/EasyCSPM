from ...core.logging_config import logger
from ..base_finding import BaseFinding

class CloudFormationStackDriftFinding(BaseFinding):
    """Finding for CloudFormation stacks with drift detected"""
    
    def get_finding_type(self):
        return "cloudformation-stack-drift"
    
    def get_title(self):
        return "CloudFormation Stack Has Drift"
    
    def get_description(self):
        return "The CloudFormation stack has detected drift, meaning the actual configuration " \
               "of resources differs from what was specified in the template. This can indicate " \
               "manual changes were made outside of CloudFormation, which could lead to unexpected " \
               "behavior, failed updates, or security issues."
    
    def get_remediation(self):
        return "Review the stack's drift details and resolve the discrepancies. Either update the " \
               "CloudFormation template to match the current configuration or modify the resources " \
               "to match the template. Consider implementing strict controls to prevent manual changes " \
               "to resources managed by CloudFormation."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if CloudFormation stack has drift
        """
        if resource.service != "cloudformation" or resource.resource_type != "stack":
            return False, {}
        
        properties = resource.properties
        
        # Skip if the stack is in a state where drift detection doesn't apply
        invalid_states = ['CREATE_IN_PROGRESS', 'ROLLBACK_IN_PROGRESS', 'DELETE_IN_PROGRESS', 
                         'UPDATE_IN_PROGRESS', 'UPDATE_ROLLBACK_IN_PROGRESS', 'DELETE_COMPLETE']
        
        stack_status = properties.get('StackStatus')
        if stack_status in invalid_states:
            return False, {}
        
        # Check drift status
        drift_status = None
        drift_info = properties.get('DriftStatus', {})
        
        if isinstance(drift_info, dict):
            drift_status = drift_info.get('StackDriftStatus')
        else:
            # In case the drift status is directly included as a string
            drift_status = drift_info
        
        if drift_status in ['DRIFTED', 'IN_SYNC_RESOURCE_NOT_CHECKED']:
            details = {
                "StackName": properties.get('StackName'),
                "StackStatus": properties.get('StackStatus'),
                "DriftStatus": drift_status,
                "LastDriftCheckTimestamp": drift_info.get('DetectionTimeStamp') if isinstance(drift_info, dict) else None
            }
            return True, details
        
        return False, {}

class CloudFormationStackNoTerminationProtectionFinding(BaseFinding):
    """Finding for CloudFormation stacks without termination protection"""
    
    def get_finding_type(self):
        return "cloudformation-no-termination-protection"
    
    def get_title(self):
        return "CloudFormation Stack Termination Protection Not Enabled"
    
    def get_description(self):
        return "The CloudFormation stack does not have termination protection enabled. " \
               "Without termination protection, the stack could be accidentally deleted, " \
               "which could lead to service disruption or data loss, especially for " \
               "production environments."
    
    def get_remediation(self):
        return "Enable termination protection for the CloudFormation stack. This can be " \
               "done through the AWS Management Console, AWS CLI, or SDK. Consider " \
               "enabling termination protection as part of your standard stack creation " \
               "procedure, especially for production stacks."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if CloudFormation stack has termination protection enabled
        """
        if resource.service != "cloudformation" or resource.resource_type != "stack":
            return False, {}
        
        properties = resource.properties
        
        # Skip nested stacks as they don't support termination protection
        if ":" in properties.get('StackName', ''):  # Nested stacks have format parent-stack:nested-stack
            return False, {}
        
        # Check if termination protection is enabled
        termination_protection = properties.get('EnableTerminationProtection', False)
        
        if not termination_protection:
            details = {
                "StackName": properties.get('StackName'),
                "StackStatus": properties.get('StackStatus'),
                "TerminationProtectionEnabled": False
            }
            return True, details
        
        return False, {}

class CloudFormationStackInsecureCapabilitiesFinding(BaseFinding):
    """Finding for CloudFormation stacks with potentially insecure capabilities"""
    
    def get_finding_type(self):
        return "cloudformation-insecure-capabilities"
    
    def get_title(self):
        return "CloudFormation Stack Using Potentially Insecure Capabilities"
    
    def get_description(self):
        return "The CloudFormation stack uses potentially insecure capabilities such as " \
               "CAPABILITY_IAM, CAPABILITY_NAMED_IAM, or CAPABILITY_AUTO_EXPAND. These " \
               "capabilities allow the stack to create or modify IAM resources or use macros, " \
               "which could lead to privilege escalation or other security issues if not " \
               "properly reviewed."
    
    def get_remediation(self):
        return "Review the CloudFormation template and ensure that any IAM resources or " \
               "macros being created or modified are necessary and properly scoped. Consider " \
               "implementing additional approval processes for templates that require these " \
               "capabilities, and ensure that IAM resources follow the principle of least " \
               "privilege."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if CloudFormation stack is using potentially insecure capabilities
        """
        if resource.service != "cloudformation" or resource.resource_type != "stack":
            return False, {}
        
        properties = resource.properties
        
        # Check if any of the potentially insecure capabilities are enabled
        capabilities = properties.get('Capabilities', [])
        insecure_capabilities = ['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM', 'CAPABILITY_AUTO_EXPAND']
        
        used_insecure_capabilities = [cap for cap in capabilities if cap in insecure_capabilities]
        
        if used_insecure_capabilities:
            details = {
                "StackName": properties.get('StackName'),
                "StackStatus": properties.get('StackStatus'),
                "InsecureCapabilities": used_insecure_capabilities
            }
            return True, details
        
        return False, {} 