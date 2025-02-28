from ...core.logging_config import logger
from ..base_finding import BaseFinding

class SecretsManagerRotationDisabledFinding(BaseFinding):
    """Finding for Secrets Manager secrets without rotation enabled"""
    
    def get_finding_type(self):
        return "secretsmanager-rotation-disabled"
    
    def get_title(self):
        return "Secrets Manager Secret Rotation Not Enabled"
    
    def get_description(self):
        return "Automatic rotation is not enabled for the Secrets Manager secret. " \
               "Regular rotation of secrets is a security best practice that helps " \
               "limit the impact of compromised credentials and complies with many " \
               "regulatory requirements."
    
    def get_remediation(self):
        return "Enable automatic rotation for the Secrets Manager secret. Configure an " \
               "appropriate rotation Lambda function and schedule. AWS provides blueprint " \
               "functions for common secret types. For custom secrets, you'll need to create " \
               "a custom Lambda function to handle rotation logic."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if Secrets Manager secret has rotation enabled
        """
        if resource.service != "secretsmanager" or resource.resource_type != "secret":
            return False, {}
        
        properties = resource.properties
        
        # Check if rotation is enabled
        rotation_enabled = properties.get('RotationEnabled', False)
        
        if not rotation_enabled:
            details = {
                "SecretName": properties.get('Name'),
                "RotationEnabled": False
            }
            return True, details
        
        return False, {}

class SecretsManagerNoEncryptionWithCustomKMSFinding(BaseFinding):
    """Finding for Secrets Manager secrets not encrypted with a custom KMS key"""
    
    def get_finding_type(self):
        return "secretsmanager-no-custom-kms-key"
    
    def get_title(self):
        return "Secrets Manager Secret Not Encrypted with Customer-Managed KMS Key"
    
    def get_description(self):
        return "The Secrets Manager secret is encrypted with the default AWS-managed KMS key " \
               "instead of a customer-managed key. Using a customer-managed key provides more " \
               "control over the encryption process, including the ability to rotate, disable, " \
               "or revoke access to the key."
    
    def get_remediation(self):
        return "Create a customer-managed KMS key and update the secret to use this key for " \
               "encryption. When creating the key, ensure that appropriate key policies and " \
               "grants are configured to limit access to only authorized entities."
    
    def get_severity(self):
        return "low"
    
    def evaluate(self, resource):
        """
        Check if Secrets Manager secret is encrypted with a custom KMS key
        """
        if resource.service != "secretsmanager" or resource.resource_type != "secret":
            return False, {}
        
        properties = resource.properties
        
        # Check the KMS key ID
        kms_key_id = properties.get('KmsKeyId', '')
        
        # Default AWS-managed keys for Secrets Manager have this format
        is_aws_managed = not kms_key_id or 'alias/aws/secretsmanager' in kms_key_id
        
        if is_aws_managed:
            details = {
                "SecretName": properties.get('Name'),
                "KmsKeyId": kms_key_id or "Default AWS-managed key"
            }
            return True, details
        
        return False, {} 