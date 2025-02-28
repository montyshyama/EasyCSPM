from ...core.logging_config import logger
from ..base_finding import BaseFinding

class DynamoDBTableEncryptionDisabledFinding(BaseFinding):
    """Finding for DynamoDB tables without encryption"""
    
    def get_finding_type(self):
        return "dynamodb-table-encryption-disabled"
    
    def get_title(self):
        return "DynamoDB Table Not Encrypted with CMK"
    
    def get_description(self):
        return "The DynamoDB table is not encrypted with a customer-managed KMS key (CMK). " \
               "While DynamoDB tables are always encrypted at rest with AWS owned keys by default, " \
               "using a CMK provides additional control over the encryption key."
    
    def get_remediation(self):
        return "Modify the DynamoDB table to use a customer-managed KMS key for encryption. " \
               "You can create a new KMS key or use an existing one. Note that this requires " \
               "creating a new table with encryption enabled, as you cannot modify the encryption " \
               "settings for an existing table."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if DynamoDB table uses CMK encryption
        """
        if resource.service != "dynamodb" or resource.resource_type != "table":
            return False, {}
        
        properties = resource.properties
        
        # Check if SSE with a CMK is enabled
        sse_description = properties.get('SSEDescription', {})
        sse_type = sse_description.get('SSEType')
        kms_master_key_id = sse_description.get('KMSMasterKeyArn')
        
        # If KMS is specified but not a CMK, it's using the AWS owned key
        if sse_type == 'KMS' and kms_master_key_id:
            return False, {}
        
        details = {
            "TableName": properties.get('TableName'),
            "SSEType": sse_type or "Default",
            "CustomKeyConfigured": False
        }
        
        return True, details

class DynamoDBPITRDisabledFinding(BaseFinding):
    """Finding for DynamoDB tables without Point-in-Time Recovery"""
    
    def get_finding_type(self):
        return "dynamodb-pitr-disabled"
    
    def get_title(self):
        return "DynamoDB Point-in-Time Recovery Not Enabled"
    
    def get_description(self):
        return "Point-in-Time Recovery (PITR) is not enabled for the DynamoDB table. " \
               "PITR provides continuous backups of your table data, allowing you to " \
               "restore the table to any point in time within the last 35 days, which " \
               "helps protect against accidental writes or deletes."
    
    def get_remediation(self):
        return "Enable Point-in-Time Recovery for the DynamoDB table. This can be done " \
               "from the AWS Management Console, AWS CLI, or SDK. There is an additional " \
               "cost for enabling this feature, but it provides an important safeguard " \
               "for your data."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if DynamoDB table has PITR enabled
        """
        if resource.service != "dynamodb" or resource.resource_type != "table":
            return False, {}
        
        properties = resource.properties
        
        # Check if continuous backups with PITR is enabled
        continuous_backups = properties.get('ContinuousBackups', {})
        pitr_status = continuous_backups.get('PointInTimeRecoveryDescription', {}).get('PointInTimeRecoveryStatus')
        
        if pitr_status == 'ENABLED':
            return False, {}
        
        details = {
            "TableName": properties.get('TableName'),
            "PITREnabled": False,
            "BillingMode": properties.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED')
        }
        
        return True, details 