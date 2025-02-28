import json
import re
from ...core.logging_config import logger
from ..base_finding import BaseFinding

class S3BucketPublicAccessFinding(BaseFinding):
    """Finding for S3 buckets with public access"""
    
    def get_finding_type(self):
        return "s3-bucket-public-access"
    
    def get_title(self):
        return "S3 Bucket Has Public Access Enabled"
    
    def get_description(self):
        return "The S3 bucket allows public access through its bucket policy or ACL settings. " \
               "Public access to S3 buckets can lead to data exposure if not carefully managed."
    
    def get_remediation(self):
        return "Enable S3 Block Public Access at the bucket or account level. Review and modify the bucket policy " \
               "and ACL settings to remove any public access grants. Use IAM policies and bucket policies to " \
               "restrict access to only authorized principals."
    
    def get_severity(self):
        return "high"
    
    def evaluate(self, resource):
        """
        Check if S3 bucket has public access
        """
        if resource.service != "s3" or resource.resource_type != "bucket":
            return False, {}
        
        properties = resource.properties
        is_public = False
        public_access_reasons = []
        
        # Check ACL for public access
        acl = properties.get('ACL', {})
        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            if grantee.get('Type') == 'Group' and 'AllUsers' in grantee.get('URI', ''):
                is_public = True
                public_access_reasons.append(f"ACL grants {grant.get('Permission')} to AllUsers")
        
        # Check bucket policy for public access
        policy = properties.get('Policy')
        if policy:
            try:
                policy_json = json.loads(policy) if isinstance(policy, str) else policy
                
                # Check for public access in policy
                for statement in policy_json.get('Statement', []):
                    principal = statement.get('Principal', {})
                    effect = statement.get('Effect', '')
                    
                    if effect == 'Allow' and (principal == '*' or principal.get('AWS') == '*'):
                        is_public = True
                        public_access_reasons.append("Bucket policy allows access to all principals (*)")
                        break
            except (json.JSONDecodeError, TypeError):
                logger.warning(f"Failed to parse S3 bucket policy for {resource.resource_id}")
        
        # Check if public access block is disabled
        public_access_block = properties.get('PublicAccessBlock', {})
        if public_access_block:
            if not public_access_block.get('BlockPublicAcls', True):
                public_access_reasons.append("BlockPublicAcls is disabled")
            
            if not public_access_block.get('BlockPublicPolicy', True):
                public_access_reasons.append("BlockPublicPolicy is disabled")
            
            if not public_access_block.get('IgnorePublicAcls', True):
                public_access_reasons.append("IgnorePublicAcls is disabled")
            
            if not public_access_block.get('RestrictPublicBuckets', True):
                public_access_reasons.append("RestrictPublicBuckets is disabled")
        else:
            public_access_reasons.append("No PublicAccessBlock configuration found")
        
        if not is_public and not public_access_reasons:
            return False, {}
        
        details = {
            "BucketName": properties.get('Name'),
            "IsPublic": is_public,
            "PublicAccessReasons": public_access_reasons
        }
        
        return True, details

class S3BucketEncryptionDisabledFinding(BaseFinding):
    """Finding for S3 buckets without default encryption"""
    
    def get_finding_type(self):
        return "s3-bucket-encryption-disabled"
    
    def get_title(self):
        return "S3 Bucket Default Encryption Not Enabled"
    
    def get_description(self):
        return "The S3 bucket does not have default encryption enabled. Without default encryption, " \
               "new objects that are uploaded without explicit encryption settings will be stored unencrypted, " \
               "which could lead to data confidentiality issues."
    
    def get_remediation(self):
        return "Enable default encryption for the S3 bucket using either SSE-S3 (S3-managed keys) " \
               "or SSE-KMS (KMS-managed keys). This ensures that all objects uploaded to the bucket " \
               "are automatically encrypted, even if encryption is not specified in the upload request."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if S3 bucket has default encryption enabled
        """
        if resource.service != "s3" or resource.resource_type != "bucket":
            return False, {}
        
        properties = resource.properties
        
        # Check for encryption configuration
        encryption = properties.get('Encryption')
        if encryption and encryption.get('Rules'):
            for rule in encryption.get('Rules', []):
                if rule.get('ApplyServerSideEncryptionByDefault'):
                    return False, {}
        
        details = {
            "BucketName": properties.get('Name'),
            "EncryptionEnabled": False
        }
        
        return True, details

class S3BucketVersioningDisabledFinding(BaseFinding):
    """Finding for S3 buckets without versioning enabled"""
    
    def get_finding_type(self):
        return "s3-bucket-versioning-disabled"
    
    def get_title(self):
        return "S3 Bucket Versioning Not Enabled"
    
    def get_description(self):
        return "The S3 bucket does not have versioning enabled. Versioning helps protect against " \
               "accidental or malicious deletion or overwriting of objects, and it preserves " \
               "object history for regulatory compliance and data recovery purposes."
    
    def get_remediation(self):
        return "Enable versioning for the S3 bucket. Once enabled, versioning cannot be disabled, " \
               "only suspended. To manage storage costs with versioning enabled, consider implementing " \
               "lifecycle policies to transition older versions of objects to lower-cost storage " \
               "classes or to expire them after a certain period."
    
    def get_severity(self):
        return "low"
    
    def evaluate(self, resource):
        """
        Check if S3 bucket has versioning enabled
        """
        if resource.service != "s3" or resource.resource_type != "bucket":
            return False, {}
        
        properties = resource.properties
        
        # Check versioning status
        versioning = properties.get('Versioning', {})
        if versioning.get('Status') == 'Enabled':
            return False, {}
        
        details = {
            "BucketName": properties.get('Name'),
            "VersioningStatus": versioning.get('Status', 'NotEnabled')
        }
        
        return True, details

class S3BucketLoggingDisabledFinding(BaseFinding):
    """Finding for S3 buckets without access logging enabled"""
    
    def get_finding_type(self):
        return "s3-bucket-logging-disabled"
    
    def get_title(self):
        return "S3 Bucket Access Logging Not Enabled"
    
    def get_description(self):
        return "The S3 bucket does not have access logging enabled. Access logs provide detailed records " \
               "of requests made to the bucket, which are useful for security audits, forensic investigations, " \
               "and compliance verification."
    
    def get_remediation(self):
        return "Enable access logging for the S3 bucket. You need to specify a target bucket to store the " \
               "log files and optionally a prefix for the log objects. The target bucket should have appropriate " \
               "lifecycle policies to manage the accumulation of log files."
    
    def get_severity(self):
        return "low"
    
    def evaluate(self, resource):
        """
        Check if S3 bucket has access logging enabled
        """
        if resource.service != "s3" or resource.resource_type != "bucket":
            return False, {}
        
        properties = resource.properties
        
        # Check for logging configuration (simulated)
        logging_enabled = False
        if 'Logging' in properties and properties['Logging'].get('TargetBucket'):
            logging_enabled = True
        
        if logging_enabled:
            return False, {}
        
        details = {
            "BucketName": properties.get('Name'),
            "LoggingEnabled": False
        }
        
        return True, details

class S3BucketMFADeleteDisabledFinding(BaseFinding):
    """Finding for S3 buckets without MFA Delete enabled"""
    
    def get_finding_type(self):
        return "s3-bucket-mfa-delete-disabled"
    
    def get_title(self):
        return "S3 Bucket MFA Delete Not Enabled"
    
    def get_description(self):
        return "The S3 bucket does not have MFA Delete enabled. MFA Delete adds an additional layer of " \
               "security by requiring multi-factor authentication for operations that could permanently " \
               "delete versioned objects or change the versioning state of the bucket."
    
    def get_remediation(self):
        return "Enable MFA Delete for the S3 bucket. This requires using the AWS CLI or SDK, as it cannot " \
               "be enabled through the AWS Management Console. Note that once enabled, all Delete operations " \
               "will require the AWS account's root user credentials and a valid MFA code."
    
    def get_severity(self):
        return "low"
    
    def evaluate(self, resource):
        """
        Check if S3 bucket has MFA Delete enabled
        """
        if resource.service != "s3" or resource.resource_type != "bucket":
            return False, {}
        
        properties = resource.properties
        
        # Check MFA Delete status
        versioning = properties.get('Versioning', {})
        mfa_delete = versioning.get('MFADelete') == 'Enabled'
        
        if mfa_delete:
            return False, {}
        
        details = {
            "BucketName": properties.get('Name'),
            "MFADeleteEnabled": False,
            "VersioningStatus": versioning.get('Status', 'Not Enabled')
        }
        
        # Only report if versioning is enabled but MFA Delete is not
        if versioning.get('Status') == 'Enabled':
            return True, details
        
        # If versioning is not enabled, MFA Delete cannot be enabled
        return False, {} 