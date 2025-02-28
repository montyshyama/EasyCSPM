from ...core.logging_config import logger
from ..base_finding import BaseFinding

class CloudFrontNoWAFFinding(BaseFinding):
    """Finding for CloudFront distributions without WAF enabled"""
    
    def get_finding_type(self):
        return "cloudfront-no-waf"
    
    def get_title(self):
        return "CloudFront Distribution Does Not Have WAF Enabled"
    
    def get_description(self):
        return "The CloudFront distribution does not have AWS WAF web ACL associated with it. " \
               "Without WAF, the distribution is more vulnerable to common web exploits and attacks " \
               "such as SQL injection, cross-site scripting (XSS), and DDoS attacks."
    
    def get_remediation(self):
        return "Associate an AWS WAF web ACL with the CloudFront distribution. Configure appropriate " \
               "WAF rules to protect against common web vulnerabilities and attacks. Consider using " \
               "AWS managed rule groups to quickly implement comprehensive protection."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if CloudFront distribution has a WAF web ACL associated
        """
        if resource.service != "cloudfront" or resource.resource_type != "distribution":
            return False, {}
        
        properties = resource.properties
        
        # Check for WebACLId in the distribution config
        distribution_config = properties.get('DistributionConfig', {})
        web_acl_id = distribution_config.get('WebACLId', '')
        
        if not web_acl_id:
            details = {
                "DistributionId": properties.get('Id'),
                "DistributionDomainName": distribution_config.get('DomainName'),
                "WAFEnabled": False
            }
            return True, details
        
        return False, {}

class CloudFrontInsecureProtocolsFinding(BaseFinding):
    """Finding for CloudFront distributions allowing insecure protocols"""
    
    def get_finding_type(self):
        return "cloudfront-insecure-protocols"
    
    def get_title(self):
        return "CloudFront Distribution Allows Insecure Protocols"
    
    def get_description(self):
        return "The CloudFront distribution is configured to allow insecure SSL/TLS protocols " \
               "(SSLv3, TLSv1.0, or TLSv1.1). These protocols contain known vulnerabilities and " \
               "have been deprecated in favor of more secure protocols like TLSv1.2 and TLSv1.3."
    
    def get_remediation(self):
        return "Update the CloudFront distribution's SSL/TLS configuration to use only secure " \
               "protocols (TLSv1.2 and TLSv1.3). This can be done by modifying the security policy " \
               "in the distribution's viewer certificate settings."
    
    def get_severity(self):
        return "high"
    
    def evaluate(self, resource):
        """
        Check if CloudFront distribution allows insecure protocols
        """
        if resource.service != "cloudfront" or resource.resource_type != "distribution":
            return False, {}
        
        properties = resource.properties
        
        # Check the security policy in the viewer certificate
        distribution_config = properties.get('DistributionConfig', {})
        viewer_certificate = distribution_config.get('ViewerCertificate', {})
        minimum_protocol_version = viewer_certificate.get('MinimumProtocolVersion', '')
        
        # Insecure protocol versions
        insecure_versions = ['SSLv3', 'TLSv1', 'TLSv1_2016', 'TLSv1.1_2016']
        
        if minimum_protocol_version in insecure_versions:
            details = {
                "DistributionId": properties.get('Id'),
                "DistributionDomainName": distribution_config.get('DomainName'),
                "MinimumProtocolVersion": minimum_protocol_version
            }
            return True, details
        
        return False, {}

class CloudFrontNoFieldLevelEncryptionFinding(BaseFinding):
    """Finding for CloudFront distributions without field-level encryption"""
    
    def get_finding_type(self):
        return "cloudfront-no-field-level-encryption"
    
    def get_title(self):
        return "CloudFront Distribution Does Not Use Field-Level Encryption"
    
    def get_description(self):
        return "The CloudFront distribution does not use field-level encryption for sensitive data. " \
               "Field-level encryption adds an additional layer of security along with HTTPS that " \
               "protects specific data throughout system processing, so that only certain applications " \
               "can see the data."
    
    def get_remediation(self):
        return "Configure field-level encryption for the CloudFront distribution to protect sensitive " \
               "data fields. This requires setting up a field-level encryption configuration and " \
               "associating it with the appropriate cache behaviors in your distribution."
    
    def get_severity(self):
        return "low"
    
    def evaluate(self, resource):
        """
        Check if CloudFront distribution uses field-level encryption
        """
        if resource.service != "cloudfront" or resource.resource_type != "distribution":
            return False, {}
        
        properties = resource.properties
        
        # Check if any cache behavior has field-level encryption configured
        distribution_config = properties.get('DistributionConfig', {})
        
        # Check default cache behavior
        default_cache_behavior = distribution_config.get('DefaultCacheBehavior', {})
        default_fle_id = default_cache_behavior.get('FieldLevelEncryptionId', '')
        
        # Check other cache behaviors
        cache_behaviors = distribution_config.get('CacheBehaviors', {}).get('Items', [])
        other_fle_ids = [behavior.get('FieldLevelEncryptionId', '') for behavior in cache_behaviors]
        
        # Check if any field-level encryption ID is configured
        has_fle = bool(default_fle_id) or any(other_fle_ids)
        
        if not has_fle:
            details = {
                "DistributionId": properties.get('Id'),
                "DistributionDomainName": distribution_config.get('DomainName'),
                "FieldLevelEncryptionEnabled": False
            }
            return True, details
        
        return False, {} 