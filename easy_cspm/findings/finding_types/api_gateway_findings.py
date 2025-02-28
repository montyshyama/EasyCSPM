import json
from ...core.logging_config import logger
from ..base_finding import BaseFinding

class APIGatewayNoWAFEnabledFinding(BaseFinding):
    """Finding for API Gateway without WAF protection"""
    
    def get_finding_type(self):
        return "api-gateway-no-waf-enabled"
    
    def get_title(self):
        return "API Gateway Not Protected by WAF"
    
    def get_description(self):
        return "The API Gateway REST API is not protected by AWS WAF (Web Application Firewall). " \
               "Without WAF protection, your API may be vulnerable to common web exploits like " \
               "SQL injection, cross-site scripting (XSS), and other attacks that could affect " \
               "availability or compromise security."
    
    def get_remediation(self):
        return "Associate an AWS WAF WebACL with your API Gateway stage. Create a WebACL in the " \
               "AWS WAF console with appropriate rules to protect against common web vulnerabilities, " \
               "then associate it with your API Gateway stage."
    
    def get_severity(self):
        return "high"
    
    def evaluate(self, resource):
        """
        Check if API Gateway has WAF enabled
        """
        if resource.service != "apigateway" or resource.resource_type != "rest_api":
            return False, {}
        
        properties = resource.properties
        
        # Check if any stage has WAF associated
        has_waf = False
        stages = properties.get('stages', [])
        
        for stage in stages:
            if 'WebAclArn' in stage:
                has_waf = True
                break
        
        if has_waf:
            return False, {}
        
        details = {
            "ApiId": properties.get('id'),
            "ApiName": properties.get('name'),
            "StageCount": len(stages),
            "HasWAF": False
        }
        
        return True, details

class APIGatewayNoAuthorizationFinding(BaseFinding):
    """Finding for API Gateway methods without authorization"""
    
    def get_finding_type(self):
        return "api-gateway-no-authorization"
    
    def get_title(self):
        return "API Gateway Methods Without Authorization"
    
    def get_description(self):
        return "One or more methods in your API Gateway REST API do not have authorization " \
               "configured. Unauthenticated API endpoints can be accessed by anyone, potentially " \
               "leading to unauthorized access to your backend resources or data exposure."
    
    def get_remediation(self):
        return "Configure authorization for all API methods. Use AWS IAM, API keys, Cognito User Pools, " \
               "or a Lambda authorizer to protect your API endpoints based on your requirements. " \
               "Ensure that only methods explicitly intended to be public lack authorization."
    
    def get_severity(self):
        return "high"
    
    def evaluate(self, resource):
        """
        Check if API Gateway methods have authorization
        """
        if resource.service != "apigateway" or resource.resource_type != "rest_api":
            return False, {}
        
        properties = resource.properties
        
        # Check resources and methods for authorization
        resources = properties.get('resources', [])
        unauthorized_methods = []
        
        for api_resource in resources:
            resource_methods = api_resource.get('resourceMethods', {})
            
            for method_key, method in resource_methods.items():
                if method_key == 'OPTIONS':
                    # Skip OPTIONS methods as they often don't require auth
                    continue
                
                authorization_type = method.get('authorizationType', '')
                
                if authorization_type == 'NONE':
                    unauthorized_methods.append({
                        "ResourcePath": api_resource.get('path', ''),
                        "Method": method_key
                    })
        
        if not unauthorized_methods:
            return False, {}
        
        details = {
            "ApiId": properties.get('id'),
            "ApiName": properties.get('name'),
            "UnauthorizedMethods": unauthorized_methods,
            "UnauthorizedMethodCount": len(unauthorized_methods)
        }
        
        return True, details 