import json
from ...core.logging_config import logger
from ..base_finding import BaseFinding

class LambdaFunctionPublicAccessFinding(BaseFinding):
    """Finding for Lambda functions with public access"""
    
    def get_finding_type(self):
        return "lambda-function-public-access"
    
    def get_title(self):
        return "Lambda Function Has Public Access"
    
    def get_description(self):
        return "The Lambda function has a resource policy that allows public access. " \
               "This means the function can be invoked by anyone on the internet, which " \
               "could lead to unauthorized usage, excessive charges, or exploitation of vulnerabilities."
    
    def get_remediation(self):
        return "Review and modify the Lambda function's resource policy to restrict access " \
               "to only authorized principals. If the function is meant to be publicly accessible " \
               "via API Gateway, consider implementing proper authentication and authorization controls."
    
    def get_severity(self):
        return "high"
    
    def evaluate(self, resource):
        """
        Check if Lambda function has public access
        """
        if resource.service != "lambda" or resource.resource_type != "function":
            return False, {}
        
        properties = resource.properties
        
        # Check resource policy for public access
        policy_str = properties.get('Policy')
        if not policy_str:
            return False, {}
        
        try:
            # Parse policy JSON
            policy = json.loads(policy_str) if isinstance(policy_str, str) else policy_str
            
            # Check statements for public access
            is_public = False
            public_statements = []
            
            for statement in policy.get('Statement', []):
                principal = statement.get('Principal', {})
                effect = statement.get('Effect', '')
                
                # Check for public access patterns
                if effect == 'Allow' and (
                    principal == '*' or 
                    principal.get('AWS') == '*' or 
                    principal.get('Service', '') == '*'
                ):
                    is_public = True
                    public_statements.append({
                        'Sid': statement.get('Sid', 'Unknown'),
                        'Principal': principal,
                        'Action': statement.get('Action', [])
                    })
            
            if not is_public:
                return False, {}
            
            details = {
                "FunctionName": properties.get('FunctionName'),
                "FunctionArn": properties.get('FunctionArn'),
                "PublicStatements": public_statements
            }
            
            return True, details
            
        except (json.JSONDecodeError, TypeError) as e:
            logger.warning(f"Failed to parse Lambda function policy for {resource.resource_id}: {str(e)}")
            return False, {}

class LambdaFunctionNoVPCFinding(BaseFinding):
    """Finding for Lambda functions not in a VPC"""
    
    def get_finding_type(self):
        return "lambda-function-no-vpc"
    
    def get_title(self):
        return "Lambda Function Not Deployed in VPC"
    
    def get_description(self):
        return "The Lambda function is not deployed within a VPC. Functions outside a VPC " \
               "have direct internet access, which increases their attack surface and may not " \
               "comply with organizational security requirements for network isolation."
    
    def get_remediation(self):
        return "Configure the Lambda function to run in a VPC by specifying subnets and security groups. " \
               "Ensure the function has access to the resources it needs within the VPC, and if internet access " \
               "is required, route outbound traffic through a NAT Gateway. Note that VPC-connected Lambda " \
               "functions may experience longer cold starts."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if Lambda function is deployed in a VPC
        """
        if resource.service != "lambda" or resource.resource_type != "function":
            return False, {}
        
        properties = resource.properties
        
        # Check if function is configured with VPC
        vpc_config = properties.get('VpcConfig', {})
        if vpc_config and vpc_config.get('SubnetIds') and vpc_config.get('SecurityGroupIds'):
            return False, {}
        
        # Some functions are designed to be outside a VPC (e.g., for internet access)
        # In a real implementation, we might check for specific tags or naming patterns to exclude these
        
        details = {
            "FunctionName": properties.get('FunctionName'),
            "FunctionArn": properties.get('FunctionArn'),
            "Runtime": properties.get('Runtime')
        }
        
        return True, details

class LambdaInsecurePermissionsFinding(BaseFinding):
    """Finding for Lambda functions with overly permissive execution role"""
    
    def get_finding_type(self):
        return "lambda-insecure-permissions"
    
    def get_title(self):
        return "Lambda Function Has Overly Permissive Execution Role"
    
    def get_description(self):
        return "The Lambda function's execution role has overly permissive IAM permissions. " \
               "This violates the principle of least privilege and could potentially allow the " \
               "function to perform unintended or unauthorized actions if compromised."
    
    def get_remediation(self):
        return "Review and refine the function's execution role to include only the permissions " \
               "necessary for its operation. Use AWS IAM Access Analyzer to identify unused permissions " \
               "and create more focused policies. Consider using resource-based conditions to further " \
               "restrict access."
    
    def get_severity(self):
        return "high"
    
    def evaluate(self, resource):
        """
        Check if Lambda function's execution role has overly permissive permissions
        Note: This is a simplified check; a comprehensive implementation would analyze the role's policies
        """
        if resource.service != "lambda" or resource.resource_type != "function":
            return False, {}
        
        properties = resource.properties
        
        # Check execution role for suspicious patterns
        role_arn = properties.get('Role')
        if not role_arn:
            return False, {}
        
        # Check for common overly permissive role patterns
        suspicious_roles = [
            'AdministratorAccess',
            'FullAccess',
            'PowerUserAccess'
        ]
        
        is_overly_permissive = False
        for suspicious_role in suspicious_roles:
            if suspicious_role in role_arn:
                is_overly_permissive = True
                break
        
        # In a real implementation, we would get the role's policies and check for wildcards
        # This is a simplified check based on role name patterns
        
        if not is_overly_permissive:
            return False, {}
        
        details = {
            "FunctionName": properties.get('FunctionName'),
            "FunctionArn": properties.get('FunctionArn'),
            "RoleArn": role_arn,
            "Reason": f"Role contains suspicious pattern: {suspicious_role}"
        }
        
        return True, details

class LambdaEnvironmentVariablesUnencryptedFinding(BaseFinding):
    """Finding for Lambda functions with unencrypted environment variables"""
    
    def get_finding_type(self):
        return "lambda-environment-variables-unencrypted"
    
    def get_title(self):
        return "Lambda Function Environment Variables Not Encrypted"
    
    def get_description(self):
        return "The Lambda function has environment variables that are not encrypted with a KMS key. " \
               "Unencrypted environment variables can expose sensitive information like API keys, " \
               "connection strings, or credentials if the Lambda configuration is accessed."
    
    def get_remediation(self):
        return "Configure the Lambda function to use KMS encryption for environment variables. " \
               "Create a KMS key or use an existing one, and specify it when configuring the " \
               "function's environment variables. Ensure the function's execution role has " \
               "permissions to use the KMS key for decryption."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if Lambda function has unencrypted environment variables
        """
        if resource.service != "lambda" or resource.resource_type != "function":
            return False, {}
        
        properties = resource.properties
        
        # Check if function has environment variables
        environment = properties.get('Environment', {})
        if not environment or not environment.get('Variables'):
            return False, {}
        
        # Check if KMS key is configured
        kms_key_arn = properties.get('KMSKeyArn')
        
        if kms_key_arn:
            return False, {}
        
        # Check if any environment variables might contain sensitive information
        env_vars = environment.get('Variables', {})
        sensitive_vars = []
        
        sensitive_patterns = ['key', 'secret', 'password', 'token', 'credential', 'auth', 'api']
        
        for key in env_vars.keys():
            for pattern in sensitive_patterns:
                if pattern.lower() in key.lower():
                    sensitive_vars.append(key)
                    break
        
        details = {
            "FunctionName": properties.get('FunctionName'),
            "FunctionArn": properties.get('FunctionArn'),
            "HasEnvironmentVariables": True,
            "KMSKeyConfigured": False,
            "EnvironmentVariableCount": len(env_vars),
            "PotentiallySensitiveVariables": sensitive_vars
        }
        
        return True, details 