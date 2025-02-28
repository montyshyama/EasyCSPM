import re
from datetime import datetime, timezone
from ...core.logging_config import logger
from ..base_finding import BaseFinding

class IAMUserMFADisabledFinding(BaseFinding):
    """Finding for IAM users without MFA enabled"""
    
    def get_finding_type(self):
        return "iam-user-mfa-disabled"
    
    def get_title(self):
        return "IAM User Does Not Have MFA Enabled"
    
    def get_description(self):
        return "The IAM user does not have Multi-Factor Authentication (MFA) enabled. " \
               "Without MFA, the account is more vulnerable to password-based attacks, " \
               "as it relies solely on password authentication."
    
    def get_remediation(self):
        return "Enable MFA for the IAM user. AWS supports virtual MFA devices, hardware TOTP tokens, " \
               "and hardware U2F keys. Consider enforcing MFA across your organization using AWS " \
               "Organizations Service Control Policies (SCPs) or IAM policies."
    
    def get_severity(self):
        return "high"
    
    def evaluate(self, resource):
        """
        Check if IAM user has MFA enabled
        """
        if resource.service != "iam" or resource.resource_type != "user":
            return False, {}
        
        properties = resource.properties
        
        # Skip service accounts and roles
        if resource.name.startswith('aws-') or 'service-' in resource.name.lower():
            return False, {}
        
        has_mfa = False
        
        # Check if user has MFA devices assigned
        if 'MFADevices' in properties and properties['MFADevices']:
            has_mfa = True
        
        if has_mfa:
            return False, {}
        
        details = {
            "UserName": properties.get('UserName'),
            "UserArn": properties.get('Arn'),
            "MFAEnabled": False
        }
        
        return True, details

class IAMUserAccessKeyRotationFinding(BaseFinding):
    """Finding for IAM users with old access keys"""
    
    def get_finding_type(self):
        return "iam-user-access-key-rotation"
    
    def get_title(self):
        return "IAM User Has Access Keys Older Than 90 Days"
    
    def get_description(self):
        return "The IAM user has active access keys that are older than 90 days. " \
               "Long-lived access keys increase the risk of compromise, as they provide " \
               "an extended window of opportunity for attackers to discover and exploit them."
    
    def get_remediation(self):
        return "Rotate access keys regularly (at least every 90 days). This involves creating a new " \
               "access key, updating applications to use the new key, and then disabling and deleting " \
               "the old key. Implement a process to track key age and automate rotation where possible."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if IAM user has old access keys
        """
        if resource.service != "iam" or resource.resource_type != "user":
            return False, {}
        
        properties = resource.properties
        
        # Skip service accounts
        if resource.name.startswith('aws-') or 'service-' in resource.name.lower():
            return False, {}
        
        # Get current time
        now = datetime.now(timezone.utc)
        max_key_age_days = 90
        old_keys = []
        
        # Check access keys
        for key in properties.get('AccessKeys', []):
            # Skip inactive keys
            if key.get('Status') != 'Active':
                continue
                
            create_date = key.get('CreateDate')
            if create_date:
                # Convert string date to datetime if needed
                if isinstance(create_date, str):
                    try:
                        create_date = datetime.fromisoformat(create_date.replace('Z', '+00:00'))
                    except ValueError:
                        # If parsing fails, assume the key is old
                        old_keys.append(key.get('AccessKeyId'))
                        continue
                
                # Calculate age in days
                key_age_days = (now - create_date).days
                
                if key_age_days > max_key_age_days:
                    old_keys.append({
                        "AccessKeyId": key.get('AccessKeyId'),
                        "AgeInDays": key_age_days
                    })
        
        if not old_keys:
            return False, {}
        
        details = {
            "UserName": properties.get('UserName'),
            "UserArn": properties.get('Arn'),
            "OldAccessKeys": old_keys
        }
        
        return True, details

class IAMPasswordPolicyWeakFinding(BaseFinding):
    """Finding for weak IAM password policy"""
    
    def get_finding_type(self):
        return "iam-password-policy-weak"
    
    def get_title(self):
        return "IAM Password Policy Does Not Meet Security Best Practices"
    
    def get_description(self):
        return "The IAM password policy does not meet security best practices. A strong password policy " \
               "enforces complex passwords, requires regular rotation, and prevents password reuse, " \
               "which helps protect against brute force and password reuse attacks."
    
    def get_remediation(self):
        return "Update the IAM password policy to require minimum length of 14 characters, " \
               "include uppercase letters, lowercase letters, numbers, and symbols, prevent password reuse, " \
               "and enforce password expiration. Balance security requirements with usability to avoid " \
               "encouraging password-related workarounds."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if IAM password policy meets security best practices
        Note: This finding is account-level, not resource-level
        """
        # This is a special finding that evaluates account-level settings
        # For example purposes, we'll simulate checking an IAM user
        if resource.service != "iam" or resource.resource_type != "user":
            return False, {}
        
        # We only want to evaluate this once per account, so we'll pick an arbitrary user
        # In a real implementation, this might have account-level resources
        if resource.name != "root" and resource.name != "admin":
            return False, {}
        
        properties = resource.properties
        
        # Check if we have password policy information
        if 'AccountPasswordPolicy' not in properties:
            # No password policy means default weak policy
            details = {
                "AccountId": resource.account_id,
                "PolicyExists": False,
                "Weaknesses": ["No custom password policy set"]
            }
            return True, details
        
        policy = properties['AccountPasswordPolicy']
        weaknesses = []
        
        # Check policy against best practices
        if not policy.get('RequireUppercaseCharacters', False):
            weaknesses.append("Uppercase characters not required")
        
        if not policy.get('RequireLowercaseCharacters', False):
            weaknesses.append("Lowercase characters not required")
        
        if not policy.get('RequireSymbols', False):
            weaknesses.append("Symbol characters not required")
        
        if not policy.get('RequireNumbers', False):
            weaknesses.append("Numeric characters not required")
        
        min_length = policy.get('MinimumPasswordLength', 0)
        if min_length < 14:
            weaknesses.append(f"Minimum password length ({min_length}) is less than recommended (14)")
        
        max_age = policy.get('MaxPasswordAge', 0)
        if max_age == 0 or max_age > 90:
            weaknesses.append("Password expiration not enforced or too long (should be 90 days or less)")
        
        reuse_prevention = policy.get('PasswordReusePrevention', 0)
        if reuse_prevention < 24:
            weaknesses.append(f"Password reuse prevention ({reuse_prevention}) is less than recommended (24)")
        
        if not weaknesses:
            return False, {}
        
        details = {
            "AccountId": resource.account_id,
            "PolicyExists": True,
            "Weaknesses": weaknesses,
            "CurrentPolicy": policy
        }
        
        return True, details

class IAMRoleWildcardPermissionsFinding(BaseFinding):
    """Finding for IAM roles with wildcard permissions"""
    
    def get_finding_type(self):
        return "iam-role-wildcard-permissions"
    
    def get_title(self):
        return "IAM Role Has Wildcard Permissions"
    
    def get_description(self):
        return "The IAM role has policies with wildcard permissions, which grant access to all actions or " \
               "resources within a service. This violates the principle of least privilege and could " \
               "potentially allow the role to perform unintended actions."
    
    def get_remediation(self):
        return "Review and refine the role's policies to specify only the specific actions and resources " \
               "that are required for the role's function. Replace wildcards (*) with specific resource ARNs " \
               "and actions. Consider using tools like IAM Access Analyzer to identify unused permissions."
    
    def get_severity(self):
        return "high"
    
    def evaluate(self, resource):
        """
        Check if IAM role has wildcard permissions
        """
        if resource.service != "iam" or resource.resource_type != "role":
            return False, {}
        
        properties = resource.properties
        
        # Skip service roles
        role_name = properties.get('RoleName', '')
        if role_name.startswith('aws-') or 'service-' in role_name.lower():
            return False, {}
        
        wildcards_found = []
        
        # Check attached policies
        for policy in properties.get('AttachedPolicies', []):
            policy_name = policy.get('PolicyName', '')
            
            # Skip AWS managed policies for now (in a real implementation, we might check these too)
            if policy_name.startswith('AWS'):
                continue
            
            policy_document = policy.get('PolicyDocument', {})
            
            for statement in policy_document.get('Statement', []):
                if statement.get('Effect') != 'Allow':
                    continue
                
                # Check for wildcard actions
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                for action in actions:
                    if '*' in action:
                        wildcards_found.append({
                            "PolicyName": policy_name,
                            "WildcardAction": action
                        })
                
                # Check for wildcard resources
                resources = statement.get('Resource', [])
                if isinstance(resources, str):
                    resources = [resources]
                
                for resource_arn in resources:
                    if resource_arn == '*' or resource_arn.endswith('*'):
                        wildcards_found.append({
                            "PolicyName": policy_name,
                            "WildcardResource": resource_arn
                        })
        
        # Check inline policies
        for policy_name, policy in properties.get('InlinePolicies', {}).items():
            policy_document = policy.get('PolicyDocument', {})
            
            for statement in policy_document.get('Statement', []):
                if statement.get('Effect') != 'Allow':
                    continue
                
                # Check for wildcard actions
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                for action in actions:
                    if '*' in action:
                        wildcards_found.append({
                            "PolicyName": f"Inline:{policy_name}",
                            "WildcardAction": action
                        })
                
                # Check for wildcard resources
                resources = statement.get('Resource', [])
                if isinstance(resources, str):
                    resources = [resources]
                
                for resource_arn in resources:
                    if resource_arn == '*' or resource_arn.endswith('*'):
                        wildcards_found.append({
                            "PolicyName": f"Inline:{policy_name}",
                            "WildcardResource": resource_arn
                        })
        
        if not wildcards_found:
            return False, {}
        
        details = {
            "RoleName": role_name,
            "RoleArn": properties.get('Arn'),
            "WildcardPermissions": wildcards_found
        }
        
        return True, details 