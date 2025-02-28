import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class IAMUserScanner(BaseScanner):
    """Scanner for IAM Users"""
    
    def get_service_name(self):
        return "iam"
    
    def get_resource_type(self):
        return "user"
    
    def scan(self):
        """Scan IAM Users in the account (global resource)"""
        try:
            # IAM is a global service, so only scan in the default region
            if self.region != 'us-east-1':
                logger.debug(f"Skipping IAM User scan in region {self.region}, IAM is a global service")
                return []
            
            iam_client = self.aws_client.get_client('iam')
            paginator = iam_client.get_paginator('list_users')
            
            user_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for user in page.get('Users', []):
                    user_name = user['UserName']
                    
                    # Get user details
                    user_properties = user.copy()
                    
                    # Get user's access keys
                    try:
                        keys_paginator = iam_client.get_paginator('list_access_keys')
                        keys = []
                        for keys_page in keys_paginator.paginate(UserName=user_name):
                            keys.extend(keys_page.get('AccessKeyMetadata', []))
                        user_properties['AccessKeys'] = keys
                    except botocore.exceptions.ClientError as e:
                        logger.warning(f"Unable to get access keys for user {user_name}: {str(e)}")
                    
                    # Get user's groups
                    try:
                        groups_paginator = iam_client.get_paginator('list_groups_for_user')
                        groups = []
                        for groups_page in groups_paginator.paginate(UserName=user_name):
                            groups.extend(groups_page.get('Groups', []))
                        user_properties['Groups'] = groups
                    except botocore.exceptions.ClientError as e:
                        logger.warning(f"Unable to get groups for user {user_name}: {str(e)}")
                    
                    # Get user's policies
                    try:
                        policies_paginator = iam_client.get_paginator('list_attached_user_policies')
                        policies = []
                        for policies_page in policies_paginator.paginate(UserName=user_name):
                            policies.extend(policies_page.get('AttachedPolicies', []))
                        user_properties['AttachedPolicies'] = policies
                    except botocore.exceptions.ClientError as e:
                        logger.warning(f"Unable to get policies for user {user_name}: {str(e)}")
                    
                    # Get user's inline policies
                    try:
                        inline_policies_paginator = iam_client.get_paginator('list_user_policies')
                        inline_policies = []
                        for policies_page in inline_policies_paginator.paginate(UserName=user_name):
                            inline_policies.extend(policies_page.get('PolicyNames', []))
                        
                        user_properties['InlinePolicies'] = {}
                        for policy_name in inline_policies:
                            try:
                                policy = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)
                                # Remove ResponseMetadata
                                if 'ResponseMetadata' in policy:
                                    del policy['ResponseMetadata']
                                user_properties['InlinePolicies'][policy_name] = policy
                            except botocore.exceptions.ClientError as e:
                                logger.warning(f"Unable to get inline policy {policy_name} for user {user_name}: {str(e)}")
                    except botocore.exceptions.ClientError as e:
                        logger.warning(f"Unable to get inline policies for user {user_name}: {str(e)}")
                    
                    # Get user's MFA devices
                    try:
                        mfa_paginator = iam_client.get_paginator('list_mfa_devices')
                        mfa_devices = []
                        for mfa_page in mfa_paginator.paginate(UserName=user_name):
                            mfa_devices.extend(mfa_page.get('MFADevices', []))
                        user_properties['MFADevices'] = mfa_devices
                    except botocore.exceptions.ClientError as e:
                        logger.warning(f"Unable to get MFA devices for user {user_name}: {str(e)}")
                    
                    # Store user in database
                    db_resource_id = self.store_resource(
                        resource_id=user_name,
                        name=user_name,
                        properties=user_properties
                    )
                    
                    resource_ids.append((db_resource_id, user_name))
                    user_count += 1
            
            logger.info(f"Discovered {user_count} IAM Users in account {self.account_id}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning IAM Users: {error_msg}")
            raise ResourceScanError("user", self.account_id, self.region, error_msg)

class IAMRoleScanner(BaseScanner):
    """Scanner for IAM Roles"""
    
    def get_service_name(self):
        return "iam"
    
    def get_resource_type(self):
        return "role"
    
    def scan(self):
        """Scan IAM Roles in the account (global resource)"""
        try:
            # IAM is a global service, so only scan in the default region
            if self.region != 'us-east-1':
                logger.debug(f"Skipping IAM Role scan in region {self.region}, IAM is a global service")
                return []
            
            iam_client = self.aws_client.get_client('iam')
            paginator = iam_client.get_paginator('list_roles')
            
            role_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for role in page.get('Roles', []):
                    role_name = role['RoleName']
                    
                    # Get role details
                    role_properties = role.copy()
                    
                    # Get role's policies
                    try:
                        policies_paginator = iam_client.get_paginator('list_attached_role_policies')
                        policies = []
                        for policies_page in policies_paginator.paginate(RoleName=role_name):
                            policies.extend(policies_page.get('AttachedPolicies', []))
                        role_properties['AttachedPolicies'] = policies
                    except botocore.exceptions.ClientError as e:
                        logger.warning(f"Unable to get policies for role {role_name}: {str(e)}")
                    
                    # Get role's inline policies
                    try:
                        inline_policies_paginator = iam_client.get_paginator('list_role_policies')
                        inline_policies = []
                        for policies_page in inline_policies_paginator.paginate(RoleName=role_name):
                            inline_policies.extend(policies_page.get('PolicyNames', []))
                        
                        role_properties['InlinePolicies'] = {}
                        for policy_name in inline_policies:
                            try:
                                policy = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                                # Remove ResponseMetadata
                                if 'ResponseMetadata' in policy:
                                    del policy['ResponseMetadata']
                                role_properties['InlinePolicies'][policy_name] = policy
                            except botocore.exceptions.ClientError as e:
                                logger.warning(f"Unable to get inline policy {policy_name} for role {role_name}: {str(e)}")
                    except botocore.exceptions.ClientError as e:
                        logger.warning(f"Unable to get inline policies for role {role_name}: {str(e)}")
                    
                    # Store role in database
                    db_resource_id = self.store_resource(
                        resource_id=role_name,
                        name=role_name,
                        properties=role_properties
                    )
                    
                    resource_ids.append((db_resource_id, role_name))
                    role_count += 1
            
            logger.info(f"Discovered {role_count} IAM Roles in account {self.account_id}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning IAM Roles: {error_msg}")
            raise ResourceScanError("role", self.account_id, self.region, error_msg) 