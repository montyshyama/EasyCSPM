from ...core.logging_config import logger
from ..base_finding import BaseFinding

class ECRRepositoryScanOnPushDisabledFinding(BaseFinding):
    """Finding for ECR repositories without scan on push enabled"""
    
    def get_finding_type(self):
        return "ecr-repository-scan-on-push-disabled"
    
    def get_title(self):
        return "ECR Repository Image Scanning on Push Not Enabled"
    
    def get_description(self):
        return "Image scanning on push is not enabled for the ECR repository. " \
               "Automatic scanning helps identify software vulnerabilities in your " \
               "container images, which is crucial for maintaining a secure container " \
               "environment."
    
    def get_remediation(self):
        return "Enable scan on push for the ECR repository. This can be done through " \
               "the AWS Management Console, AWS CLI, or SDK. Consider implementing a process " \
               "to review and remediate vulnerabilities identified during scans."
    
    def get_severity(self):
        return "medium"
    
    def evaluate(self, resource):
        """
        Check if ECR repository has scan on push enabled
        """
        if resource.service != "ecr" or resource.resource_type != "repository":
            return False, {}
        
        properties = resource.properties
        
        # Check if scan on push is enabled
        scan_config = properties.get('scanningConfiguration', {})
        scan_on_push = scan_config.get('scanOnPush', False)
        
        if not scan_on_push:
            details = {
                "RepositoryName": properties.get('repositoryName'),
                "RepositoryUri": properties.get('repositoryUri'),
                "ScanOnPush": scan_on_push
            }
            return True, details
        
        return False, {}

class ECRRepositoryNoLifecyclePolicyFinding(BaseFinding):
    """Finding for ECR repositories without lifecycle policies"""
    
    def get_finding_type(self):
        return "ecr-repository-no-lifecycle-policy"
    
    def get_title(self):
        return "ECR Repository Missing Lifecycle Policy"
    
    def get_description(self):
        return "The ECR repository does not have a lifecycle policy configured. " \
               "Without a lifecycle policy, the repository may accumulate unused " \
               "and outdated images, increasing storage costs and creating potential " \
               "security issues with unmaintained images."
    
    def get_remediation(self):
        return "Create and apply a lifecycle policy for the ECR repository. Define rules " \
               "to automatically clean up unused or old images based on age, count, or " \
               "other criteria. This helps maintain repository hygiene and reduces costs."
    
    def get_severity(self):
        return "low"
    
    def evaluate(self, resource):
        """
        Check if ECR repository has a lifecycle policy
        """
        if resource.service != "ecr" or resource.resource_type != "repository":
            return False, {}
        
        properties = resource.properties
        
        # Check if a lifecycle policy exists
        lifecycle_policy = properties.get('lifecyclePolicy')
        
        if not lifecycle_policy:
            details = {
                "RepositoryName": properties.get('repositoryName'),
                "RepositoryUri": properties.get('repositoryUri'),
                "HasLifecyclePolicy": False
            }
            return True, details
        
        return False, {}

class ECRRepositoryPublicAccessFinding(BaseFinding):
    """Finding for ECR repositories with public access"""
    
    def get_finding_type(self):
        return "ecr-repository-public-access"
    
    def get_title(self):
        return "ECR Repository Has Public Access"
    
    def get_description(self):
        return "The ECR repository has a policy that grants public access to the repository. " \
               "Public access to container images could lead to unauthorized use, intellectual " \
               "property exposure, or potential security vulnerabilities if the images contain " \
               "sensitive information."
    
    def get_remediation(self):
        return "Review and modify the repository policy to remove public access. " \
               "Implement the principle of least privilege by only granting access " \
               "to specific AWS accounts, roles, or users that require it."
    
    def get_severity(self):
        return "high"
    
    def evaluate(self, resource):
        """
        Check if ECR repository policy allows public access
        """
        if resource.service != "ecr" or resource.resource_type != "repository":
            return False, {}
        
        properties = resource.properties
        
        # Check if a policy exists and if it grants public access
        policy = properties.get('policy')
        
        if not policy:
            return False, {}
        
        # Analyze the policy (simplified approach - in reality, would need more comprehensive policy analysis)
        has_public_access = False
        
        if isinstance(policy, str):
            has_public_access = '"Principal": "*"' in policy or '"Principal": {"AWS": "*"}' in policy
        
        if has_public_access:
            details = {
                "RepositoryName": properties.get('repositoryName'),
                "RepositoryUri": properties.get('repositoryUri'),
                "HasPublicAccess": True
            }
            return True, details
        
        return False, {} 