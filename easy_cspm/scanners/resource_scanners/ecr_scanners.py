import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class ECRRepositoryScanner(BaseScanner):
    """Scanner for ECR Repositories"""
    
    def get_service_name(self):
        return "ecr"
    
    def get_resource_type(self):
        return "repository"
    
    def scan(self):
        """Scan ECR Repositories in the current region"""
        try:
            ecr_client = self.aws_client.get_client('ecr')
            paginator = ecr_client.get_paginator('describe_repositories')
            
            repo_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for repository in page.get('repositories', []):
                    repo_name = repository['repositoryName']
                    repo_arn = repository['repositoryArn']
                    
                    try:
                        # Get repository policy
                        try:
                            policy_response = ecr_client.get_repository_policy(repositoryName=repo_name)
                            repository['policy'] = policy_response.get('policyText')
                        except botocore.exceptions.ClientError as e:
                            if 'RepositoryPolicyNotFoundException' in str(e):
                                repository['policy'] = None
                            else:
                                logger.warning(f"Failed to get policy for ECR repository {repo_name}: {str(e)}")
                        
                        # Get repository scanning configuration
                        try:
                            scan_config_response = ecr_client.get_repository_scanning_configuration(
                                repositoryName=repo_name
                            )
                            repository['scanningConfiguration'] = scan_config_response.get('scanningConfiguration')
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get scanning configuration for ECR repository {repo_name}: {str(e)}")
                        
                        # Get lifecycle policy
                        try:
                            lifecycle_response = ecr_client.get_lifecycle_policy(repositoryName=repo_name)
                            repository['lifecyclePolicy'] = lifecycle_response.get('lifecyclePolicyText')
                        except botocore.exceptions.ClientError as e:
                            if 'LifecyclePolicyNotFoundException' in str(e):
                                repository['lifecyclePolicy'] = None
                            else:
                                logger.warning(f"Failed to get lifecycle policy for ECR repository {repo_name}: {str(e)}")
                        
                        # Store repository in database
                        db_resource_id = self.store_resource(
                            resource_id=repo_arn,
                            name=repo_name,
                            properties=repository
                        )
                        
                        resource_ids.append((db_resource_id, repo_name))
                        repo_count += 1
                        
                    except botocore.exceptions.ClientError as e:
                        logger.error(f"Failed to get details for ECR repository {repo_name}: {str(e)}")
            
            logger.info(f"Discovered {repo_count} ECR repositories in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning ECR repositories: {error_msg}")
            raise ResourceScanError("repository", self.account_id, self.region, error_msg) 