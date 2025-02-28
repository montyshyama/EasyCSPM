import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class ECRRepositoryScanner(BaseScanner):
    """Scanner for ECR repositories"""
    
    def get_service_name(self):
        return "ecr"
    
    def get_resource_type(self):
        return "repository"
    
    def scan(self):
        client = self.aws_client.get_client('ecr')
        try:
            paginator = client.get_paginator('describe_repositories')
            resources = []
            
            for page in paginator.paginate():
                for repo in page.get('repositories', []):
                    repo_name = repo.get('repositoryName')
                    repo_arn = repo.get('repositoryArn')
                    
                    # Get scan configuration if available
                    scan_config = {}
                    try:
                        # Note: Older boto3 versions might not have this method
                        if hasattr(client, 'get_repository_policy'):
                            policy_response = client.get_repository_policy(repositoryName=repo_name)
                            scan_config['policy'] = policy_response.get('policyText')
                    except Exception as e:
                        logger.debug(f"Could not get repository policy for {repo_name}: {str(e)}")
                    
                    resources.append((repo_arn, repo_name))
                    
            logger.info(f"Discovered {len(resources)} ECR repositories in account {self.account_id} region {self.region}")
            return resources
        except Exception as e:
            logger.error(f"Error scanning ECR repositories: {str(e)}")
            return [] 