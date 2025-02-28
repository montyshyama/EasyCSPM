def scan(self):
    """Scan for ECR repositories"""
    try:
        # Get all repositories
        paginator = self.aws_client.get_paginator('describe_repositories')
        repositories = []
        
        for page in paginator.paginate():
            for repo in page.get('repositories', []):
                repo_name = repo.get('repositoryName')
                repo_arn = repo.get('repositoryArn')
                
                # Use ARN as resource_id if available, otherwise name
                resource_id = repo_arn if repo_arn else f"ecr-repo-{repo_name}"
                
                # Store repository in the database
                self.store_resource(resource_id, repo_name, repo)
                
                repositories.append((resource_id, repo_name))
        
        logger.info(f"Discovered {len(repositories)} ECR repositories in account {self.account_id} region {self.region}")
        return repositories
    except Exception as e:
        if "AccessDeniedException" in str(e):
            logger.warning(f"Access denied when scanning ECR repositories in account {self.account_id} region {self.region}")
            return []
        raise 