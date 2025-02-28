import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class ECSClusterScanner(BaseScanner):
    """Scanner for ECS Clusters"""
    
    def get_service_name(self):
        return "ecs"
    
    def get_resource_type(self):
        return "cluster"
    
    def scan(self):
        """Scan ECS Clusters in the current region"""
        try:
            ecs_client = self.aws_client.get_client('ecs')
            paginator = ecs_client.get_paginator('list_clusters')
            
            cluster_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                cluster_arns = page.get('clusterArns', [])
                
                if not cluster_arns:
                    continue
                
                # Get detailed information for clusters
                clusters_response = ecs_client.describe_clusters(
                    clusters=cluster_arns,
                    include=['TAGS', 'SETTINGS', 'CONFIGURATIONS', 'ATTACHMENTS']
                )
                
                for cluster in clusters_response.get('clusters', []):
                    cluster_arn = cluster['clusterArn']
                    cluster_name = cluster['clusterName']
                    
                    # Enhance cluster with additional information
                    try:
                        # Get services in the cluster
                        services_paginator = ecs_client.get_paginator('list_services')
                        services = []
                        
                        for services_page in services_paginator.paginate(cluster=cluster_arn):
                            services.extend(services_page.get('serviceArns', []))
                        
                        cluster['services'] = services
                        
                        # Get tasks in the cluster
                        tasks_paginator = ecs_client.get_paginator('list_tasks')
                        tasks = []
                        
                        for tasks_page in tasks_paginator.paginate(cluster=cluster_arn):
                            tasks.extend(tasks_page.get('taskArns', []))
                        
                        cluster['tasks'] = tasks
                        
                        # Store cluster in database
                        db_resource_id = self.store_resource(
                            resource_id=cluster_arn,
                            name=cluster_name,
                            properties=cluster
                        )
                        
                        resource_ids.append((db_resource_id, cluster_name))
                        cluster_count += 1
                        
                    except botocore.exceptions.ClientError as e:
                        logger.error(f"Failed to get details for ECS cluster {cluster_name}: {str(e)}")
            
            logger.info(f"Discovered {cluster_count} ECS clusters in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning ECS clusters: {error_msg}")
            raise ResourceScanError("cluster", self.account_id, self.region, error_msg)

class ECSTaskDefinitionScanner(BaseScanner):
    """Scanner for ECS Task Definitions"""
    
    def get_service_name(self):
        return "ecs"
    
    def get_resource_type(self):
        return "task_definition"
    
    def scan(self):
        """Scan ECS Task Definitions in the current region"""
        try:
            ecs_client = self.aws_client.get_client('ecs')
            paginator = ecs_client.get_paginator('list_task_definitions')
            
            task_def_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                task_def_arns = page.get('taskDefinitionArns', [])
                
                for task_def_arn in task_def_arns:
                    try:
                        # Get detailed information for the task definition
                        task_def_response = ecs_client.describe_task_definition(
                            taskDefinition=task_def_arn,
                            include=['TAGS']
                        )
                        
                        task_def = task_def_response.get('taskDefinition', {})
                        task_def_family = task_def.get('family', '')
                        task_def_revision = task_def.get('revision', '')
                        
                        task_def_name = f"{task_def_family}:{task_def_revision}"
                        
                        # Add tags if available
                        if 'tags' in task_def_response:
                            task_def['tags'] = task_def_response['tags']
                        
                        # Store task definition in database
                        db_resource_id = self.store_resource(
                            resource_id=task_def_arn,
                            name=task_def_name,
                            properties=task_def
                        )
                        
                        resource_ids.append((db_resource_id, task_def_name))
                        task_def_count += 1
                        
                    except botocore.exceptions.ClientError as e:
                        logger.error(f"Failed to get details for ECS task definition {task_def_arn}: {str(e)}")
            
            logger.info(f"Discovered {task_def_count} ECS task definitions in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning ECS task definitions: {error_msg}")
            raise ResourceScanError("task_definition", self.account_id, self.region, error_msg) 