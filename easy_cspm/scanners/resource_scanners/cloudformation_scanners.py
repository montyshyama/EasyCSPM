import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class CloudFormationStackScanner(BaseScanner):
    """Scanner for CloudFormation Stacks"""
    
    def get_service_name(self):
        return "cloudformation"
    
    def get_resource_type(self):
        return "stack"
    
    def scan(self):
        client = self.aws_client.get_client('cloudformation')
        resources = []
        
        try:
            paginator = client.get_paginator('list_stacks')
            
            # Only include active stacks (not deleted ones)
            active_statuses = [
                'CREATE_COMPLETE', 'CREATE_IN_PROGRESS', 'ROLLBACK_IN_PROGRESS',
                'ROLLBACK_COMPLETE', 'UPDATE_IN_PROGRESS', 'UPDATE_COMPLETE_CLEANUP_IN_PROGRESS',
                'UPDATE_COMPLETE', 'UPDATE_ROLLBACK_IN_PROGRESS', 'UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS',
                'UPDATE_ROLLBACK_COMPLETE', 'REVIEW_IN_PROGRESS', 'IMPORT_IN_PROGRESS', 'IMPORT_COMPLETE',
                'IMPORT_ROLLBACK_IN_PROGRESS', 'IMPORT_ROLLBACK_COMPLETE'
            ]
            
            for page in paginator.paginate(StackStatusFilter=active_statuses):
                for stack in page.get('StackSummaries', []):
                    stack_id = stack.get('StackId')
                    stack_name = stack.get('StackName')
                    resources.append((stack_id, stack_name))
            
            logger.info(f"Discovered {len(resources)} CloudFormation stacks in account {self.account_id} region {self.region}")
            return resources
        except Exception as e:
            logger.error(f"Error scanning CloudFormation stacks: {str(e)}")
            return [] 