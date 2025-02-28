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
        """Scan CloudFormation Stacks in the current region"""
        try:
            cfn_client = self.aws_client.get_client('cloudformation')
            paginator = cfn_client.get_paginator('describe_stacks')
            
            stack_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for stack in page.get('Stacks', []):
                    stack_name = stack.get('StackName')
                    stack_id = stack.get('StackId')
                    
                    try:
                        # Get stack template
                        try:
                            template_response = cfn_client.get_template(
                                StackName=stack_name
                            )
                            stack['Template'] = template_response.get('TemplateBody')
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get template for CloudFormation stack {stack_name}: {str(e)}")
                        
                        # Get stack resources
                        try:
                            resources_paginator = cfn_client.get_paginator('list_stack_resources')
                            resources = []
                            
                            for resources_page in resources_paginator.paginate(StackName=stack_name):
                                resources.extend(resources_page.get('StackResourceSummaries', []))
                            
                            stack['Resources'] = resources
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get resources for CloudFormation stack {stack_name}: {str(e)}")
                        
                        # Get stack policy
                        try:
                            policy_response = cfn_client.get_stack_policy(
                                StackName=stack_name
                            )
                            stack['StackPolicy'] = policy_response.get('StackPolicyBody')
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get policy for CloudFormation stack {stack_name}: {str(e)}")
                        
                        # Check for drift
                        try:
                            drift_response = cfn_client.detect_stack_drift(
                                StackName=stack_name
                            )
                            drift_id = drift_response.get('StackDriftDetectionId')
                            
                            # Wait for drift detection to complete
                            waiter = cfn_client.get_waiter('stack_drift_detection_complete')
                            waiter.wait(
                                StackDriftDetectionId=drift_id
                            )
                            
                            # Get drift detection status
                            drift_status_response = cfn_client.describe_stack_drift_detection_status(
                                StackDriftDetectionId=drift_id
                            )
                            stack['DriftStatus'] = drift_status_response
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to check drift for CloudFormation stack {stack_name}: {str(e)}")
                        
                        # Store stack in database
                        db_resource_id = self.store_resource(
                            resource_id=stack_id,
                            name=stack_name,
                            properties=stack
                        )
                        
                        resource_ids.append((db_resource_id, stack_name))
                        stack_count += 1
                        
                    except botocore.exceptions.ClientError as e:
                        logger.error(f"Failed to get details for CloudFormation stack {stack_name}: {str(e)}")
            
            logger.info(f"Discovered {stack_count} CloudFormation stacks in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning CloudFormation stacks: {error_msg}")
            raise ResourceScanError("stack", self.account_id, self.region, error_msg) 