import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class LambdaFunctionScanner(BaseScanner):
    """Scanner for Lambda Functions"""
    
    def get_service_name(self):
        return "lambda"
    
    def get_resource_type(self):
        return "function"
    
    def scan(self):
        """Scan Lambda Functions in the current region"""
        try:
            lambda_client = self.aws_client.get_client('lambda')
            paginator = lambda_client.get_paginator('list_functions')
            
            function_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for function in page.get('Functions', []):
                    function_name = function['FunctionName']
                    function_arn = function['FunctionArn']
                    
                    # Get detailed function configuration
                    try:
                        # Get function policy
                        try:
                            policy_response = lambda_client.get_policy(FunctionName=function_name)
                            function['Policy'] = policy_response.get('Policy')
                        except botocore.exceptions.ClientError as e:
                            # Function might not have a resource policy
                            if 'ResourceNotFoundException' in str(e):
                                function['Policy'] = None
                            else:
                                logger.warning(f"Failed to get policy for Lambda function {function_name}: {str(e)}")
                        
                        # Get function environment variables (with placeholder for sensitive values)
                        try:
                            env_response = lambda_client.get_function_configuration(FunctionName=function_name)
                            environment = env_response.get('Environment', {}).get('Variables', {})
                            
                            # Replace potentially sensitive values with placeholder
                            environment_filtered = {}
                            for key, value in environment.items():
                                if any(sensitive in key.lower() for sensitive in ('pass', 'key', 'secret', 'token', 'cred')):
                                    environment_filtered[key] = '[SENSITIVE VALUE REDACTED]'
                                else:
                                    environment_filtered[key] = value
                            
                            function['Environment'] = {'Variables': environment_filtered}
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get environment for Lambda function {function_name}: {str(e)}")
                        
                        # Get function concurrency
                        try:
                            concurrency_response = lambda_client.get_function_concurrency(FunctionName=function_name)
                            function['Concurrency'] = concurrency_response.get('ReservedConcurrentExecutions')
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get concurrency for Lambda function {function_name}: {str(e)}")
                        
                        # Store function in database
                        db_resource_id = self.store_resource(
                            resource_id=function_arn,
                            name=function_name,
                            properties=function
                        )
                        
                        resource_ids.append((db_resource_id, function_name))
                        function_count += 1
                        
                    except botocore.exceptions.ClientError as e:
                        logger.error(f"Failed to get details for Lambda function {function_name}: {str(e)}")
            
            logger.info(f"Discovered {function_count} Lambda functions in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning Lambda functions: {error_msg}")
            raise ResourceScanError("function", self.account_id, self.region, error_msg) 