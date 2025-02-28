import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class APIGatewayRestAPIScanner(BaseScanner):
    """Scanner for API Gateway REST APIs"""
    
    def get_service_name(self):
        return "apigateway"
    
    def get_resource_type(self):
        return "rest_api"
    
    def scan(self):
        """Scan API Gateway REST APIs in the current region"""
        try:
            apigw_client = self.aws_client.get_client('apigateway')
            paginator = apigw_client.get_paginator('get_rest_apis')
            
            api_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for api in page.get('items', []):
                    api_id = api['id']
                    api_name = api.get('name', api_id)
                    
                    try:
                        # Get stages
                        stages_response = apigw_client.get_stages(restApiId=api_id)
                        api['stages'] = stages_response.get('item', [])
                        
                        # Get resources
                        resources_paginator = apigw_client.get_paginator('get_resources')
                        resources = []
                        
                        for resources_page in resources_paginator.paginate(restApiId=api_id):
                            resources.extend(resources_page.get('items', []))
                        
                        api['resources'] = resources
                        
                        # Get API Gateway domain names
                        try:
                            domain_names_response = apigw_client.get_domain_names()
                            api['domainNames'] = domain_names_response.get('items', [])
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get domain names for API Gateway REST API {api_name}: {str(e)}")
                        
                        # Store API in database
                        db_resource_id = self.store_resource(
                            resource_id=api_id,
                            name=api_name,
                            properties=api
                        )
                        
                        resource_ids.append((db_resource_id, api_name))
                        api_count += 1
                        
                    except botocore.exceptions.ClientError as e:
                        logger.error(f"Failed to get details for API Gateway REST API {api_name}: {str(e)}")
            
            logger.info(f"Discovered {api_count} API Gateway REST APIs in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning API Gateway REST APIs: {error_msg}")
            raise ResourceScanError("rest_api", self.account_id, self.region, error_msg) 