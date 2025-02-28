import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class DynamoDBTableScanner(BaseScanner):
    """Scanner for DynamoDB Tables"""
    
    def get_service_name(self):
        return "dynamodb"
    
    def get_resource_type(self):
        return "table"
    
    def scan(self):
        """Scan DynamoDB Tables in the current region"""
        try:
            dynamodb_client = self.aws_client.get_client('dynamodb')
            paginator = dynamodb_client.get_paginator('list_tables')
            
            table_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for table_name in page.get('TableNames', []):
                    try:
                        # Get detailed information about the table
                        table_info = dynamodb_client.describe_table(TableName=table_name)
                        table = table_info.get('Table', {})
                        
                        # Get table tags
                        try:
                            table_arn = table.get('TableArn')
                            tags_response = dynamodb_client.list_tags_of_resource(ResourceArn=table_arn)
                            table['Tags'] = tags_response.get('Tags', [])
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get tags for DynamoDB table {table_name}: {str(e)}")
                        
                        # Get continuous backups status
                        try:
                            backup_response = dynamodb_client.describe_continuous_backups(TableName=table_name)
                            table['ContinuousBackups'] = backup_response.get('ContinuousBackupsDescription', {})
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get continuous backups info for DynamoDB table {table_name}: {str(e)}")
                        
                        # Store table in database
                        db_resource_id = self.store_resource(
                            resource_id=table_name,
                            name=table_name,
                            properties=table
                        )
                        
                        resource_ids.append((db_resource_id, table_name))
                        table_count += 1
                        
                    except botocore.exceptions.ClientError as e:
                        logger.error(f"Failed to get details for DynamoDB table {table_name}: {str(e)}")
            
            logger.info(f"Discovered {table_count} DynamoDB tables in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning DynamoDB tables: {error_msg}")
            raise ResourceScanError("table", self.account_id, self.region, error_msg) 