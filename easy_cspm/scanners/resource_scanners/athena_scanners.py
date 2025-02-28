import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class AthenaWorkgroupScanner(BaseScanner):
    """Scanner for Athena Workgroups"""
    
    def get_service_name(self):
        return "athena"
    
    def get_resource_type(self):
        return "workgroup"
    
    def scan(self):
        client = self.aws_client.get_client('athena')
        resources = []
        
        try:
            # APIs that don't support paginator can be manually paginated
            response = client.list_work_groups(MaxResults=50)
            workgroups = response.get('WorkGroups', [])
            
            # Manual pagination
            while 'NextToken' in response:
                response = client.list_work_groups(
                    MaxResults=50,
                    NextToken=response['NextToken']
                )
                workgroups.extend(response.get('WorkGroups', []))
            
            for workgroup in workgroups:
                workgroup_name = workgroup.get('Name')
                resources.append((workgroup_name, workgroup_name))
            
            logger.info(f"Discovered {len(resources)} Athena workgroups in account {self.account_id} region {self.region}")
            return resources
        except Exception as e:
            logger.error(f"Error scanning Athena workgroups: {str(e)}")
            return []

    def get_details(self, workgroup_name):
        """Get detailed information about a specific workgroup"""
        try:
            athena_client = self.aws_client.get_client('athena')
            
            # Get detailed information about the workgroup
            workgroup_response = athena_client.get_work_group(
                WorkGroup=workgroup_name
            )
            workgroup_detail = workgroup_response.get('WorkGroup', {})
            
            # Get named queries for the workgroup
            try:
                query_paginator = athena_client.get_paginator('list_named_queries')
                named_queries = []
                
                for query_page in query_paginator.paginate(WorkGroup=workgroup_name):
                    named_queries.extend(query_page.get('NamedQueryIds', []))
                
                workgroup_detail['NamedQueries'] = named_queries
            except botocore.exceptions.ClientError as e:
                logger.warning(f"Failed to get named queries for Athena workgroup {workgroup_name}: {str(e)}")
            
            # Get prepared statements for the workgroup
            try:
                stmt_paginator = athena_client.get_paginator('list_prepared_statements')
                prepared_statements = []
                
                for stmt_page in stmt_paginator.paginate(WorkGroup=workgroup_name):
                    prepared_statements.extend(stmt_page.get('PreparedStatements', []))
                
                workgroup_detail['PreparedStatements'] = prepared_statements
            except botocore.exceptions.ClientError as e:
                logger.warning(f"Failed to get prepared statements for Athena workgroup {workgroup_name}: {str(e)}")
            
            # Get tags
            try:
                tags_response = athena_client.list_tags_for_resource(
                    ResourceARN=workgroup_detail.get('WorkGroupConfiguration', {}).get('WorkGroupConfigurationUpdates', {}).get('WorkGroupConfigurationUpdate', {}).get('EngineVersion', {}).get('EngineVersionId')
                )
                workgroup_detail['Tags'] = tags_response.get('Tags', [])
            except (botocore.exceptions.ClientError, TypeError) as e:
                if isinstance(e, TypeError):
                    logger.warning(f"Could not construct ARN for Athena workgroup {workgroup_name} to get tags")
                else:
                    logger.warning(f"Failed to get tags for Athena workgroup {workgroup_name}: {str(e)}")
            
            return workgroup_detail
        except botocore.exceptions.ClientError as e:
            logger.error(f"Failed to get details for Athena workgroup {workgroup_name}: {str(e)}")
            return None 