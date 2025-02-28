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
        """Scan Athena Workgroups in the current region"""
        try:
            athena_client = self.aws_client.get_client('athena')
            paginator = athena_client.get_paginator('list_work_groups')
            
            workgroup_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for workgroup in page.get('WorkGroups', []):
                    workgroup_name = workgroup.get('Name')
                    
                    try:
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
                        
                        # Store workgroup in database
                        db_resource_id = self.store_resource(
                            resource_id=workgroup_name,
                            name=workgroup_name,
                            properties=workgroup_detail
                        )
                        
                        resource_ids.append((db_resource_id, workgroup_name))
                        workgroup_count += 1
                        
                    except botocore.exceptions.ClientError as e:
                        logger.error(f"Failed to get details for Athena workgroup {workgroup_name}: {str(e)}")
            
            logger.info(f"Discovered {workgroup_count} Athena workgroups in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning Athena workgroups: {error_msg}")
            raise ResourceScanError("workgroup", self.account_id, self.region, error_msg) 