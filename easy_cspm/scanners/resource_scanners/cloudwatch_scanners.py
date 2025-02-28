import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class CloudWatchAlarmScanner(BaseScanner):
    """Scanner for CloudWatch Alarms"""
    
    def get_service_name(self):
        return "cloudwatch"
    
    def get_resource_type(self):
        return "alarm"
    
    def scan(self):
        """Scan CloudWatch Alarms in the current region"""
        try:
            cloudwatch_client = self.aws_client.get_client('cloudwatch')
            paginator = cloudwatch_client.get_paginator('describe_alarms')
            
            alarm_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                # Process metric alarms
                for alarm in page.get('MetricAlarms', []):
                    alarm_name = alarm['AlarmName']
                    alarm_arn = alarm['AlarmArn']
                    
                    try:
                        # Get alarm tags
                        try:
                            tags_response = cloudwatch_client.list_tags_for_resource(ResourceARN=alarm_arn)
                            alarm['Tags'] = tags_response.get('Tags', [])
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get tags for CloudWatch alarm {alarm_name}: {str(e)}")
                        
                        # Store alarm in database
                        db_resource_id = self.store_resource(
                            resource_id=alarm_arn,
                            name=alarm_name,
                            properties=alarm
                        )
                        
                        resource_ids.append((db_resource_id, alarm_name))
                        alarm_count += 1
                        
                    except botocore.exceptions.ClientError as e:
                        logger.error(f"Failed to get details for CloudWatch alarm {alarm_name}: {str(e)}")
                
                # Process composite alarms
                for alarm in page.get('CompositeAlarms', []):
                    alarm_name = alarm['AlarmName']
                    alarm_arn = alarm['AlarmArn']
                    
                    try:
                        # Get alarm tags
                        try:
                            tags_response = cloudwatch_client.list_tags_for_resource(ResourceARN=alarm_arn)
                            alarm['Tags'] = tags_response.get('Tags', [])
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get tags for CloudWatch composite alarm {alarm_name}: {str(e)}")
                        
                        # Add type indicator
                        alarm['AlarmType'] = 'CompositeAlarm'
                        
                        # Store alarm in database
                        db_resource_id = self.store_resource(
                            resource_id=alarm_arn,
                            name=alarm_name,
                            properties=alarm
                        )
                        
                        resource_ids.append((db_resource_id, alarm_name))
                        alarm_count += 1
                        
                    except botocore.exceptions.ClientError as e:
                        logger.error(f"Failed to get details for CloudWatch composite alarm {alarm_name}: {str(e)}")
            
            logger.info(f"Discovered {alarm_count} CloudWatch alarms in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning CloudWatch alarms: {error_msg}")
            raise ResourceScanError("alarm", self.account_id, self.region, error_msg)

class CloudWatchLogGroupScanner(BaseScanner):
    """Scanner for CloudWatch Log Groups"""
    
    def get_service_name(self):
        return "logs"
    
    def get_resource_type(self):
        return "log_group"
    
    def scan(self):
        """Scan CloudWatch Log Groups in the current region"""
        try:
            logs_client = self.aws_client.get_client('logs')
            paginator = logs_client.get_paginator('describe_log_groups')
            
            log_group_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for log_group in page.get('logGroups', []):
                    log_group_name = log_group['logGroupName']
                    log_group_arn = log_group.get('arn') or f"arn:aws:logs:{self.region}:{self.account_id}:log-group:{log_group_name}"
                    
                    try:
                        # Get log group metric filters
                        try:
                            filter_paginator = logs_client.get_paginator('describe_metric_filters')
                            metric_filters = []
                            
                            for filter_page in filter_paginator.paginate(logGroupName=log_group_name):
                                metric_filters.extend(filter_page.get('metricFilters', []))
                            
                            log_group['metricFilters'] = metric_filters
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get metric filters for CloudWatch log group {log_group_name}: {str(e)}")
                        
                        # Get resource policy if available
                        try:
                            policy_response = logs_client.describe_resource_policies()
                            policies = policy_response.get('resourcePolicies', [])
                            for policy in policies:
                                if log_group_arn in policy.get('policyDocument', ''):
                                    log_group['resourcePolicy'] = policy.get('policyDocument')
                                    break
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get resource policies for CloudWatch log group {log_group_name}: {str(e)}")
                        
                        # Get subscription filters
                        try:
                            subscription_response = logs_client.describe_subscription_filters(logGroupName=log_group_name)
                            log_group['subscriptionFilters'] = subscription_response.get('subscriptionFilters', [])
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get subscription filters for CloudWatch log group {log_group_name}: {str(e)}")
                        
                        # Store log group in database
                        db_resource_id = self.store_resource(
                            resource_id=log_group_arn,
                            name=log_group_name,
                            properties=log_group
                        )
                        
                        resource_ids.append((db_resource_id, log_group_name))
                        log_group_count += 1
                        
                    except botocore.exceptions.ClientError as e:
                        logger.error(f"Failed to get details for CloudWatch log group {log_group_name}: {str(e)}")
            
            logger.info(f"Discovered {log_group_count} CloudWatch log groups in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning CloudWatch log groups: {error_msg}")
            raise ResourceScanError("log_group", self.account_id, self.region, error_msg) 