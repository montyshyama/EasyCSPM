import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class SNSTopicScanner(BaseScanner):
    """Scanner for SNS Topics"""
    
    def get_service_name(self):
        return "sns"
    
    def get_resource_type(self):
        return "topic"
    
    def scan(self):
        """Scan SNS Topics in the current region"""
        try:
            sns_client = self.aws_client.get_client('sns')
            paginator = sns_client.get_paginator('list_topics')
            
            topic_count = 0
            resource_ids = []
            
            for page in paginator.paginate():
                for topic in page.get('Topics', []):
                    topic_arn = topic['TopicArn']
                    
                    try:
                        # Extract topic name from ARN
                        topic_name = topic_arn.split(':')[-1]
                        
                        # Get topic attributes
                        attributes_response = sns_client.get_topic_attributes(TopicArn=topic_arn)
                        attributes = attributes_response.get('Attributes', {})
                        
                        # Combine all properties
                        topic_properties = {
                            'TopicArn': topic_arn,
                            'TopicName': topic_name,
                            **attributes
                        }
                        
                        # Get topic subscriptions
                        try:
                            subscriptions_paginator = sns_client.get_paginator('list_subscriptions_by_topic')
                            subscriptions = []
                            
                            for subs_page in subscriptions_paginator.paginate(TopicArn=topic_arn):
                                subscriptions.extend(subs_page.get('Subscriptions', []))
                            
                            topic_properties['Subscriptions'] = subscriptions
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get subscriptions for SNS topic {topic_name}: {str(e)}")
                        
                        # Get topic tags
                        try:
                            tags_response = sns_client.list_tags_for_resource(ResourceArn=topic_arn)
                            topic_properties['Tags'] = tags_response.get('Tags', [])
                        except botocore.exceptions.ClientError as e:
                            logger.warning(f"Failed to get tags for SNS topic {topic_name}: {str(e)}")
                        
                        # Store topic in database
                        db_resource_id = self.store_resource(
                            resource_id=topic_arn,
                            name=topic_name,
                            properties=topic_properties
                        )
                        
                        resource_ids.append((db_resource_id, topic_name))
                        topic_count += 1
                        
                    except botocore.exceptions.ClientError as e:
                        logger.error(f"Failed to get details for SNS topic {topic_arn}: {str(e)}")
            
            logger.info(f"Discovered {topic_count} SNS topics in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning SNS topics: {error_msg}")
            raise ResourceScanError("topic", self.account_id, self.region, error_msg) 