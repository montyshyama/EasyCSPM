import botocore
import json
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class SQSQueueScanner(BaseScanner):
    """Scanner for SQS Queues"""
    
    def get_service_name(self):
        return "sqs"
    
    def get_resource_type(self):
        return "queue"
    
    def scan(self):
        """Scan SQS Queues in the current region"""
        try:
            sqs_client = self.aws_client.get_client('sqs')
            
            queue_count = 0
            resource_ids = []
            
            # List queues
            queue_list_response = sqs_client.list_queues()
            queue_urls = queue_list_response.get('QueueUrls', [])
            
            for queue_url in queue_urls:
                try:
                    # Extract queue name from URL
                    queue_name = queue_url.split('/')[-1]
                    
                    # Get queue attributes
                    attributes_response = sqs_client.get_queue_attributes(
                        QueueUrl=queue_url,
                        AttributeNames=['All']
                    )
                    attributes = attributes_response.get('Attributes', {})
                    
                    # Get queue policy if it exists
                    policy = None
                    if 'Policy' in attributes:
                        try:
                            policy = json.loads(attributes['Policy'])
                        except json.JSONDecodeError:
                            logger.warning(f"Failed to parse policy for SQS queue {queue_name}")
                    
                    # Combine attributes and policy information
                    queue_properties = {
                        'QueueUrl': queue_url,
                        'QueueName': queue_name,
                        'Attributes': attributes,
                        'Policy': policy
                    }
                    
                    # Get tags
                    try:
                        tags_response = sqs_client.list_queue_tags(QueueUrl=queue_url)
                        queue_properties['Tags'] = tags_response.get('Tags', {})
                    except botocore.exceptions.ClientError as e:
                        logger.warning(f"Failed to get tags for SQS queue {queue_name}: {str(e)}")
                    
                    # Store queue in database
                    queue_arn = attributes.get('QueueArn')
                    db_resource_id = self.store_resource(
                        resource_id=queue_arn,
                        name=queue_name,
                        properties=queue_properties
                    )
                    
                    resource_ids.append((db_resource_id, queue_name))
                    queue_count += 1
                    
                except botocore.exceptions.ClientError as e:
                    logger.error(f"Failed to get details for SQS queue {queue_url}: {str(e)}")
            
            logger.info(f"Discovered {queue_count} SQS queues in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning SQS queues: {error_msg}")
            raise ResourceScanError("queue", self.account_id, self.region, error_msg) 