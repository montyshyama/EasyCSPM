import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class ElasticsearchDomainScanner(BaseScanner):
    """Scanner for Elasticsearch Domains"""
    
    def get_service_name(self):
        return "elasticsearch"
    
    def get_resource_type(self):
        return "domain"
    
    def scan(self):
        """Scan Elasticsearch Domains in the current region"""
        try:
            es_client = self.aws_client.get_client('elasticsearch')
            
            domain_count = 0
            resource_ids = []
            
            # List domains
            list_response = es_client.list_domain_names()
            
            for domain_info in list_response.get('DomainNames', []):
                domain_name = domain_info['DomainName']
                
                try:
                    # Get detailed domain information
                    domain_response = es_client.describe_elasticsearch_domain(DomainName=domain_name)
                    domain = domain_response.get('DomainStatus', {})
                    
                    # Get domain config
                    config_response = es_client.describe_elasticsearch_domain_config(DomainName=domain_name)
                    domain['DomainConfig'] = config_response.get('DomainConfig', {})
                    
                    # Get tags
                    try:
                        arn = domain.get('ARN')
                        if arn:
                            tags_response = es_client.list_tags(ARN=arn)
                            domain['Tags'] = tags_response.get('TagList', [])
                    except botocore.exceptions.ClientError as e:
                        logger.warning(f"Failed to get tags for Elasticsearch domain {domain_name}: {str(e)}")
                    
                    # Store domain in database
                    db_resource_id = self.store_resource(
                        resource_id=domain_name,
                        name=domain_name,
                        properties=domain
                    )
                    
                    resource_ids.append((db_resource_id, domain_name))
                    domain_count += 1
                    
                except botocore.exceptions.ClientError as e:
                    logger.error(f"Failed to get details for Elasticsearch domain {domain_name}: {str(e)}")
            
            logger.info(f"Discovered {domain_count} Elasticsearch domains in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning Elasticsearch domains: {error_msg}")
            raise ResourceScanError("domain", self.account_id, self.region, error_msg) 