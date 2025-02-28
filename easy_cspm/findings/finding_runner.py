from ..core.logging_config import logger

class FindingRunner:
    """Runs findings against collected resources"""
    
    def __init__(self, db_manager, scan_id, finding_classes):
        self.db_manager = db_manager
        self.scan_id = scan_id
        self.finding_classes = finding_classes
        self.findings = []
        
    def run_findings(self, account_id, region):
        """Run findings against resources in a specific account and region"""
        # Get resources for this account and region
        resources = self.db_manager.get_resources_by_account_and_region(account_id, region)
        
        logger.info(f"Running findings against {len(resources)} resources in account {account_id} region {region}")
        
        # For each resource, evaluate each finding
        for resource in resources:
            for finding_class in self.finding_classes:
                try:
                    # Instantiate the finding
                    finding = finding_class(self.db_manager, self.scan_id)
                    
                    # Skip findings that aren't relevant to this resource type
                    if hasattr(finding, 'applies_to'):
                        if resource.service not in finding.applies_to:
                            continue
                    
                    # Evaluate the finding
                    result = finding.process_resource(resource)
                    
                    # Store the finding result
                    if result:
                        self.findings.append({
                            'resource_id': resource.resource_id,
                            'finding_type': finding.finding_type,
                            'severity': finding.severity
                        })
                        
                except Exception as e:
                    logger.error(f"Error evaluating {finding_class.__name__} against resource {resource.resource_id}: {str(e)}")
        
        return self.findings 