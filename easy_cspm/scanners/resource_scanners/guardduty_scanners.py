import botocore
from ...core.logging_config import logger
from ...core.exceptions import ResourceScanError
from ..base_scanner import BaseScanner

class GuardDutyDetectorScanner(BaseScanner):
    """Scanner for GuardDuty Detectors"""
    
    def get_service_name(self):
        return "guardduty"
    
    def get_resource_type(self):
        return "detector"
    
    def scan(self):
        """Scan GuardDuty Detectors in the current region"""
        try:
            gd_client = self.aws_client.get_client('guardduty')
            
            detector_count = 0
            resource_ids = []
            
            # List detector IDs
            detector_ids_response = gd_client.list_detectors()
            detector_ids = detector_ids_response.get('DetectorIds', [])
            
            for detector_id in detector_ids:
                try:
                    # Get detector details
                    detector_response = gd_client.get_detector(
                        DetectorId=detector_id
                    )
                    
                    # Create a combined detector object
                    detector = {
                        'DetectorId': detector_id,
                        **detector_response
                    }
                    
                    # Get findings statistics
                    try:
                        findings_statistics_response = gd_client.get_findings_statistics(
                            DetectorId=detector_id,
                            FindingStatisticTypes=['COUNT_BY_SEVERITY'],
                            FindingCriteria={
                                'Criterion': {
                                    'service.archived': {
                                        'Equals': ['false']
                                    }
                                }
                            }
                        )
                        detector['FindingsStatistics'] = findings_statistics_response.get('FindingStatistics', {})
                    except botocore.exceptions.ClientError as e:
                        logger.warning(f"Failed to get findings statistics for GuardDuty detector {detector_id}: {str(e)}")
                    
                    # Get findings
                    try:
                        findings_paginator = gd_client.get_paginator('list_findings')
                        finding_ids = []
                        
                        for findings_page in findings_paginator.paginate(DetectorId=detector_id):
                            finding_ids.extend(findings_page.get('FindingIds', []))
                        
                        detector['FindingIds'] = finding_ids
                        
                        # Limit to 10 findings to avoid excessive details
                        if finding_ids:
                            findings_sample = finding_ids[:10]
                            findings_response = gd_client.get_findings(
                                DetectorId=detector_id,
                                FindingIds=findings_sample
                            )
                            detector['FindingsSample'] = findings_response.get('Findings', [])
                    except botocore.exceptions.ClientError as e:
                        logger.warning(f"Failed to get findings for GuardDuty detector {detector_id}: {str(e)}")
                    
                    # Get IP sets
                    try:
                        ipsets_response = gd_client.list_ip_sets(DetectorId=detector_id)
                        detector['IpSets'] = ipsets_response.get('IpSets', [])
                    except botocore.exceptions.ClientError as e:
                        logger.warning(f"Failed to get IP sets for GuardDuty detector {detector_id}: {str(e)}")
                    
                    # Get threat intel sets
                    try:
                        threatintel_response = gd_client.list_threat_intel_sets(DetectorId=detector_id)
                        detector['ThreatIntelSets'] = threatintel_response.get('ThreatIntelSets', [])
                    except botocore.exceptions.ClientError as e:
                        logger.warning(f"Failed to get threat intel sets for GuardDuty detector {detector_id}: {str(e)}")
                    
                    # Store detector in database
                    detector_name = f"Detector-{detector_id[:8]}"
                    db_resource_id = self.store_resource(
                        resource_id=detector_id,
                        name=detector_name,
                        properties=detector
                    )
                    
                    resource_ids.append((db_resource_id, detector_name))
                    detector_count += 1
                    
                except botocore.exceptions.ClientError as e:
                    logger.error(f"Failed to get details for GuardDuty detector {detector_id}: {str(e)}")
            
            logger.info(f"Discovered {detector_count} GuardDuty detectors in account {self.account_id} region {self.region}")
            return resource_ids
            
        except botocore.exceptions.ClientError as e:
            error_msg = str(e)
            logger.error(f"Error scanning GuardDuty detectors: {error_msg}")
            raise ResourceScanError("detector", self.account_id, self.region, error_msg) 