#!/usr/bin/env python3
import os
import sys
import argparse
import logging
import importlib
import pkgutil
import csv
import datetime
import json
from dotenv import load_dotenv

from easy_cspm.core.logging_config import configure_logging, logger
from easy_cspm.core.aws_client import AWSClient
from easy_cspm.core.db_manager import DBManager
from easy_cspm.scanners.base_scanner import BaseScanner
from easy_cspm.findings.base_finding import BaseFinding

# Add a version constant at the top of the file
__version__ = '0.1.0'

def load_env_config():
    """Load configuration from .env file"""
    load_dotenv()
    
    aws_config = {
        'aws_access_key_id': os.getenv('AWS_ACCESS_KEY_ID'),
        'aws_secret_access_key': os.getenv('AWS_SECRET_ACCESS_KEY'),
        'aws_session_token': os.getenv('AWS_SESSION_TOKEN'),
        'aws_account_id': os.getenv('AWS_ACCOUNT_ID'),
        'aws_regions': os.getenv('AWS_REGIONS', 'us-east-1').split(','),
        'db_connection_string': os.getenv('DB_CONNECTION_STRING', 'sqlite:///easy_cspm.db')
    }
    
    return aws_config

def discover_scanner_classes():
    """Dynamically discover all resource scanner classes"""
    scanner_classes = []
    scanners_package = 'easy_cspm.scanners.resource_scanners'
    
    package = importlib.import_module(scanners_package)
    prefix = package.__name__ + "."
    
    for _, modname, _ in pkgutil.iter_modules(package.__path__, prefix):
        module = importlib.import_module(modname)
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and issubclass(attr, BaseScanner) and attr != BaseScanner:
                scanner_classes.append(attr)
    
    logger.info(f"Discovered {len(scanner_classes)} scanner classes")
    return scanner_classes

def discover_finding_classes():
    """Dynamically discover all finding classes"""
    finding_classes = []
    findings_package = 'easy_cspm.findings.finding_types'
    
    package = importlib.import_module(findings_package)
    prefix = package.__name__ + "."
    
    for _, modname, _ in pkgutil.iter_modules(package.__path__, prefix):
        module = importlib.import_module(modname)
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and issubclass(attr, BaseFinding) and attr != BaseFinding:
                finding_classes.append(attr)
    
    logger.info(f"Discovered {len(finding_classes)} finding classes")
    return finding_classes

def run_scanners(scanner_classes, aws_client, db_manager, account_id, region):
    """Run all scanners for a given account and region"""
    scan_id = f"{account_id}-{region}-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
    
    for scanner_class in scanner_classes:
        scanner_name = scanner_class.__name__
        logger.info(f"Running {scanner_name} in account {account_id} region {region}")
        
        try:
            # Create scanner instance
            scanner = scanner_class(aws_client, account_id, region)
            
            # Run scanner
            resources = scanner.scan()
            
            # Store resources in database if any were found
            if resources:
                for resource_id, resource_name in resources:
                    # Store resource in database with basic properties
                    properties = {
                        "resource_id": resource_id,
                        "name": resource_name
                    }
                    
                    # Store in database
                    db_manager.store_resource(
                        scan_id=scan_id,
                        resource_id=resource_id,
                        account_id=account_id,
                        region=region,
                        service=scanner.get_service_name(),
                        resource_type=scanner.get_resource_type(),
                        name=resource_name,
                        properties=properties
                    )
                    
                    # Log discovery
                    logger.info(f"Found {scanner.get_resource_type()} resource: {resource_name}")
            else:
                logger.info(f"No {scanner.get_service_name()} {scanner.get_resource_type()} resources found")
                
        except Exception as e:
            logger.error(f"Error running {scanner_name}: {str(e)}")

def run_findings(finding_classes, db_manager, account_id, region):
    """Run all findings for a given account and region"""
    logger.info(f"Running findings against resources in account {account_id} region {region}")
    
    # Get all resources for this account and region
    resources = db_manager.get_resources_by_account_and_region(account_id, region)
    logger.info(f"Running findings against {len(resources)} resources in account {account_id} region {region}")
    
    findings_results = []
    scan_id = f"{account_id}-{region}-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
    
    for finding_class in finding_classes:
        finding_name = finding_class.__name__
        
        try:
            # Initialize finding
            finding = finding_class(db_manager, scan_id)
            
            # Run finding against each resource
            for resource in resources:
                try:
                    # Skip resources that don't match the finding's target service/resource type
                    # We'll have to determine if the finding applies to this resource type
                    # This is a simplified example - you'd want more robust logic here
                    
                    # Execute finding
                    result = finding.execute(resource)
                    
                    if result:
                        # Get finding details
                        finding_type = finding.get_finding_type()
                        severity = finding.get_severity()
                        title = finding.get_title()
                        description = finding.get_description()
                        remediation = finding.get_remediation()
                        
                        # Add to results
                        findings_results.append({
                            'scan_id': scan_id,
                            'account_id': account_id,
                            'region': region,
                            'resource_id': resource.resource_id,
                            'resource_name': resource.name,
                            'finding_type': finding_type,
                            'severity': severity,
                            'title': title,
                            'description': description,
                            'remediation': remediation
                        })
                        
                        logger.info(f"Finding: {title} - {resource.name} ({severity})")
                        
                except Exception as e:
                    logger.error(f"Error evaluating {finding_name} against resource {resource.resource_id}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error initializing finding {finding_name}: {str(e)}")
    
    return findings_results

def export_to_csv(findings, output_file):
    """Export findings to CSV file"""
    if not findings:
        logger.warning("No findings to export to CSV")
        return
    
    try:
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = [
                'scan_id', 'account_id', 'region', 'resource_id', 'resource_name',
                'finding_type', 'severity', 'title', 'description', 'remediation'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for finding in findings:
                writer.writerow(finding)
                
        logger.info(f"Exported {len(findings)} findings to {output_file}")
    except Exception as e:
        logger.error(f"Failed to export findings to CSV: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='AWS CSPM CLI Tool')
    parser.add_argument('--output', '-o', default='findings.csv', help='Output CSV file path')
    parser.add_argument('--debug', '-d', action='store_true', help='Enable debug logging')
    parser.add_argument('--env-file', '-e', default='.env', help='Path to .env file')
    parser.add_argument('--version', '-v', action='version', version=f'Easy CSPM {__version__}')
    args = parser.parse_args()
    
    # Load env file
    load_dotenv(args.env_file)
    
    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    configure_logging(log_level)
    
    # Load AWS configuration
    aws_config = load_env_config()
    
    if not aws_config['aws_access_key_id'] or not aws_config['aws_secret_access_key']:
        logger.error("AWS credentials not found in .env file or environment variables")
        sys.exit(1)
    
    # Initialize database
    db_manager = DBManager(aws_config['db_connection_string'])
    db_manager.init_db()
    
    # Discover scanner and finding classes
    scanner_classes = discover_scanner_classes()
    finding_classes = discover_finding_classes()
    
    logger.info(f"Starting CSPM scan with {len(scanner_classes)} scanners and {len(finding_classes)} findings types")
    
    all_findings = []
    
    # Run scanners and findings for each region
    for region in aws_config['aws_regions']:
        logger.info(f"Processing region: {region}")
        
        # Initialize AWS client for this region
        aws_client = AWSClient(
            aws_access_key_id=aws_config['aws_access_key_id'],
            aws_secret_access_key=aws_config['aws_secret_access_key'],
            aws_session_token=aws_config['aws_session_token'],
            region=region
        )
        
        # Run resource scanners
        run_scanners(scanner_classes, aws_client, db_manager, aws_config['aws_account_id'], region)
        
        # Run findings
        findings_results = run_findings(finding_classes, db_manager, aws_config['aws_account_id'], region)
        all_findings.extend(findings_results)
    
    # Export findings to CSV
    export_to_csv(all_findings, args.output)
    
    # Summary
    logger.info(f"CSPM scan completed: {len(all_findings)} findings detected across {len(aws_config['aws_regions'])} regions")
    
    # Return exit code 1 if critical or high findings were found
    if any(finding['severity'] in ['critical', 'high'] for finding in all_findings):
        logger.warning("Critical or high severity findings detected")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 