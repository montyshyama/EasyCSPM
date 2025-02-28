import hashlib
import json
from sqlalchemy import create_engine, and_, func
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.exc import SQLAlchemyError
from .models import Base, Account, Scan, Resource, Finding
from ..core.logging_config import logger
from ..core.exceptions import DatabaseError

class Database:
    """Database operations class"""
    
    def __init__(self, db_uri="sqlite:///easy_cspm.db"):
        """Initialize the database connection and create tables if they don't exist"""
        try:
            self.engine = create_engine(db_uri)
            self.session_factory = sessionmaker(bind=self.engine)
            self.Session = scoped_session(self.session_factory)
            Base.metadata.create_all(self.engine)
            logger.info(f"Database initialized with {db_uri}")
        except SQLAlchemyError as e:
            logger.error(f"Failed to initialize database: {str(e)}")
            raise DatabaseError(f"Failed to initialize database: {str(e)}")
    
    def get_session(self):
        """Get a database session"""
        return self.Session()
    
    def store_account(self, account_name, account_id, access_key_id, secret_access_key, regions):
        """Store AWS account credentials"""
        session = self.get_session()
        try:
            # Check if account exists
            existing_account = session.query(Account).filter_by(account_id=account_id).first()
            
            if existing_account:
                # Update existing account
                existing_account.account_name = account_name
                existing_account.access_key_id = access_key_id
                existing_account.secret_access_key = secret_access_key
                existing_account.regions = regions
                session.commit()
                logger.info(f"Updated account: {account_id} ({account_name})")
                return existing_account.id
            else:
                # Create new account
                new_account = Account(
                    account_name=account_name,
                    account_id=account_id,
                    access_key_id=access_key_id,
                    secret_access_key=secret_access_key,
                    regions=regions
                )
                session.add(new_account)
                session.commit()
                logger.info(f"Stored new account: {account_id} ({account_name})")
                return new_account.id
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Database error storing account {account_id}: {str(e)}")
            raise DatabaseError(f"Failed to store account {account_id}: {str(e)}")
        finally:
            session.close()
    
    def get_accounts(self):
        """Get all stored AWS accounts"""
        session = self.get_session()
        try:
            accounts = session.query(Account).all()
            logger.info(f"Retrieved {len(accounts)} accounts")
            return accounts
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving accounts: {str(e)}")
            raise DatabaseError(f"Failed to retrieve accounts: {str(e)}")
        finally:
            session.close()
    
    def create_scan(self, account_id):
        """Create a new scan record"""
        session = self.get_session()
        try:
            account = session.query(Account).filter_by(id=account_id).first()
            if not account:
                raise DatabaseError(f"Account with ID {account_id} not found")
            
            new_scan = Scan(account_id=account_id)
            session.add(new_scan)
            session.commit()
            
            # Update account with last scan ID
            account.last_scan_id = new_scan.scan_id
            session.commit()
            
            logger.info(f"Created new scan {new_scan.scan_id} for account {account.account_id}")
            return new_scan.id, new_scan.scan_id
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Database error creating scan for account {account_id}: {str(e)}")
            raise DatabaseError(f"Failed to create scan for account {account_id}: {str(e)}")
        finally:
            session.close()
    
    def update_scan_status(self, scan_id, status, error_message=None):
        """Update scan status and end time"""
        session = self.get_session()
        try:
            scan = session.query(Scan).filter_by(scan_id=scan_id).first()
            if not scan:
                raise DatabaseError(f"Scan with ID {scan_id} not found")
            
            scan.status = status
            if status in ['completed', 'failed']:
                scan.end_time = func.now()
            if error_message:
                scan.error_message = error_message
                
            session.commit()
            logger.info(f"Updated scan {scan_id} status to {status}")
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Database error updating scan {scan_id}: {str(e)}")
            raise DatabaseError(f"Failed to update scan {scan_id}: {str(e)}")
        finally:
            session.close()
    
    def store_resource(self, scan_id, resource_id, account_id, region, service, resource_type, name, properties):
        """Store a discovered AWS resource"""
        session = self.get_session()
        try:
            # Generate a fingerprint for deduplication
            properties_str = json.dumps(properties, sort_keys=True)
            fingerprint = hashlib.sha256(properties_str.encode()).hexdigest()
            
            # Get the scan record
            scan = session.query(Scan).filter_by(scan_id=scan_id).first()
            if not scan:
                raise DatabaseError(f"Scan with ID {scan_id} not found")
            
            # Check for existing resource with same fingerprint in previous scans
            existing_resource = (
                session.query(Resource)
                .filter(
                    Resource.resource_id == resource_id,
                    Resource.account_id == account_id,
                    Resource.region == region
                )
                .first()
            )
            
            if existing_resource:
                # If resource exists but properties have changed (different fingerprint)
                if existing_resource.fingerprint != fingerprint:
                    existing_resource.properties = properties
                    existing_resource.fingerprint = fingerprint
                    existing_resource.name = name
                    existing_resource.scan_id = scan.id
                    existing_resource.updated_at = func.now()
                    logger.info(f"Updated resource {resource_id} in account {account_id}, region {region}")
                else:
                    # Resource hasn't changed, just update the scan_id reference
                    existing_resource.scan_id = scan.id
                    logger.debug(f"Resource {resource_id} in account {account_id}, region {region} unchanged")
                
                session.commit()
                return existing_resource.id
            else:
                # Create new resource
                new_resource = Resource(
                    resource_id=resource_id,
                    scan_id=scan.id,
                    account_id=account_id,
                    region=region,
                    service=service,
                    resource_type=resource_type,
                    name=name,
                    properties=properties,
                    fingerprint=fingerprint
                )
                session.add(new_resource)
                session.commit()
                logger.info(f"Stored new resource {resource_id} of type {resource_type} in account {account_id}, region {region}")
                return new_resource.id
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Database error storing resource {resource_id}: {str(e)}")
            raise DatabaseError(f"Failed to store resource {resource_id}: {str(e)}")
        finally:
            session.close()
    
    def store_finding(self, scan_id, resource_id, finding_type, severity, title, description, remediation, properties=None):
        """Store a security finding"""
        session = self.get_session()
        try:
            # Get the scan record
            scan = session.query(Scan).filter_by(scan_id=scan_id).first()
            if not scan:
                raise DatabaseError(f"Scan with ID {scan_id} not found")
            
            # Check if the resource exists
            resource = session.query(Resource).filter_by(id=resource_id).first()
            if not resource:
                raise DatabaseError(f"Resource with ID {resource_id} not found")
            
            # Check for existing finding with same type for this resource
            existing_finding = (
                session.query(Finding)
                .filter(
                    Finding.resource_id == resource_id,
                    Finding.finding_type == finding_type
                )
                .first()
            )
            
            if existing_finding:
                # Update existing finding
                existing_finding.scan_id = scan.id
                existing_finding.severity = severity
                existing_finding.title = title
                existing_finding.description = description
                existing_finding.remediation = remediation
                if properties:
                    existing_finding.properties = properties
                existing_finding.updated_at = func.now()
                session.commit()
                logger.info(f"Updated finding {finding_type} for resource {resource.resource_id}")
                return existing_finding.id
            else:
                # Create new finding
                new_finding = Finding(
                    scan_id=scan.id,
                    resource_id=resource_id,
                    finding_type=finding_type,
                    severity=severity,
                    title=title,
                    description=description,
                    remediation=remediation,
                    properties=properties or {}
                )
                session.add(new_finding)
                session.commit()
                logger.info(f"Stored new finding {finding_type} for resource {resource.resource_id}")
                return new_finding.id
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Database error storing finding {finding_type} for resource {resource_id}: {str(e)}")
            raise DatabaseError(f"Failed to store finding {finding_type} for resource {resource_id}: {str(e)}")
        finally:
            session.close()
    
    def get_resources_for_scan(self, scan_id):
        """Get all resources discovered in a scan"""
        session = self.get_session()
        try:
            scan = session.query(Scan).filter_by(scan_id=scan_id).first()
            if not scan:
                raise DatabaseError(f"Scan with ID {scan_id} not found")
            
            resources = session.query(Resource).filter_by(scan_id=scan.id).all()
            logger.info(f"Retrieved {len(resources)} resources for scan {scan_id}")
            return resources
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving resources for scan {scan_id}: {str(e)}")
            raise DatabaseError(f"Failed to retrieve resources for scan {scan_id}: {str(e)}")
        finally:
            session.close()
    
    def get_findings_for_scan(self, scan_id):
        """Get all findings from a scan"""
        session = self.get_session()
        try:
            scan = session.query(Scan).filter_by(scan_id=scan_id).first()
            if not scan:
                raise DatabaseError(f"Scan with ID {scan_id} not found")
            
            findings = session.query(Finding).filter_by(scan_id=scan.id).all()
            logger.info(f"Retrieved {len(findings)} findings for scan {scan_id}")
            return findings
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving findings for scan {scan_id}: {str(e)}")
            raise DatabaseError(f"Failed to retrieve findings for scan {scan_id}: {str(e)}")
        finally:
            session.close() 