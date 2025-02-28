import json
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
import datetime
from ..core.logging_config import logger

Base = declarative_base()

class Resource(Base):
    __tablename__ = 'resources'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(255), nullable=False)
    resource_id = Column(String(255), nullable=False)
    account_id = Column(String(64), nullable=False)
    region = Column(String(64), nullable=False)
    service = Column(String(64), nullable=False)
    resource_type = Column(String(64), nullable=False)
    name = Column(String(255), nullable=True)
    properties = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    findings = relationship("Finding", back_populates="resource")

    def get_properties(self):
        """Get properties as a Python dictionary"""
        if not self.properties:
            return {}
        try:
            return json.loads(self.properties)
        except Exception:
            logger.error(f"Failed to parse properties for resource {self.resource_id}")
            return {}

class Finding(Base):
    __tablename__ = 'findings'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(255), nullable=False)
    resource_id = Column(Integer, ForeignKey('resources.id'), nullable=False)
    account_id = Column(String(64), nullable=False)
    region = Column(String(64), nullable=False)
    finding_type = Column(String(128), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(64), nullable=False)
    remediation = Column(Text, nullable=True)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    resource = relationship("Resource", back_populates="findings")

class DBManager:
    """Database manager for storing CSPM scan results"""
    
    def __init__(self, connection_string='sqlite:///easy_cspm.db'):
        """Initialize database manager with connection string"""
        self.connection_string = connection_string
        self.engine = create_engine(connection_string)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()
        
    def init_db(self):
        """Initialize database tables"""
        Base.metadata.create_all(self.engine)
        logger.debug("Database initialized")
        
    def close(self):
        """Close database connection"""
        self.session.close()
        
    def store_resource(self, scan_id, resource_id, account_id, region, service, resource_type, name, properties=None):
        """Store a resource in the database"""
        try:
            # Check if this resource already exists
            existing_resource = self.session.query(Resource).filter_by(
                resource_id=resource_id,
                account_id=account_id,
                region=region
            ).first()
            
            # Convert properties to JSON string for storage
            properties_json = json.dumps(properties) if properties else None
            
            if existing_resource:
                # Update existing resource
                existing_resource.scan_id = scan_id
                existing_resource.service = service
                existing_resource.resource_type = resource_type
                existing_resource.name = name
                existing_resource.properties = properties_json
                existing_resource.updated_at = datetime.datetime.utcnow()
                self.session.commit()
                logger.debug(f"Updated resource {resource_id} in database")
                return existing_resource.id
            else:
                # Create new resource
                new_resource = Resource(
                    scan_id=scan_id,
                    resource_id=resource_id,
                    account_id=account_id,
                    region=region,
                    service=service,
                    resource_type=resource_type,
                    name=name,
                    properties=properties_json
                )
                self.session.add(new_resource)
                self.session.commit()
                logger.debug(f"Stored resource {resource_id} in database")
                return new_resource.id
        except Exception as e:
            self.session.rollback()
            logger.error(f"Failed to store resource {resource_id}: {str(e)}")
            raise
            
    def get_resources_by_account_and_region(self, account_id, region):
        """Get all resources for a given account and region"""
        try:
            resources = self.session.query(Resource).filter_by(
                account_id=account_id,
                region=region
            ).all()
            logger.debug(f"Retrieved {len(resources)} resources for account {account_id} in region {region}")
            return resources
        except Exception as e:
            logger.error(f"Failed to get resources for account {account_id} in region {region}: {str(e)}")
            return []
    
    def store_finding(self, scan_id, resource_id, finding_type, severity, title, description, remediation, properties=None):
        """Store a finding in the database"""
        try:
            # Create new finding
            new_finding = Finding(
                scan_id=scan_id,
                resource_id=resource_id,
                finding_type=finding_type,
                severity=severity,
                title=title,
                description=description,
                remediation=remediation,
                properties=json.dumps(properties) if properties else None
            )
            self.session.add(new_finding)
            self.session.commit()
            logger.debug(f"Stored finding {finding_type} for resource {resource_id} in database")
            return new_finding.id
        except Exception as e:
            self.session.rollback()
            logger.error(f"Failed to store finding for resource {resource_id}: {str(e)}")
            raise
    
    def get_findings_by_scan_id(self, scan_id):
        """Get all findings for a given scan ID"""
        try:
            findings = self.session.query(Finding).filter_by(scan_id=scan_id).all()
            logger.debug(f"Retrieved {len(findings)} findings for scan {scan_id}")
            return findings
        except Exception as e:
            logger.error(f"Failed to get findings for scan {scan_id}: {str(e)}")
            return [] 