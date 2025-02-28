import json
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
import datetime

Base = declarative_base()

class Resource(Base):
    __tablename__ = 'resources'
    
    id = Column(Integer, primary_key=True)
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

class Finding(Base):
    __tablename__ = 'findings'
    
    id = Column(Integer, primary_key=True)
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
    def __init__(self, connection_string):
        self.connection_string = connection_string
        self.engine = create_engine(connection_string)
        self.Session = sessionmaker(bind=self.engine)
    
    def init_db(self):
        """Initialize the database schema"""
        Base.metadata.create_all(self.engine)
    
    def add_resource(self, resource_id, account_id, region, service, resource_type, name, properties):
        """Add a resource to the database"""
        session = self.Session()
        try:
            # Check if resource already exists
            existing_resource = session.query(Resource).filter_by(
                resource_id=resource_id,
                account_id=account_id,
                region=region,
                service=service,
                resource_type=resource_type
            ).first()
            
            if existing_resource:
                # Update existing resource
                existing_resource.name = name
                existing_resource.properties = properties
                existing_resource.updated_at = datetime.datetime.utcnow()
                resource_id = existing_resource.id
            else:
                # Create new resource
                resource = Resource(
                    resource_id=resource_id,
                    account_id=account_id,
                    region=region,
                    service=service,
                    resource_type=resource_type,
                    name=name,
                    properties=properties
                )
                session.add(resource)
                session.flush()
                resource_id = resource.id
            
            session.commit()
            return resource_id
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def add_finding(self, resource_id, account_id, region, finding_type, title, description, severity, remediation, details):
        """Add a finding to the database"""
        session = self.Session()
        try:
            # Check if finding already exists
            existing_finding = session.query(Finding).filter_by(
                resource_id=resource_id,
                finding_type=finding_type
            ).first()
            
            if existing_finding:
                # Update existing finding
                existing_finding.title = title
                existing_finding.description = description
                existing_finding.severity = severity
                existing_finding.remediation = remediation
                existing_finding.details = details
                existing_finding.updated_at = datetime.datetime.utcnow()
            else:
                # Create new finding
                finding = Finding(
                    resource_id=resource_id,
                    account_id=account_id,
                    region=region,
                    finding_type=finding_type,
                    title=title,
                    description=description,
                    severity=severity,
                    remediation=remediation,
                    details=details
                )
                session.add(finding)
            
            session.commit()
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def get_resources_by_account_and_region(self, account_id, region):
        """Get all resources for a specific account and region"""
        session = self.Session()
        try:
            resources = session.query(Resource).filter_by(
                account_id=account_id,
                region=region
            ).all()
            return resources
        finally:
            session.close()
    
    def get_findings_by_account_and_region(self, account_id, region):
        """Get all findings for a specific account and region"""
        session = self.Session()
        try:
            findings = session.query(Finding).filter_by(
                account_id=account_id,
                region=region
            ).all()
            return findings
        finally:
            session.close() 