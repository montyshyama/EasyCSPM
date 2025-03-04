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
    
    # Cache for parsed properties
    _properties_dict = None

    def get_properties(self):
        """
        Get the properties as a dictionary
        
        Returns:
            dict: The properties as a dictionary
        """
        if self.properties is None:
            return {}
        
        # Already a dict, just return it
        if isinstance(self.properties, dict):
            return self.properties
        
        # Try to parse as JSON
        if isinstance(self.properties, str):
            try:
                return json.loads(self.properties)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse properties JSON for resource {self.resource_id}")
                return {}
        
        # Not sure what it is, try to convert to dict
        try:
            return dict(self.properties)
        except:
            logger.error(f"Could not convert properties to dict for resource {self.resource_id}")
            return {}
    
    def get_property(self, key, default=None):
        """
        Safely access a resource property by key
        
        Args:
            key: The property key to access
            default: Default value to return if key not found
            
        Returns:
            The property value or default if not found
        """
        # Get properties as dict first
        props = self.get_properties()
        
        # Return the requested property or default
        return props.get(key, default)

class Finding(Base):
    __tablename__ = 'findings'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(255), nullable=False)
    resource_id = Column(String(255), ForeignKey('resources.resource_id'))
    finding_type = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    properties = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
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

    def reset_db(self):
        """Drop all tables and recreate them"""
        Base.metadata.drop_all(self.engine)
        Base.metadata.create_all(self.engine)
        logger.debug("Database reset")
        
    def store_resource(self, scan_id, resource_id, account_id, region, service, resource_type, name, properties=None):
        """Store a resource in the database"""
        try:
            # Ensure resource_id is not None
            if resource_id is None:
                resource_id = f"{service}-{resource_type}-{name}-{int(datetime.datetime.now().timestamp())}"
                logger.warning(f"Generated resource_id for {name}: {resource_id}")
            
            # Check if properties is valid JSON if it's a string
            if properties is not None and isinstance(properties, str):
                try:
                    # Validate JSON string
                    json.loads(properties)
                except json.JSONDecodeError:
                    # If it's not valid JSON, convert it to JSON
                    properties = json.dumps({"raw_data": properties})
            # Check if resource already exists
            existing_resource = self.session.query(Resource).filter_by(resource_id=resource_id).first()
            
            if existing_resource:
                # Update existing resource
                existing_resource.scan_id = scan_id
                existing_resource.account_id = account_id
                existing_resource.region = region
                existing_resource.service = service
                existing_resource.resource_type = resource_type
                existing_resource.name = name
                existing_resource.properties = properties
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
                    properties=properties
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
            # Convert properties to JSON string if needed
            properties_json = None
            if properties is not None:
                if isinstance(properties, str):
                    try:
                        # Validate JSON string
                        json.loads(properties)
                        properties_json = properties
                    except json.JSONDecodeError:
                        properties_json = json.dumps({"raw_data": properties})
                else:
                    properties_json = json.dumps(properties)
            
            # Create new finding
            new_finding = Finding(
                scan_id=scan_id,
                resource_id=resource_id,
                finding_type=finding_type,
                severity=severity,
                title=title,
                description=description,
                remediation=remediation,
                properties=properties_json
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
