from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey, Boolean, Text, create_engine, Index, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from datetime import datetime
import uuid
import json

Base = declarative_base()

class Account(Base):
    """AWS Account information"""
    __tablename__ = 'accounts'
    
    id = Column(Integer, primary_key=True)
    account_id = Column(String(12), unique=True, nullable=False)
    account_name = Column(String(255), nullable=False)
    access_key_id = Column(String(255), nullable=False)
    secret_access_key = Column(String(255), nullable=False)
    regions = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_scan_id = Column(String(36), nullable=True)
    
    scans = relationship("Scan", back_populates="account")
    
    def __repr__(self):
        return f"<Account(id={self.id}, account_id='{self.account_id}', account_name='{self.account_name}')>"

class Scan(Base):
    """Scan information"""
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    account_id = Column(Integer, ForeignKey('accounts.id'))
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    status = Column(String(20), default='running')  # running, completed, failed
    error_message = Column(Text, nullable=True)
    
    account = relationship("Account", back_populates="scans")
    resources = relationship("Resource", back_populates="scan")
    findings = relationship("Finding", back_populates="scan")
    
    def __repr__(self):
        return f"<Scan(scan_id='{self.scan_id}', status='{self.status}')>"

class Resource(Base):
    """AWS Resource information"""
    __tablename__ = 'resources'
    
    id = Column(Integer, primary_key=True)
    resource_id = Column(String(255), nullable=False)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    account_id = Column(String(12), nullable=False)
    region = Column(String(20), nullable=False)
    service = Column(String(50), nullable=False)
    resource_type = Column(String(100), nullable=False)
    name = Column(String(255), nullable=True)
    properties = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    fingerprint = Column(String(64), nullable=False)  # Hash of the resource properties for deduplication
    
    scan = relationship("Scan", back_populates="resources")
    findings = relationship("Finding", back_populates="resource")
    
    __table_args__ = (
        Index('idx_resource_id_account_region', 'resource_id', 'account_id', 'region', unique=True),
        Index('idx_fingerprint', 'fingerprint'),
    )
    
    def __repr__(self):
        return f"<Resource(resource_id='{self.resource_id}', service='{self.service}', type='{self.resource_type}')>"

class Finding(Base):
    """Security Finding information"""
    __tablename__ = 'findings'
    
    id = Column(Integer, primary_key=True)
    finding_id = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    scan_id = Column(Integer, ForeignKey('scans.id'))
    resource_id = Column(Integer, ForeignKey('resources.id'))
    finding_type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low, informational
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    properties = Column(JSON, nullable=True)
    status = Column(String(20), default='active')  # active, resolved, suppressed
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    scan = relationship("Scan", back_populates="findings")
    resource = relationship("Resource", back_populates="findings")
    
    __table_args__ = (
        Index('idx_finding_type_resource', 'finding_type', 'resource_id'),
    )
    
    def __repr__(self):
        return f"<Finding(finding_id='{self.finding_id}', type='{self.finding_type}', severity='{self.severity}')>" 