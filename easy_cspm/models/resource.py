from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.orm import relationship
import datetime

class Resource(Base):
    """Database model for AWS resources"""
    __tablename__ = 'resources'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String, nullable=False)
    resource_id = Column(String, nullable=False)
    account_id = Column(String, nullable=False)
    region = Column(String, nullable=False)
    service = Column(String, nullable=False)
    resource_type = Column(String, nullable=False)
    name = Column(String)
    properties = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_updated = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    # Relationship to findings
    findings = relationship("Finding", back_populates="resource")
    
    def __repr__(self):
        return f"<Resource(id={self.id}, resource_id={self.resource_id}, name={self.name})>" 