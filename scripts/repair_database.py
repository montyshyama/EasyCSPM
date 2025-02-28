import sys
import os
import json

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from easy_cspm.core.db_manager import DBManager
from easy_cspm.core.logging_config import logger

def repair_database():
    """Repair the database by ensuring all properties are properly stored as JSON"""
    try:
        db = DBManager()
        session = db.session
        
        # Get all resources
        resources = session.query(db.Resource).all()
        count = 0
        
        for resource in resources:
            # Check if properties exist and need conversion
            if resource.properties:
                if isinstance(resource.properties, str):
                    try:
                        # Try to parse as JSON to validate
                        json.loads(resource.properties)
                        # If it parsed correctly, no need to change
                    except:
                        # If it's not valid JSON but is a string, wrap it in quotes
                        resource.properties = json.dumps(resource.properties)
                        count += 1
                elif isinstance(resource.properties, dict):
                    # Convert dict to JSON string
                    resource.properties = json.dumps(resource.properties)
                    count += 1
        
        # Commit the changes
        if count > 0:
            session.commit()
            logger.info(f"Repaired {count} resources in the database")
        else:
            logger.info("No database repairs needed")
    
    except Exception as e:
        logger.error(f"Error repairing database: {str(e)}")

if __name__ == "__main__":
    repair_database() 