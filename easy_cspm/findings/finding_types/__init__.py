import os
import sys
import importlib
import inspect
from ...core.logging_config import logger

def update_finding_classes():
    """Update all finding classes to use _evaluate instead of evaluate"""
    try:
        # Get the directory of finding_types
        finding_types_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Loop through all Python files in the directory
        for filename in os.listdir(finding_types_dir):
            if filename.endswith('_findings.py'):
                module_name = filename[:-3]  # Remove .py
                full_module_name = f"easy_cspm.findings.finding_types.{module_name}"
                
                # Import the module
                module = importlib.import_module(full_module_name)
                
                # Find all classes that have evaluate but not _evaluate
                for name, obj in inspect.getmembers(module):
                    if inspect.isclass(obj) and hasattr(obj, 'evaluate') and not hasattr(obj, '_evaluate'):
                        # Add _evaluate method to point to evaluate
                        setattr(obj, '_evaluate', getattr(obj, 'evaluate'))
                        
                        # Remove original evaluate to avoid conflicts
                        delattr(obj, 'evaluate')
                        
                        logger.debug(f"Updated {name} to use _evaluate")
        
        logger.info("All finding classes updated to use _evaluate")
    except Exception as e:
        logger.error(f"Error updating finding classes: {str(e)}") 