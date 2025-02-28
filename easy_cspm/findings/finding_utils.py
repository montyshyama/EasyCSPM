import json
from ..core.logging_config import logger

def get_property(resource, key, default=None):
    """
    Safely access a resource property by key, handling both dictionary and string formats.
    
    Args:
        resource: The resource object
        key: The property key to access
        default: Default value to return if key not found
        
    Returns:
        The property value or default if not found
    """
    # First try to access properties_dict if available
    if hasattr(resource, 'properties_dict') and isinstance(resource.properties_dict, dict):
        return resource.properties_dict.get(key, default)
    
    # Next try to parse properties from string if needed
    props = {}
    if hasattr(resource, 'properties'):
        if isinstance(resource.properties, dict):
            props = resource.properties
        elif isinstance(resource.properties, str):
            try:
                props = json.loads(resource.properties)
            except:
                logger.error(f"Failed to parse properties for resource {resource.resource_id}")
    
    # Store the parsed properties for future use
    if not hasattr(resource, 'properties_dict'):
        resource.properties_dict = props
    
    return props.get(key, default) 