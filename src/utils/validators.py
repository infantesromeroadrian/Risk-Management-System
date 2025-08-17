"""
Validation utilities for data validation.
"""
from typing import Dict, Any, List, Optional

def validate_incident_data(data: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Validate incident data format and required fields.
    
    Args:
        data (dict): The incident data to validate
        
    Returns:
        dict: Dictionary with field names as keys and lists of error messages as values
    """
    errors = {}
    
    # Check required fields
    required_fields = ["titulo", "descripcion"]
    for field in required_fields:
        if field not in data or not data[field]:
            errors[field] = [f"El campo {field} es obligatorio"]
    
    return errors

def is_valid_severity(severity: str) -> bool:
    """
    Check if the severity value is valid.
    
    Args:
        severity (str): Severity level string
        
    Returns:
        bool: True if valid, False otherwise
    """
    valid_severities = ["low", "medium", "high", "critical", 
                        "baja", "media", "alta", "critica"]
    return severity.lower() in valid_severities

def is_valid_status(status: str) -> bool:
    """
    Check if the status value is valid.
    
    Args:
        status (str): Status string
        
    Returns:
        bool: True if valid, False otherwise
    """
    valid_statuses = ["open", "investigating", "resolved", "closed",
                     "abierto", "investigando", "resuelto", "cerrado"]
    return status.lower() in valid_statuses 