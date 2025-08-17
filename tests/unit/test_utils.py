"""
Unit tests for utility functions.
"""
import unittest
from unittest.mock import patch
import os
import sys

# Add the src directory to the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.utils.validators import (
    validate_incident_data,
    is_valid_severity,
    is_valid_status
)


class TestValidators(unittest.TestCase):
    """
    Test validators utility functions.
    """
    
    def test_validate_incident_data_valid(self):
        """Test validation with valid data."""
        data = {
            "titulo": "Test Incident",
            "descripcion": "Test Description"
        }
        errors = validate_incident_data(data)
        self.assertEqual(errors, {})
    
    def test_validate_incident_data_missing_fields(self):
        """Test validation with missing fields."""
        data = {
            "titulo": "Test Incident"
        }
        errors = validate_incident_data(data)
        self.assertIn("descripcion", errors)
        
        data = {
            "descripcion": "Test Description"
        }
        errors = validate_incident_data(data)
        self.assertIn("titulo", errors)
    
    def test_is_valid_severity(self):
        """Test severity validation."""
        self.assertTrue(is_valid_severity("low"))
        self.assertTrue(is_valid_severity("medium"))
        self.assertTrue(is_valid_severity("high"))
        self.assertTrue(is_valid_severity("critical"))
        self.assertTrue(is_valid_severity("CRITICAL"))  # Case insensitive
        self.assertTrue(is_valid_severity("alta"))  # Spanish
        
        self.assertFalse(is_valid_severity("invalid"))
        self.assertFalse(is_valid_severity(""))
    
    def test_is_valid_status(self):
        """Test status validation."""
        self.assertTrue(is_valid_status("open"))
        self.assertTrue(is_valid_status("investigating"))
        self.assertTrue(is_valid_status("resolved"))
        self.assertTrue(is_valid_status("closed"))
        self.assertTrue(is_valid_status("OPEN"))  # Case insensitive
        self.assertTrue(is_valid_status("abierto"))  # Spanish
        
        self.assertFalse(is_valid_status("invalid"))
        self.assertFalse(is_valid_status(""))


if __name__ == "__main__":
    unittest.main() 