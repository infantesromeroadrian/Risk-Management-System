"""
Integration tests for API endpoints.
"""
import os
import sys
import unittest
from fastapi.testclient import TestClient

# Add the src directory to the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.main import app


class TestAPI(unittest.TestCase):
    """
    Integration tests for API endpoints.
    """
    
    def setUp(self):
        """Set up test client."""
        self.client = TestClient(app)
    
    def test_home_page(self):
        """Test the home page endpoint."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])
    
    def test_examples_endpoint(self):
        """Test the examples endpoint."""
        response = self.client.get("/api/examples")
        self.assertEqual(response.status_code, 200)
        self.assertIn("application/json", response.headers["content-type"])
    
    def test_analyze_endpoint_valid(self):
        """Test the analyze endpoint with valid data."""
        data = {
            "titulo": "Test Incident",
            "descripcion": "Test Description for security incident"
        }
        response = self.client.post("/api/analyze", json=data)
        self.assertEqual(response.status_code, 200)
        self.assertIn("application/json", response.headers["content-type"])
        
        # Check response structure
        json_data = response.json()
        self.assertIn("status", json_data)
        self.assertIn("data", json_data)
        self.assertEqual(json_data["status"], "success")
    
    def test_analyze_endpoint_invalid(self):
        """Test the analyze endpoint with invalid data."""
        # Missing description
        data = {
            "titulo": "Test Incident"
        }
        response = self.client.post("/api/analyze", json=data)
        self.assertEqual(response.status_code, 400)
        
        # Missing title
        data = {
            "descripcion": "Test Description"
        }
        response = self.client.post("/api/analyze", json=data)
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main() 