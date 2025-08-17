"""
Data service for handling JSON data files.
"""
from typing import Dict, Any, List, Optional
import json
import os
from src.utils.logger import setup_logger

logger = setup_logger(__name__)

class DataService:
    """
    Service for handling data operations.
    """
    
    def __init__(self, data_dir: str = "data"):
        """
        Initialize the data service with data directory.
        
        Args:
            data_dir (str): Path to the data directory
        """
        self.data_dir = data_dir
    
    def load_json_file(self, filename: str) -> Dict[str, Any]:
        """
        Load data from a JSON file.
        
        Args:
            filename (str): Name of the JSON file
            
        Returns:
            dict: Loaded JSON data or empty dict if error
        """
        try:
            file_path = os.path.join(self.data_dir, filename)
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading JSON file {filename}: {str(e)}")
            return {}
    
    def save_json_file(self, data: Dict[str, Any], 
                      filename: str) -> bool:
        """
        Save data to a JSON file.
        
        Args:
            data (dict): Data to save
            filename (str): Name of the JSON file
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            file_path = os.path.join(self.data_dir, filename)
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            logger.error(f"Error saving JSON file {filename}: {str(e)}")
            return False
    
    def load_incident_examples(self) -> Dict[str, Any]:
        """
        Load incident examples data.
        
        Returns:
            dict: Incident examples data
        """
        return self.load_json_file("incident_examples.json") 