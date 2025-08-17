"""
Configuration utilities for loading and managing environment variables.
"""
import os
from dotenv import load_dotenv

def load_config():
    """
    Load configuration from environment variables.
    
    Returns:
        dict: Dictionary containing configuration values
    """
    # Load environment variables from .env file
    load_dotenv()
    
    return {
        "openai_api_key": os.getenv("OPENAI_API_KEY"),
        "app_environment": os.getenv("APP_ENVIRONMENT", "development"),
        "log_level": os.getenv("LOG_LEVEL", "INFO"),
    }

# Load configuration on module import
config = load_config() 