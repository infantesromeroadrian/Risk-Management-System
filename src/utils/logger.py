"""
Logging utilities for the application.
"""
import logging
import sys
from .config import config

def setup_logger(name):
    """
    Set up a logger with the given name and configured log level.
    
    Args:
        name (str): Name for the logger
        
    Returns:
        Logger: Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Get log level from config
    log_level = getattr(logging, config.get("log_level", "INFO"))
    logger.setLevel(log_level)
    
    # Add console handler if not already added
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    return logger 