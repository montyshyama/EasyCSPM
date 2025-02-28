import logging
import colorlog
import os
import sys
from datetime import datetime

# Create logger
logger = logging.getLogger("easy_cspm")

def configure_logging(log_level=logging.INFO, log_file=None):
    """Configure logging for the application
    
    Args:
        log_level: The logging level to use
        log_file: Optional path to a log file
    """
    if not log_file:
        # Create logs directory if it doesn't exist
        if not os.path.exists('logs'):
            os.makedirs('logs')
        
        # Default log file with timestamp
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        log_file = f"logs/easy_cspm_{timestamp}.log"
    
    # Set up root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Clear existing handlers to avoid duplicate logs
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
        
    # Console handler with colors
    console_handler = colorlog.StreamHandler(stream=sys.stdout)
    console_handler.setLevel(log_level)
    
    # Color formatting
    console_formatter = colorlog.ColoredFormatter(
        '%(log_color)s%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white',
        }
    )
    console_handler.setFormatter(console_formatter)
    
    # File handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(log_level)
    file_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', 
                                       datefmt='%Y-%m-%d %H:%M:%S')
    file_handler.setFormatter(file_formatter)
    
    # Add handlers to root logger
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
    
    # Set our app's logger level
    logger.setLevel(log_level)
    
    # Log the initialization
    logger.info(f"Logging initialized at level {logging.getLevelName(log_level)}")
    logger.info(f"Log file: {os.path.abspath(log_file)}")
    
    return logger 