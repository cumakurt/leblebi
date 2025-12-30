"""Logging module for Leblebi"""

import logging
import sys
import threading
from pathlib import Path
from typing import Optional


class Logger:
    """Centralized logging for Leblebi"""
    
    _instance: Optional['Logger'] = None
    _lock = threading.Lock()
    _logger: Optional[logging.Logger] = None
    
    def __new__(cls, log_level: str = 'INFO', log_file: Optional[str] = None):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, log_level: str = 'INFO', log_file: Optional[str] = None):
        """Initialize logger"""
        if hasattr(self, '_initialized') and self._initialized:
            return
        
        self._initialized = True
        
        # Determine log level
        level_map = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARN': logging.WARNING,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL,
        }
        level = level_map.get(log_level.upper(), logging.INFO)
        
        # Create logger
        self._logger = logging.getLogger('leblebi')
        self._logger.setLevel(level)
        
        # Clear existing handlers
        self._logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_format = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] [LEBLEBI] [PID:%(process)d] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_format)
        self._logger.addHandler(console_handler)
        
        # File handler if specified
        if log_file:
            try:
                log_path = Path(log_file)
                log_path.parent.mkdir(parents=True, exist_ok=True)
                file_handler = logging.FileHandler(log_file)
                file_handler.setLevel(level)
                file_format = logging.Formatter(
                    '[%(asctime)s] [%(levelname)s] [LEBLEBI] [PID:%(process)d] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
                file_handler.setFormatter(file_format)
                self._logger.addHandler(file_handler)
            except Exception as e:
                self._logger.warning(f"Could not create log file {log_file}: {e}")
    
    @property
    def logger(self) -> logging.Logger:
        """Get logger instance"""
        return self._logger
    
    def debug(self, message: str):
        """Log debug message"""
        self._logger.debug(message)
    
    def info(self, message: str):
        """Log info message"""
        self._logger.info(message)
    
    def warning(self, message: str):
        """Log warning message"""
        self._logger.warning(message)
    
    def error(self, message: str):
        """Log error message"""
        self._logger.error(message)
    
    def critical(self, message: str):
        """Log critical message"""
        self._logger.critical(message)


def get_logger(log_level: str = 'INFO', log_file: Optional[str] = None) -> logging.Logger:
    """Get or create logger instance"""
    logger = Logger(log_level, log_file)
    return logger.logger

