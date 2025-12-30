"""Logging level guidelines for Leblebi

This module provides constants and guidelines for consistent logging
throughout the application.

Logging Level Guidelines:
- DEBUG: Detailed diagnostic information for troubleshooting (e.g., API request details, parsing steps)
- INFO: General informational messages about application flow (e.g., "Processing alerts", "Report generated")
- WARNING: Warning messages for potentially problematic situations (e.g., missing optional data, API connection issues)
- ERROR: Error messages for failures that don't stop execution (e.g., failed API call, file read error)
- CRITICAL: Critical errors that may cause application to stop (e.g., configuration errors, fatal exceptions)
"""

import logging

# Logging level constants
LOG_DEBUG = logging.DEBUG
LOG_INFO = logging.INFO
LOG_WARNING = logging.WARNING
LOG_ERROR = logging.ERROR
LOG_CRITICAL = logging.CRITICAL


def should_log_error(exception: Exception, context: str = "") -> bool:
    """Determine if an exception should be logged as error or warning
    
    Args:
        exception: Exception that occurred
        context: Context where exception occurred
        
    Returns:
        True if should log as error, False if warning
    """
    # Network/API errors are usually warnings (expected in some scenarios)
    if isinstance(exception, (ConnectionError, TimeoutError)):
        return False
    
    # File not found for optional files is warning
    if isinstance(exception, FileNotFoundError) and 'optional' in context.lower():
        return False
    
    # Permission errors are warnings if for optional operations
    if isinstance(exception, PermissionError) and 'optional' in context.lower():
        return False
    
    # Everything else is an error
    return True


def get_log_level_for_exception(exception: Exception, context: str = "") -> int:
    """Get appropriate log level for an exception
    
    Args:
        exception: Exception that occurred
        context: Context where exception occurred
        
    Returns:
        Logging level constant
    """
    if should_log_error(exception, context):
        return LOG_ERROR
    return LOG_WARNING

