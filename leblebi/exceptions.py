"""Custom exception classes for Leblebi

This module provides a hierarchy of custom exceptions with detailed
error messages to help users understand and fix issues.
"""


class LeblebiError(Exception):
    """Base exception for all Leblebi errors
    
    All custom exceptions inherit from this class to allow catching
    all Leblebi-specific errors with a single exception handler.
    
    Attributes:
        message: Error message
        suggestion: Optional suggestion for fixing the issue
    """
    
    def __init__(self, message: str, suggestion: str = ""):
        """Initialize Leblebi error
        
        Args:
            message: Error message describing what went wrong
            suggestion: Optional suggestion for fixing the issue
        """
        self.message = message
        self.suggestion = suggestion
        if suggestion:
            full_message = f"{message}\n\nSuggestion: {suggestion}"
        else:
            full_message = message
        super().__init__(full_message)


class ConfigurationError(LeblebiError):
    """Configuration related errors
    
    Raised when configuration validation fails or required
    configuration values are missing or invalid.
    """
    pass


class APIError(LeblebiError):
    """API related errors
    
    Base class for all Wazuh API related errors.
    """
    pass


class APIConnectionError(APIError):
    """API connection errors
    
    Raised when unable to connect to Wazuh API.
    This includes network errors, DNS resolution failures, etc.
    """
    pass


class APIAuthenticationError(APIError):
    """API authentication errors
    
    Raised when API authentication fails.
    This includes invalid credentials, expired tokens, etc.
    """
    pass


class APITimeoutError(APIError):
    """API timeout errors
    
    Raised when API requests exceed the configured timeout.
    """
    pass


class ReportGenerationError(LeblebiError):
    """Report generation errors
    
    Raised when HTML report generation fails.
    This includes template errors, file write errors, etc.
    """
    pass


class AlertProcessingError(LeblebiError):
    """Alert processing errors
    
    Raised when alert processing fails.
    This includes JSON parsing errors, file read errors, etc.
    """
    pass


class EmailError(LeblebiError):
    """Email sending errors
    
    Raised when email sending fails.
    This includes SMTP connection errors, authentication failures, etc.
    """
    pass


class MemoryError(LeblebiError):
    """Memory related errors
    
    Raised when memory limits are exceeded or memory operations fail.
    Note: This shadows Python's built-in MemoryError to provide
    more context-specific error messages.
    """
    pass

