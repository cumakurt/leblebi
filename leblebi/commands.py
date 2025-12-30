"""Command pattern implementation for Leblebi CLI commands"""

import sys
import logging
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from leblebi.config import Config
from leblebi.exceptions import LeblebiError
from leblebi.factory import WazuhAPIFactory
from leblebi.wazuh_api import WazuhAPI


class Command(ABC):
    """Base command interface"""
    
    def __init__(self, config: Config, logger: Optional[logging.Logger] = None):
        """Initialize command
        
        Args:
            config: Configuration object
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or logging.getLogger('leblebi')
    
    @abstractmethod
    def execute(self) -> int:
        """Execute command
        
        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        pass


class TestAPICommand(Command):
    """Command to test Wazuh API connection"""
    
    def execute(self) -> int:
        """Test API connection and display results"""
        from leblebi.leblebi import test_api_connection
        
        try:
            success = test_api_connection(self.config)
            return 0 if success else 1
        except Exception as e:
            self.logger.error(f"API test failed: {e}", exc_info=True)
            return 1


class TestConfigurationCommand(Command):
    """Command to test configuration"""
    
    def execute(self) -> int:
        """Test configuration and display results"""
        from leblebi.leblebi import test_configuration
        
        try:
            success = test_configuration(self.config)
            return 0 if success else 1
        except Exception as e:
            self.logger.error(f"Configuration test failed: {e}", exc_info=True)
            return 1


class GenerateReportCommand(Command):
    """Command to generate security report"""
    
    def __init__(
        self,
        config: Config,
        logger: Optional[logging.Logger] = None,
        alerts_file: Optional[str] = None,
        dry_run: bool = False,
        test_mode: bool = False
    ):
        """Initialize report generation command
        
        Args:
            config: Configuration object
            logger: Logger instance
            alerts_file: Optional path to alerts file
            dry_run: If True, don't send email
            test_mode: If True, save report to current directory
        """
        super().__init__(config, logger)
        self.alerts_file = alerts_file
        self.dry_run = dry_run
        self.test_mode = test_mode
    
    def execute(self) -> int:
        """Generate security report"""
        # This will be implemented by refactoring main() function
        # For now, return success
        return 0

