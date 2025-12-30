"""Factory classes for creating Leblebi components"""

from typing import Optional
from leblebi.wazuh_api import WazuhAPI
from leblebi.exceptions import ConfigurationError, APIConnectionError
from leblebi.config import Config


class WazuhAPIFactory:
    """Factory for creating and managing WazuhAPI instances"""
    
    _instance: Optional[WazuhAPI] = None
    _config: Optional[Config] = None
    
    @classmethod
    def create(cls, config: Config, force_new: bool = False) -> Optional[WazuhAPI]:
        """Create or get existing WazuhAPI instance
        
        Args:
            config: Configuration object
            force_new: If True, create new instance even if one exists
            
        Returns:
            WazuhAPI instance or None if API is disabled
        """
        # Check if API is enabled
        if not config.get('wazuh_api_enabled', False):
            return None
        
        # Return existing instance if available and not forcing new
        if not force_new and cls._instance is not None and cls._config == config:
            return cls._instance
        
        # Validate required configuration
        required_fields = ['wazuh_api_host', 'wazuh_api_username', 'wazuh_api_password']
        for field in required_fields:
            if not config.get(field):
                raise ConfigurationError(f"Required API configuration field '{field}' is missing")
        
        # Create new instance
        try:
            api_client = WazuhAPI(
                host=config.get('wazuh_api_host', 'localhost'),
                port=config.get('wazuh_api_port', 55000),
                protocol=config.get('wazuh_api_protocol', 'https'),
                username=config.get('wazuh_api_username', 'wazuh'),
                password=config.get('wazuh_api_password', 'wazuh'),
                verify_ssl=config.get('wazuh_api_verify_ssl', False)
            )
            
            # Test connection
            if not api_client.test_connection():
                raise APIConnectionError("Failed to connect to Wazuh API")
            
            # Store instance and config for reuse
            cls._instance = api_client
            cls._config = config
            
            return api_client
            
        except Exception as e:
            raise APIConnectionError(f"Failed to create WazuhAPI instance: {str(e)}") from e
    
    @classmethod
    def reset(cls):
        """Reset factory (clear cached instance)"""
        cls._instance = None
        cls._config = None

