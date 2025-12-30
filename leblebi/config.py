"""Configuration management for Leblebi

This module provides configuration management with validation,
error handling, and support for environment variables.
"""

import os
import re
import configparser
from pathlib import Path
from typing import Optional, Dict, Any, List


class ConfigError(Exception):
    """Configuration error with detailed message
    
    Attributes:
        message: Error message describing the configuration issue
        field: Optional field name that caused the error
    """
    
    def __init__(self, message: str, field: Optional[str] = None):
        """Initialize configuration error
        
        Args:
            message: Error message
            field: Optional field name that caused the error
        """
        self.message = message
        self.field = field
        super().__init__(self.message)


class Config:
    """Configuration manager for Leblebi"""
    
    def __init__(self, config_file: Optional[str] = None, require_config: bool = True):
        """Initialize configuration from file or environment variables
        
        Args:
            config_file: Path to config file
            require_config: If True, config file must exist and be valid
        """
        # Default config file locations (in order of preference)
        default_locations = [
            os.getenv('LEBLEBI_CONFIG'),  # Environment variable
            './config.conf',  # Current directory
            os.path.join(os.path.expanduser('~'), '.leblebi', 'config.conf'),  # User home
            '/etc/leblebi/config.conf',  # System-wide
        ]
        
        # Find first existing config file
        if config_file:
            self.config_file = config_file
        else:
            self.config_file = None
            for location in default_locations:
                if location and os.path.exists(location):
                    self.config_file = location
                    break
        
        # Require config file if specified
        if require_config:
            if not self.config_file or not os.path.exists(self.config_file):
                raise ConfigError(
                    f"Configuration file is required but not found.\n"
                    f"Searched locations:\n" +
                    "\n".join(f"  - {loc}" for loc in default_locations if loc) +
                    f"\n\nPlease create a config.conf file or specify one with -c option."
                )
        
        self._config = {}
        self._load_config()
        self._validate_config()
    
    def _load_config(self):
        """Load configuration from file or use defaults"""
        # Default values
        defaults = {
            'level': 12,
            'top_alerts_count': 100,
            'log_dir': '/var/ossec/logs/alerts',
            'output_dir': '/var/ossec/logs/reports',
            'smtp_server': os.getenv('SMTP_SERVER', '10.101.1.1'),
            'smtp_port': int(os.getenv('SMTP_PORT', '25')),
            'mail_to': os.getenv('MAIL_TO', 'cuma.kurt@nscsoft.com'),
            'mail_from': os.getenv('MAIL_FROM', 'wazuh@nscsoft.com'),
            'mail_subject_prefix': 'Leblebi Security Report',
            'mail_format': 'html_attachment',  # HTML in body + HTML as attachment
            'smtp_use_tls': False,
            'smtp_auth_user': os.getenv('SMTP_AUTH_USER', ''),
            'smtp_auth_pass': os.getenv('SMTP_AUTH_PASS', ''),
            'log_level': os.getenv('LOG_LEVEL', 'WARNING'),
            'lock_file': os.path.join(os.getenv('HOME', '/tmp'), '.leblebi_report.lock'),
            'lock_timeout': 3600,
            # Wazuh API Configuration
            'wazuh_api_enabled': os.getenv('WAZUH_API_ENABLED', 'false').lower() in ('true', '1', 'yes'),
            'wazuh_api_host': os.getenv('WAZUH_API_HOST', 'localhost'),
            'wazuh_api_port': int(os.getenv('WAZUH_API_PORT', '55000')),
            'wazuh_api_protocol': os.getenv('WAZUH_API_PROTOCOL', 'https'),
            'wazuh_api_username': os.getenv('WAZUH_API_USERNAME', 'wazuh'),
            'wazuh_api_password': os.getenv('WAZUH_API_PASSWORD', 'wazuh'),
            'wazuh_api_verify_ssl': os.getenv('WAZUH_API_VERIFY_SSL', 'false').lower() in ('true', '1', 'yes'),
            # API-based data collection (optional - for advanced features)
            # Note: Alerts are ALWAYS read from alerts.json file (required)
            'use_api_for_agent_health': os.getenv('USE_API_FOR_AGENT_HEALTH', 'true').lower() in ('true', '1', 'yes'),
            'use_api_for_rootcheck': os.getenv('USE_API_FOR_ROOTCHECK', 'true').lower() in ('true', '1', 'yes'),
            'use_api_for_manager_status': os.getenv('USE_API_FOR_MANAGER_STATUS', 'true').lower() in ('true', '1', 'yes'),
            'use_logs_for_trends': os.getenv('USE_LOGS_FOR_TRENDS', 'true').lower() in ('true', '1', 'yes'),
            # Report Period
            'report_period': os.getenv('REPORT_PERIOD', '1d'),  # Format: 'Nd' where N is number of days (e.g., '1d', '2d', '7d')
            # Performance settings for large log files (optimized defaults for large files)
            'max_alerts_to_process': int(os.getenv('MAX_ALERTS_TO_PROCESS', '1000000')),  # 1 million default
            'sampling_enabled': os.getenv('SAMPLING_ENABLED', 'true').lower() in ('true', '1', 'yes'),  # Enabled by default
            'sampling_rate': float(os.getenv('SAMPLING_RATE', '0.1')),  # 10% default
            'use_streaming_parser': os.getenv('USE_STREAMING_PARSER', 'true').lower() in ('true', '1', 'yes'),
            'memory_limit_mb': int(os.getenv('MEMORY_LIMIT_MB', '0')),
            'max_agents_to_collect': int(os.getenv('MAX_AGENTS_TO_COLLECT', '50')),
            'api_max_workers': int(os.getenv('API_MAX_WORKERS', '5')),
            'api_timeout': int(os.getenv('API_TIMEOUT', '30')),
            'api_collection_timeout': int(os.getenv('API_COLLECTION_TIMEOUT', '120')),
            'api_limit_per_agent': int(os.getenv('API_LIMIT_PER_AGENT', '10')),
            'attack_timeline_min_level': int(os.getenv('ATTACK_TIMELINE_MIN_LEVEL', '12')),
            'attack_timeline_limit': int(os.getenv('ATTACK_TIMELINE_LIMIT', '500')),
        }
        
        # Load from config file if exists
        if os.path.exists(self.config_file):
            parser = configparser.ConfigParser()
            parser.read(self.config_file)
            
            if 'leblebi' in parser:
                section = parser['leblebi']
                defaults.update({
                    'level': section.getint('level', defaults['level']),
                    'top_alerts_count': section.getint('top_alerts_count', defaults['top_alerts_count']),
                    'log_dir': section.get('log_dir', defaults['log_dir']),
                    'output_dir': section.get('output_dir', defaults['output_dir']),
                    'smtp_server': section.get('smtp_server', defaults['smtp_server']),
                    'smtp_port': section.getint('smtp_port', defaults['smtp_port']),
                    'mail_to': section.get('mail_to', defaults['mail_to']),  # Can be comma/semicolon separated
                    'mail_from': section.get('mail_from', defaults['mail_from']),
                    'mail_subject_prefix': section.get('mail_subject_prefix', defaults['mail_subject_prefix']),
                    'mail_format': section.get('mail_format', defaults['mail_format']),
                    'smtp_use_tls': section.getboolean('smtp_use_tls', defaults['smtp_use_tls']),
                    'smtp_auth_user': section.get('smtp_auth_user', defaults['smtp_auth_user']),
                    'smtp_auth_pass': section.get('smtp_auth_pass', defaults['smtp_auth_pass']),
                    'log_level': section.get('log_level', defaults['log_level']),
                    'lock_file': section.get('lock_file', defaults['lock_file']),
                    'lock_timeout': section.getint('lock_timeout', defaults['lock_timeout']),
                    # Wazuh API Configuration
                    'wazuh_api_enabled': section.getboolean('wazuh_api_enabled', defaults['wazuh_api_enabled']),
                    'wazuh_api_host': section.get('wazuh_api_host', defaults['wazuh_api_host']),
                    'wazuh_api_port': section.getint('wazuh_api_port', defaults['wazuh_api_port']),
                    'wazuh_api_protocol': section.get('wazuh_api_protocol', defaults['wazuh_api_protocol']),
                    'wazuh_api_username': section.get('wazuh_api_username', defaults['wazuh_api_username']),
                    'wazuh_api_password': section.get('wazuh_api_password', defaults['wazuh_api_password']),
                    'wazuh_api_verify_ssl': section.getboolean('wazuh_api_verify_ssl', defaults['wazuh_api_verify_ssl']),
                    # API-based data collection (optional - for advanced features)
                    # Note: Alerts are ALWAYS read from alerts.json file (required)
                    'use_api_for_agent_health': section.getboolean('use_api_for_agent_health', defaults['use_api_for_agent_health']),
                    'use_api_for_rootcheck': section.getboolean('use_api_for_rootcheck', defaults['use_api_for_rootcheck']),
                    'use_api_for_manager_status': section.getboolean('use_api_for_manager_status', defaults['use_api_for_manager_status']),
                    'use_logs_for_trends': section.getboolean('use_logs_for_trends', defaults['use_logs_for_trends']),
                    # Report Period
                    'report_period': section.get('report_period', defaults['report_period']).lower(),
                })
            
            # Load performance settings if performance section exists
            if 'performance' in parser:
                perf_section = parser['performance']
                defaults.update({
                    'max_alerts_to_process': perf_section.getint('max_alerts_to_process', defaults['max_alerts_to_process']),
                    'sampling_enabled': perf_section.getboolean('sampling_enabled', defaults['sampling_enabled']),
                    'sampling_rate': perf_section.getfloat('sampling_rate', defaults['sampling_rate']),
                    'use_streaming_parser': perf_section.getboolean('use_streaming_parser', defaults['use_streaming_parser']),
                    'memory_limit_mb': perf_section.getint('memory_limit_mb', defaults['memory_limit_mb']),
                    'max_agents_to_collect': perf_section.getint('max_agents_to_collect', defaults['max_agents_to_collect']),
                    'api_max_workers': perf_section.getint('api_max_workers', defaults['api_max_workers']),
                    'api_timeout': perf_section.getint('api_timeout', defaults['api_timeout']),
                    'api_collection_timeout': perf_section.getint('api_collection_timeout', defaults['api_collection_timeout']),
                    'api_limit_per_agent': perf_section.getint('api_limit_per_agent', defaults['api_limit_per_agent']),
                    'attack_timeline_min_level': perf_section.getint('attack_timeline_min_level', defaults['attack_timeline_min_level']),
                    'attack_timeline_limit': perf_section.getint('attack_timeline_limit', defaults['attack_timeline_limit']),
                })
            else:
                # If performance section doesn't exist, use optimized defaults
                defaults.update({
                    'max_alerts_to_process': 1000000,  # 1 million
                    'sampling_enabled': True,  # Enabled
                    'sampling_rate': 0.1,  # 10%
                    'use_streaming_parser': True,
                    'memory_limit_mb': 0,
                    'max_agents_to_collect': 50,
                    'api_max_workers': 5,
                    'api_timeout': 30,
                    'api_collection_timeout': 120,
                    'api_limit_per_agent': 10,
                    'attack_timeline_min_level': 12,
                    'attack_timeline_limit': 500,
                })
        
        # Override with environment variables
        for key in defaults:
            env_key = f'LEBLEBI_{key.upper()}'
            if env_key in os.environ:
                value = os.environ[env_key]
                # Type conversion
                if isinstance(defaults[key], bool):
                    defaults[key] = value.lower() in ('true', '1', 'yes')
                elif isinstance(defaults[key], int):
                    defaults[key] = int(value)
                else:
                    defaults[key] = value
        
        self._config = defaults
    
    def _validate_email_format(self, email: str) -> bool:
        """Validate email address format using regex
        
        Args:
            email: Email address to validate
            
        Returns:
            True if email format is valid, False otherwise
        """
        if not email or not isinstance(email, str):
            return False
        
        # RFC 5322 compliant email regex (simplified)
        email_pattern = re.compile(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        )
        return bool(email_pattern.match(email.strip()))
    
    def _validate_port(self, port: int, port_name: str) -> List[str]:
        """Validate port number
        
        Args:
            port: Port number to validate
            port_name: Name of the port field for error messages
            
        Returns:
            List of error messages (empty if valid)
        """
        errors = []
        if not isinstance(port, int):
            errors.append(
                f"Invalid {port_name}: '{port}' must be an integer. "
                f"Please check your configuration file."
            )
        elif not (1 <= port <= 65535):
            errors.append(
                f"Invalid {port_name}: '{port}'. Port must be between 1 and 65535. "
                f"Please correct this value in config.conf or environment variable."
            )
        return errors
    
    def _validate_hostname_or_ip(self, host: str, field_name: str) -> List[str]:
        """Validate hostname or IP address format
        
        Args:
            host: Hostname or IP to validate
            field_name: Name of the field for error messages
            
        Returns:
            List of error messages (empty if valid)
        """
        errors = []
        if not host or not isinstance(host, str):
            errors.append(
                f"Invalid {field_name}: must be a non-empty string. "
                f"Please provide a valid hostname or IP address."
            )
            return errors
        
        host = host.strip()
        
        # Allow localhost
        if host == 'localhost':
            return errors
        
        # Validate IP address format (IPv4)
        ip_pattern = re.compile(
            r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        
        # Validate hostname format (RFC 1123)
        hostname_pattern = re.compile(
            r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
            r'[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        )
        
        if not (ip_pattern.match(host) or hostname_pattern.match(host)):
            errors.append(
                f"Invalid {field_name}: '{host}'. "
                f"Must be a valid IP address (e.g., 192.168.1.1) or hostname (e.g., example.com). "
                f"Please correct this value in config.conf."
            )
        
        return errors
    
    def _validate_config(self):
        """Validate configuration values with detailed error messages
        
        Raises:
            ConfigError: If validation fails with detailed error messages
        """
        errors = []
        
        # Validate report_period (format: 'Nd' where N is number of days, e.g., '1d', '2d', '7d')
        period = str(self._config.get('report_period', '1d')).lower().strip()
        if period.endswith('d'):
            try:
                days = int(period.rstrip('d'))
                if days < 1:
                    errors.append(
                        f"Invalid report_period: '{period}'. Number of days must be >= 1. "
                        f"Example: '1d' for today, '7d' for last 7 days. "
                        f"Please correct this in config.conf."
                    )
                elif days > 365:
                    errors.append(
                        f"Invalid report_period: '{period}'. Number of days exceeds maximum (365). "
                        f"For very large periods, consider using sampling. "
                        f"Please use a value between 1 and 365."
                    )
                else:
                    self._config['report_period'] = period
            except ValueError:
                errors.append(
                    f"Invalid report_period: '{period}'. Must be in format 'Nd' where N is number of days. "
                    f"Examples: '1d' (today), '7d' (last 7 days), '30d' (last 30 days). "
                    f"Please correct this in config.conf."
                )
        else:
            # Try to parse as integer (backward compatibility)
            try:
                days = int(period)
                if days < 1:
                    errors.append(
                        f"Invalid report_period: '{period}'. Number of days must be >= 1. "
                        f"Please use format 'Nd' (e.g., '1d', '7d') in config.conf."
                    )
                elif days > 365:
                    errors.append(
                        f"Invalid report_period: '{period}'. Number of days exceeds maximum (365). "
                        f"Please use a value between 1 and 365."
                    )
                else:
                    # Convert to 'Nd' format
                    self._config['report_period'] = f"{days}d"
            except ValueError:
                errors.append(
                    f"Invalid report_period: '{period}'. Must be in format 'Nd' where N is number of days. "
                    f"Examples: '1d', '7d', '30d'. Please correct this in config.conf."
                )
        
        # Validate required fields
        required_fields = {
            'level': (int, 'Alert severity threshold (0-15)'),
            'top_alerts_count': (int, 'Maximum number of top alerts to display'),
            'log_dir': (str, 'Directory where Wazuh alert logs are stored'),
            'output_dir': (str, 'Directory where generated reports will be saved'),
            'smtp_server': (str, 'SMTP server address for sending email reports'),
            'smtp_port': (int, 'SMTP server port number'),
            'mail_to': (str, 'Recipient email address(es) for reports'),
            'mail_from': (str, 'Sender email address for reports'),
        }
        
        for field, (field_type, description) in required_fields.items():
            value = self._config.get(field)
            if value is None:
                errors.append(
                    f"Required field '{field}' is missing. {description}. "
                    f"Please add this field to config.conf or set environment variable LEBLEBI_{field.upper()}."
                )
            elif not isinstance(value, field_type):
                errors.append(
                    f"Field '{field}' must be of type {field_type.__name__}, but got {type(value).__name__}. "
                    f"Please correct this in config.conf."
                )
        
        # Validate SMTP port
        smtp_port = self._config.get('smtp_port')
        if smtp_port is not None:
            errors.extend(self._validate_port(smtp_port, 'smtp_port'))
        
        # Validate email addresses with regex
        mail_to_raw = self._config.get('mail_to', '').strip()
        if not mail_to_raw:
            errors.append(
                "Invalid or missing 'mail_to' email address. "
                "Please set mail_to in config.conf with one or more email addresses "
                "(comma or semicolon separated). Example: mail_to = admin@example.com"
            )
        else:
            # Parse multiple email addresses (comma or semicolon separated)
            mail_to_list = [addr.strip() for addr in mail_to_raw.replace(';', ',').split(',') if addr.strip()]
            if not mail_to_list:
                errors.append(
                    "Invalid or missing 'mail_to' email address. "
                    "Please provide at least one valid email address in config.conf."
                )
            else:
                # Validate each email address
                for email in mail_to_list:
                    if not self._validate_email_format(email):
                        errors.append(
                            f"Invalid email address in 'mail_to': '{email}'. "
                            f"Email must be in format 'user@domain.com'. "
                            f"Please correct this in config.conf."
                        )
                # Store as list for easier processing
                self._config['mail_to'] = mail_to_list
        
        mail_from = self._config.get('mail_from', '').strip()
        if not mail_from:
            errors.append(
                "Invalid or missing 'mail_from' email address. "
                "Please set mail_from in config.conf with a valid email address. "
                f"Example: mail_from = sender@example.com"
            )
        elif not self._validate_email_format(mail_from):
            errors.append(
                f"Invalid email format for 'mail_from': '{mail_from}'. "
                f"Email must be in format 'user@domain.com'. "
                f"Please correct this in config.conf."
            )
        
        # Validate SMTP server (hostname or IP)
        smtp_server = self._config.get('smtp_server', '').strip()
        if smtp_server:
            errors.extend(self._validate_hostname_or_ip(smtp_server, 'smtp_server'))
        
        # Validate API settings if enabled
        if self._config.get('wazuh_api_enabled'):
            api_host = self._config.get('wazuh_api_host', '').strip()
            if not api_host:
                errors.append(
                    "wazuh_api_host is required when wazuh_api_enabled is true. "
                    "Please set wazuh_api_host in config.conf or set WAZUH_API_HOST environment variable."
                )
            else:
                errors.extend(self._validate_hostname_or_ip(api_host, 'wazuh_api_host'))
            
            api_port = self._config.get('wazuh_api_port')
            if api_port is not None:
                errors.extend(self._validate_port(api_port, 'wazuh_api_port'))
            
            if not self._config.get('wazuh_api_username'):
                errors.append(
                    "wazuh_api_username is required when wazuh_api_enabled is true. "
                    "Please set wazuh_api_username in config.conf or set WAZUH_API_USERNAME environment variable."
                )
            
            if not self._config.get('wazuh_api_password'):
                errors.append(
                    "wazuh_api_password is required when wazuh_api_enabled is true. "
                    "Please set wazuh_api_password in config.conf or set WAZUH_API_PASSWORD environment variable. "
                    "For security, consider using environment variables instead of config file."
                )
            
            protocol = self._config.get('wazuh_api_protocol', '').lower()
            if protocol not in ('http', 'https'):
                errors.append(
                    f"Invalid wazuh_api_protocol: '{protocol}'. Must be 'http' or 'https'. "
                    f"Please correct this in config.conf."
                )
        
        # Validate performance settings
        sampling_rate = self._config.get('sampling_rate', 1.0)
        if not isinstance(sampling_rate, (int, float)) or not (0.0 < sampling_rate <= 1.0):
            errors.append(
                f"Invalid sampling_rate: '{sampling_rate}'. Must be between 0.0 and 1.0. "
                f"Example: 0.1 for 10%, 0.5 for 50%. Please correct this in config.conf."
            )
        
        max_alerts = self._config.get('max_alerts_to_process', 0)
        if not isinstance(max_alerts, int) or max_alerts < 0:
            errors.append(
                f"Invalid max_alerts_to_process: '{max_alerts}'. Must be a non-negative integer. "
                f"Use 0 for unlimited. Please correct this in config.conf."
            )
        
        level = self._config.get('level', 12)
        if not isinstance(level, int) or not (0 <= level <= 15):
            errors.append(
                f"Invalid level: '{level}'. Must be between 0 and 15. "
                f"Recommended: 12 for standard monitoring. Please correct this in config.conf."
            )
        
        if errors:
            error_msg = (
                "Configuration validation failed. Please fix the following errors:\n\n" +
                "\n".join(f"  • {e}" for e in errors) +
                "\n\nFor help, see config.conf comments or README.md documentation."
            )
            raise ConfigError(error_msg)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return self._config.get(key, default)
    
    def __getitem__(self, key: str) -> Any:
        """Get configuration value using bracket notation"""
        return self._config[key]
    
    def __contains__(self, key: str) -> bool:
        """Check if configuration key exists"""
        return key in self._config

