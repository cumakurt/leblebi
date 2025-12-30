#!/usr/bin/env python3
"""Leblebi - Wazuh Security Reports Generator

Leblebi: A delicious and nutritious snack that provides energy and satisfaction.
This application provides comprehensive security intelligence and reporting for Wazuh.

Developer: Cuma KURT
GitHub: https://github.com/cumakurt/leblebi
LinkedIn: https://www.linkedin.com/in/cuma-kurt-34414917/
"""

# Standard library imports
import sys
import os
import argparse
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta

# Third-party imports
try:
    import ijson
    IJSON_AVAILABLE = True
except ImportError:
    IJSON_AVAILABLE = False

# Project root is automatically in path when run as module or script

# Local application imports
from leblebi.config import Config, ConfigError
from leblebi.logger import get_logger
from leblebi.alerts import AlertProcessor
from leblebi.reporting import HTMLReportGenerator
from leblebi.email import EmailSender
from leblebi.system_info import SystemInfo
from leblebi.utils import (
    LockFile, safe_mkdir, get_temp_file, check_memory_limit,
    should_enable_sampling, get_memory_usage_mb
)
from leblebi.wazuh_api import WazuhAPI
from leblebi.mitre_enrichment import MITREEnrichment
from leblebi.vulnerability_detection import VulnerabilityDetector
from leblebi.services import APIService, SystemInfoService, AlertProcessingService
from leblebi.factory import WazuhAPIFactory
from leblebi.exceptions import LeblebiError, APIError, ReportGenerationError

# Import CLI utilities
from leblebi.cli import Colors, print_summary_header, print_step, print_info, print_warning, print_error, print_success

# Import log utilities
from leblebi.log_utils import find_alerts_file, find_wazuh_log_files, get_time_range


def _collect_basic_system_info(config: Config, logger) -> Dict[str, Any]:
    """Collect basic system information without API
    
    Args:
        config: Configuration object
        logger: Logger instance
        
    Returns:
        Dictionary with basic system information
    """
    sys_info = SystemInfo()
    return {
        'wazuh_version': sys_info.get_wazuh_version(),
        'system_updates': sys_info.get_system_updates(),
        'memory_info': sys_info.get_memory_info(),
        'disk_usage': sys_info.get_disk_usage('/'),
        'swap_info': sys_info.get_swap_info(),
        'agent_count': sys_info.get_wazuh_agent_count(),
        'alerts_directory_size': None,  # Will be set later
        'api_enabled': False,
        'api_data': {},
        'report_period': config.get('report_period', 'daily')
    }


def _get_agents_list(api_client: WazuhAPI, logger) -> List[Dict[str, Any]]:
    """Get agents list from API with fallback strategies
    
    Args:
        api_client: WazuhAPI client instance
        logger: Logger instance
        
    Returns:
        List of agent dictionaries, empty list on error
    """
    import urllib.error
    
    try:
        # Try active agents first
        agents = api_client.get_agents(status='active', limit=1000)
        if not agents or len(agents) == 0:
            logger.debug("No active agents found, trying all agents")
            agents = api_client.get_agents(limit=1000)
        if not agents:
            agents = api_client.get_agents(limit=500)
        
        if agents:
            logger.info(f"Found {len(agents)} agents for data collection")
            # Log sample agent IDs and names for debugging
            sample_count = min(5, len(agents))
            sample_agents = [(str(a.get('id', 'N/A')), a.get('name', 'N/A')) 
                            for a in agents[:sample_count] if a.get('id')]
            logger.debug(f"Sample agents (ID, Name): {sample_agents}")
            # Log agent status distribution
            statuses = {}
            for a in agents:
                status = a.get('status', 'unknown')
                statuses[status] = statuses.get(status, 0) + 1
            logger.debug(f"Agent status distribution: {statuses}")
        else:
            logger.warning("Agent list is empty - cannot collect agent data")
        
        return agents or []
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        logger.warning(f"Failed to get agents list: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error getting agents: {e}", exc_info=True)
        return []


def _collect_agent_health_data(api_client: WazuhAPI, logger) -> Dict[str, Any]:
    """Collect agent health monitoring data
    
    Args:
        api_client: WazuhAPI client instance
        logger: Logger instance
        
    Returns:
        Dictionary with agent health data
    """
    import urllib.error
    from leblebi.agent_health import AgentHealthMonitor
    
    try:
        agent_monitor = AgentHealthMonitor(api_client)
        return {
            'agent_summary': agent_monitor.get_agent_summary(),
            'disconnected_agents': agent_monitor.get_disconnected_agents(hours_threshold=24),
            'critical_agents': agent_monitor.get_critical_agents(),
            'agents_by_version': agent_monitor.get_agents_by_version(),
            'agents_by_os': agent_monitor.get_agents_by_os(),
        }
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        logger.warning(f"Failed to collect agent health data: {e}")
        return {'agent_summary': {'enabled': False, 'error': str(e)}}
    except Exception as e:
        logger.error(f"Unexpected error collecting agent health: {e}", exc_info=True)
        return {'agent_summary': {'enabled': False, 'error': str(e)}}


def _collect_agent_data_parallel(api_collector, agents: List[Dict[str, Any]], config: Config, logger) -> Dict[str, List[Dict[str, Any]]]:
    """Collect agent data in parallel
    
    Args:
        api_collector: APICollector instance
        agents: List of agent dictionaries
        config: Configuration object
        logger: Logger instance
        
    Returns:
        Dictionary with collected agent data by type
    """
    data_types_to_collect = []
    if config.get('use_api_for_sca', True):
        data_types_to_collect.append('sca')
    if config.get('use_api_for_syscheck', True):
        data_types_to_collect.append('syscheck')
    if config.get('use_api_for_rootcheck', True):
        data_types_to_collect.append('rootcheck')
    if config.get('use_api_for_syscollector', True):
        data_types_to_collect.append('syscollector')
    
    if not data_types_to_collect:
        return {}
    
    try:
        max_agents_to_collect = config.get('max_agents_to_collect', 50)
        if max_agents_to_collect == 0:
            max_agents_to_collect = len(agents)
        else:
            max_agents_to_collect = min(max_agents_to_collect, len(agents))
        
        agents_to_collect = agents[:max_agents_to_collect]
        logger.info(f"Collecting agent data in parallel: {', '.join(data_types_to_collect)} from {len(agents_to_collect)} agents")
        
        parallel_results = api_collector.collect_agent_data_parallel(
            agents_to_collect,
            data_types_to_collect,
            limit_per_agent=10
        )
        
        # Process and log results
        result_data = {}
        for data_type in data_types_to_collect:
            if data_type in parallel_results:
                result_data[data_type] = parallel_results[data_type]
                logger.info(f"Collected {data_type.upper()} data from {len(parallel_results[data_type])} agents")
            else:
                result_data[data_type] = []
        
        return result_data
    except Exception as e:
        logger.error(f"Error in parallel data collection: {e}", exc_info=True)
        return {dt: [] for dt in data_types_to_collect}


def _collect_manager_data_parallel(api_collector, config: Config, report_period: str, logger) -> Dict[str, Any]:
    """Collect manager-level data in parallel
    
    Args:
        api_collector: APICollector instance
        config: Configuration object
        report_period: Report period string
        logger: Logger instance
        
    Returns:
        Dictionary with manager data
    """
    manager_data_types = []
    if config.get('use_api_for_manager_status', True):
        manager_data_types.append('status')
        manager_data_types.append('stats')
    if config.get('use_api_for_ciscat', True):
        manager_data_types.append('ciscat')
    
    if not manager_data_types:
        return {}
    
    try:
        manager_results = api_collector.collect_manager_data_parallel(manager_data_types)
        
        result_data = {}
        if 'status' in manager_results:
            result_data['manager_status'] = manager_results['status']
        
        if 'stats' in manager_results:
            stats_component = {
                'daily': 'hourly',
                'weekly': 'weekly',
                'monthly': 'monthly',
                'all': 'hourly'
            }.get(report_period, 'hourly')
            result_data['manager_stats'] = manager_results['stats']
        
        if 'ciscat' in manager_results:
            result_data['ciscat'] = manager_results['ciscat']
            ciscat_count = len(manager_results['ciscat']) if isinstance(manager_results['ciscat'], list) else 0
            logger.info(f"Collected CIS-CAT data for {ciscat_count} agents")
        
        return result_data
    except Exception as e:
        logger.warning(f"Error collecting manager data: {e}")
        return {'ciscat': []} if 'ciscat' in manager_data_types else {}


def _collect_api_data_fallback(config: Config, report_period: str, logger) -> Dict[str, Any]:
    """Collect API data using fallback method (when api_service is None)
    
    Args:
        config: Configuration object
        report_period: Report period string
        logger: Logger instance
        
    Returns:
        Dictionary with API data or error information
    """
    import urllib.error
    import json
    from leblebi.wazuh_api import WazuhAPI
    from leblebi.api_collector import APICollector
    
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
            return {
                'api_enabled': False,
                'api_error': "Connection test failed"
            }
        
        api_data = {
            'api_enabled': True,
            'agent_summary': {},
            'manager_status': None
        }
        
        # Collect agent health data
        agent_health = _collect_agent_health_data(api_client, logger)
        api_data.update(agent_health)
        
        # Collect manager status
        try:
            manager_status = api_client.get_manager_status()
            if manager_status:
                api_data['manager_status'] = manager_status
        except (urllib.error.HTTPError, urllib.error.URLError) as e:
            logger.warning(f"Failed to get manager status: {e}")
        except Exception as e:
            logger.debug(f"Manager status collection error: {e}")
        
        # Use parallel API collector for agent data
        api_collector = APICollector(api_client, logger=logger, max_workers=5)
        
        # Get agents list
        agents = _get_agents_list(api_client, logger)
        
        if agents:
            # Collect agent data in parallel
            agent_data = _collect_agent_data_parallel(api_collector, agents, config, logger)
            api_data.update(agent_data)
        
        # Collect manager-level data
        manager_data = _collect_manager_data_parallel(api_collector, config, report_period, logger)
        api_data.update(manager_data)
        
        return api_data
        
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        logger.error(f"Network error during API connection test: {e}")
        return {
            'api_enabled': False,
            'api_error': f"Network error: {str(e)}"
        }
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON response during API connection test: {e}")
        return {
            'api_enabled': False,
            'api_error': f"Invalid API response: {str(e)}"
        }
    except ImportError as e:
        logger.error(f"Failed to import API modules: {e}")
        return {
            'api_enabled': False,
            'api_error': f"Import error: {str(e)}"
        }
    except Exception as e:
        logger.error(f"Unexpected error during API setup: {e}", exc_info=True)
        return {
            'api_enabled': False,
            'api_error': str(e)
        }


def collect_system_info(
    config: Config,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    report_period: str = 'daily',
    logger = None,
    api_service: Optional[APIService] = None
) -> Dict[str, Any]:
    """Collect system information from both system and Wazuh API
    
    Args:
        config: Configuration object
        start_time: Start time for filtering (optional)
        end_time: End time for filtering (optional)
        report_period: Report period string
        logger: Logger instance (optional, will be created if not provided)
        api_service: Optional API service instance
        
    Returns:
        Dictionary with system information
    """
    from typing import Optional, Dict, Any
    from datetime import datetime
    
    # Get logger if not provided
    if logger is None:
        logger = get_logger()
    
    # Use service layer if available (preferred method)
    if api_service:
        system_info_service = SystemInfoService(config, api_service, logger)
        return system_info_service.collect_all(start_time, end_time, report_period)
    
    # Fallback to old method for backward compatibility
    system_data = _collect_basic_system_info(config, logger)
    system_data['report_period'] = report_period
    
    # Collect API data if enabled and available
    if config.get('wazuh_api_enabled'):
        api_data = _collect_api_data_fallback(config, report_period, logger)
        system_data['api_enabled'] = api_data.get('api_enabled', False)
        system_data['api_data'] = {k: v for k, v in api_data.items() if k != 'api_enabled'}
        if 'api_error' in api_data:
            system_data['api_error'] = api_data['api_error']
    
    return system_data




def test_api_connection(config):
    """Test Wazuh API connection and display detailed information"""
    from leblebi.logger import get_logger
    logger = get_logger()
    
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}  WAZUH API CONNECTION TEST{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}\n")
    
    # Check if API is enabled in config
    api_enabled = config.get('wazuh_api_enabled', False)
    
    if not api_enabled:
        print_warning("Wazuh API is disabled in configuration")
        print_info("To enable API, set 'wazuh_api_enabled = true' in config.conf")
        print(f"\n{Colors.WARNING}Current API Configuration:{Colors.ENDC}")
        print(f"  wazuh_api_enabled: {api_enabled}")
        print(f"  wazuh_api_host: {config.get('wazuh_api_host', 'N/A')}")
        print(f"  wazuh_api_port: {config.get('wazuh_api_port', 'N/A')}")
        print(f"  wazuh_api_protocol: {config.get('wazuh_api_protocol', 'N/A')}")
        print(f"\n{Colors.FAIL}✗ API test skipped - API is disabled{Colors.ENDC}\n")
        return False
    
    # Display configuration
    print(f"{Colors.BOLD}API Configuration:{Colors.ENDC}")
    print_info("Host", config.get('wazuh_api_host', 'N/A'))
    print_info("Port", str(config.get('wazuh_api_port', 'N/A')))
    print_info("Protocol", config.get('wazuh_api_protocol', 'N/A'))
    print_info("Username", config.get('wazuh_api_username', 'N/A'))
    print_info("SSL Verification", "Enabled" if config.get('wazuh_api_verify_ssl', False) else "Disabled")
    print()
    
    # Create API client
    print(f"{Colors.BOLD}Testing API Connection...{Colors.ENDC}\n")
    
    try:
        api_client = WazuhAPI(
            host=config.get('wazuh_api_host', 'localhost'),
            port=config.get('wazuh_api_port', 55000),
            protocol=config.get('wazuh_api_protocol', 'https'),
            username=config.get('wazuh_api_username', 'wazuh'),
            password=config.get('wazuh_api_password', 'wazuh'),
            verify_ssl=config.get('wazuh_api_verify_ssl', False)
        )
        
        # Test authentication
        print_step(1, 4, "Testing authentication")
        if api_client.test_connection():
            print_info("Authentication", "SUCCESS")
            print_info("Token", "Obtained successfully")
        else:
            print_error("Authentication FAILED")
            print(f"\n{Colors.FAIL}Possible issues:{Colors.ENDC}")
            print("  - Incorrect username or password")
            print("  - API user does not have proper permissions")
            print("  - Wazuh API service is not running")
            print(f"\n{Colors.FAIL}✗ API connection test FAILED{Colors.ENDC}\n")
            return False
        
        # Test manager status
        print_step(2, 4, "Testing manager status endpoint")
        manager_status = api_client.get_manager_status()
        if manager_status:
            print_info("Manager Status", "SUCCESS")
            status = manager_status.get('status', 'Unknown')
            version = manager_status.get('version', 'Unknown')
            print_info("Status", status)
            print_info("Version", version)
        else:
            print_warning("Manager status endpoint returned no data")
        
        # Test agents endpoint
        print_step(3, 4, "Testing agents endpoint")
        agents = api_client.get_agents(limit=10)
        if agents is not None:
            print_info("Agents Endpoint", "SUCCESS")
            print_info("Agents Found", f"{len(agents)} (showing first 10)")
            if agents:
                print(f"\n{Colors.BOLD}Sample Agents:{Colors.ENDC}")
                for agent in agents[:3]:
                    agent_id = agent.get('id', 'N/A')
                    agent_name = agent.get('name', 'N/A')
                    agent_status = agent.get('status', 'N/A')
                    print(f"  - {agent_name} (ID: {agent_id}, Status: {agent_status})")
        else:
            print_warning("Agents endpoint returned no data")
        
        # Test additional endpoints
        print_step(4, 4, "Testing additional endpoints")
        endpoints_tested = []
        
        # Test rules endpoint
        try:
            rules = api_client.get_rules(limit=1)
            if rules is not None:
                endpoints_tested.append("Rules")
        except (Exception, AttributeError, KeyError) as e:
            # Endpoint may not be available or may return unexpected format
            logger.debug(f"Rules endpoint test failed: {e}")
        
        if endpoints_tested:
            print_info("Additional Endpoints", ", ".join(endpoints_tested))
        else:
            print_warning("Some endpoints may not be available")
        
        # Final summary
        print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}{Colors.BOLD}  ✓ API CONNECTION TEST SUCCESSFUL{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}\n")
        
        print(f"{Colors.BOLD}Summary:{Colors.ENDC}")
        print_info("API Connection", "Working")
        print_info("Authentication", "Successful")
        print_info("Endpoints", "Accessible")
        print(f"\n{Colors.OKGREEN}You can now use API features in Leblebi reports!{Colors.ENDC}\n")
        
        return True
        
    except Exception as e:
        print_error(f"API connection test FAILED: {str(e)}")
        print(f"\n{Colors.FAIL}Detailed Error Information:{Colors.ENDC}")
        print(f"  Error Type: {type(e).__name__}")
        print(f"  Error Message: {str(e)}")
        
        print(f"\n{Colors.WARNING}Possible Issues:{Colors.ENDC}")
        print("  1. Network connectivity:")
        print(f"     - Check if {config.get('wazuh_api_host')} is reachable")
        print(f"     - Verify port {config.get('wazuh_api_port')} is open")
        print("  2. Wazuh API service:")
        print("     - Check if Wazuh API is running: systemctl status wazuh-api")
        print("     - Check API logs: /var/ossec/logs/api.log")
        print("  3. Configuration:")
        print("     - Verify API host, port, and protocol in config.conf")
        print("     - Check username and password are correct")
        print("  4. SSL/TLS:")
        if config.get('wazuh_api_protocol') == 'https':
            print("     - If using self-signed certificate, set wazuh_api_verify_ssl = false")
            print("     - Or ensure certificate is properly configured")
        print("  5. Firewall:")
        print(f"     - Ensure port {config.get('wazuh_api_port')} is not blocked")
        
        print(f"\n{Colors.FAIL}✗ API connection test FAILED{Colors.ENDC}\n")
        return False


def test_configuration(config) -> bool:
    """Test configuration, log file, API connection, and email sending
    
    Args:
        config: Configuration object
        
    Returns:
        True if all tests pass, False otherwise
    """
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}  LEBLEBI CONFIGURATION TEST{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}\n")
    
    all_tests_passed = True
    test_count = 0
    passed_count = 0
    
    # Test 1: Configuration file
    test_count += 1
    print_step(test_count, 4, "Testing configuration file")
    try:
        config_file = config.config_file if hasattr(config, 'config_file') else None
        if config_file and os.path.exists(config_file):
            print_info("Config file found", config_file)
            # Try to validate config
            try:
                # Check if required fields exist
                required_fields = ['mail_to', 'mail_from', 'smtp_server']
                missing_fields = []
                for field in required_fields:
                    value = config.get(field, '')
                    if not value or (isinstance(value, str) and value.strip() == ''):
                        missing_fields.append(field)
                
                if missing_fields:
                    print_warning(f"Missing or empty required fields: {', '.join(missing_fields)}")
                    all_tests_passed = False
                else:
                    print_info("Configuration validation", "PASSED")
                    passed_count += 1
            except Exception as e:
                print_error(f"Configuration validation failed: {e}")
                all_tests_passed = False
        else:
            print_error("Configuration file not found")
            all_tests_passed = False
    except Exception as e:
        print_error(f"Configuration test failed: {e}")
        all_tests_passed = False
    
    # Test 2: Log file (alerts.json)
    test_count += 1
    print_step(test_count, 4, "Testing alerts.json file")
    try:
        log_dir = config.get('log_dir', '/var/ossec/logs/alerts')
        alerts_file = os.path.join(log_dir, 'alerts.json')
        
        # Also check standard location
        standard_locations = [
            '/var/ossec/logs/alerts/alerts.json',
            alerts_file,
            './alerts.json'
        ]
        
        found_file = None
        for location in standard_locations:
            if os.path.exists(location):
                found_file = location
                break
        
        if found_file:
            file_size = os.path.getsize(found_file)
            file_size_mb = file_size / (1024 * 1024)
            print_info("Alerts file found", found_file)
            print_info("File size", f"{file_size_mb:.2f} MB ({file_size:,} bytes)")
            
            # Check if file is readable
            try:
                with open(found_file, 'r') as f:
                    f.read(1)  # Try to read first byte
                print_info("File readability", "PASSED")
                passed_count += 1
            except PermissionError:
                print_error("Permission denied: Cannot read alerts.json file")
                all_tests_passed = False
            except Exception as e:
                print_error(f"Cannot read alerts.json file: {e}")
                all_tests_passed = False
        else:
            print_error("alerts.json file not found")
            print_warning("Searched locations:")
            for loc in standard_locations:
                print_warning(f"  - {loc}")
            all_tests_passed = False
    except Exception as e:
        print_error(f"Log file test failed: {e}")
        all_tests_passed = False
    
    # Test 3: API connection
    test_count += 1
    print_step(test_count, 4, "Testing Wazuh API connection")
    try:
        api_enabled = config.get('wazuh_api_enabled', False)
        if api_enabled:
            from leblebi.wazuh_api import WazuhAPI
            
            api_client = WazuhAPI(
                host=config.get('wazuh_api_host', 'localhost'),
                port=config.get('wazuh_api_port', 55000),
                protocol=config.get('wazuh_api_protocol', 'https'),
                username=config.get('wazuh_api_username', 'wazuh'),
                password=config.get('wazuh_api_password', 'wazuh'),
                verify_ssl=config.get('wazuh_api_verify_ssl', False)
            )
            
            if api_client.test_connection():
                print_info("API connection", "SUCCESS")
                print_info("API host", f"{config.get('wazuh_api_host')}:{config.get('wazuh_api_port')}")
                passed_count += 1
            else:
                print_error("API connection failed")
                print_warning("Check API credentials and network connectivity")
                all_tests_passed = False
        else:
            print_warning("Wazuh API is disabled in configuration")
            print_info("API test", "SKIPPED (API disabled)")
            passed_count += 1  # Count as passed since it's intentionally disabled
    except ImportError as e:
        print_error(f"Failed to import API module: {e}")
        all_tests_passed = False
    except Exception as e:
        print_error(f"API connection test failed: {e}")
        all_tests_passed = False
    
    # Test 4: Email sending
    test_count += 1
    print_step(test_count, 4, "Testing email sending")
    try:
        mail_to_raw = config.get('mail_to', '')
        # Handle both list and string formats
        if isinstance(mail_to_raw, list):
            mail_to_list = mail_to_raw
        else:
            mail_to_list = [addr.strip() for addr in str(mail_to_raw).replace(';', ',').split(',') if addr.strip()]
        
        mail_from = config.get('mail_from', '').strip()
        smtp_server = config.get('smtp_server', '').strip()
        
        if not mail_to_list or not any('@' in email for email in mail_to_list):
            print_error("Invalid or missing 'mail_to' email address")
            all_tests_passed = False
        elif not mail_from or '@' not in mail_from:
            print_error("Invalid or missing 'mail_from' email address")
            all_tests_passed = False
        elif not smtp_server:
            print_error("SMTP server not configured")
            all_tests_passed = False
        else:
            print_info("Email configuration", "Valid")
            print_info("SMTP server", f"{smtp_server}:{config.get('smtp_port', 25)}")
            if len(mail_to_list) == 1:
                print_info("Recipient", mail_to_list[0])
            else:
                print_info("Recipients", f"{len(mail_to_list)} addresses")
                for idx, email in enumerate(mail_to_list, 1):
                    print_info(f"  Recipient {idx}", email)
            print_info("Sender", mail_from)
            
            # Try to send test email
            try:
                from leblebi.email import EmailSender
                import tempfile
                
                # Create a simple test HTML content
                test_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Leblebi Configuration Test</title>
</head>
<body>
    <h2>Leblebi Configuration Test Email</h2>
    <p>This is a test email sent from Leblebi to verify email configuration.</p>
    <p><strong>Test Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p>If you received this email, your email configuration is working correctly.</p>
    <hr>
    <p style="color: #666; font-size: 12px;">Leblebi - Wazuh Security Reports Generator</p>
</body>
</html>"""
                
                # Create temporary HTML file
                with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
                    f.write(test_html)
                    temp_html_file = f.name
                
                email_config = {
                    'smtp_server': smtp_server,
                    'smtp_port': config.get('smtp_port', 25),
                    'smtp_use_tls': config.get('smtp_use_tls', False),
                    'smtp_auth_user': config.get('smtp_auth_user', ''),
                    'smtp_auth_pass': config.get('smtp_auth_pass', ''),
                    'mail_from': mail_from,
                    'mail_to': mail_to_list,  # Pass as list
                    'mail_subject_prefix': 'Leblebi Configuration Test',
                    'mail_format': 'html_attachment',
                }
                
                sender = EmailSender(email_config)
                sender.send_report(temp_html_file)
                
                # Cleanup
                try:
                    os.remove(temp_html_file)
                except Exception:
                    pass
                
                print_info("Test email", "SENT SUCCESSFULLY")
                if len(mail_to_list) == 1:
                    print_info("Please check", f"inbox of {mail_to_list[0]}")
                else:
                    print_info("Please check", f"inboxes of {len(mail_to_list)} recipients")
                passed_count += 1
            except Exception as e:
                print_error(f"Failed to send test email: {e}")
                print_warning("Check SMTP server settings and network connectivity")
                all_tests_passed = False
    except Exception as e:
        print_error(f"Email test failed: {e}")
        all_tests_passed = False
    
    # Print summary
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}")
    print(f"{Colors.BOLD}TEST SUMMARY{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}\n")
    
    print_info("Tests completed", f"{passed_count}/{test_count}")
    
    if all_tests_passed:
        print(f"\n{Colors.OKGREEN}{Colors.BOLD}  ✓ All configuration tests PASSED{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Leblebi is ready to generate security reports!{Colors.ENDC}\n")
        return True
    else:
        print(f"\n{Colors.FAIL}{Colors.BOLD}  ✗ Some configuration tests FAILED{Colors.ENDC}")
        print(f"{Colors.WARNING}Please fix the issues above before running Leblebi.{Colors.ENDC}\n")
        return False


def print_final_summary(processor, system_info: dict, report_file: str, email_sent: bool, temp_files: List[str]):
    """Print final summary"""
    risk_score, counts = processor.calculate_risk_score()
    
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}  EXECUTION SUMMARY{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}\n")
    
    print(f"{Colors.BOLD}Report Statistics:{Colors.ENDC}")
    print_info("Total Alerts Processed", f"{len(processor.alerts):,}")
    print_info("Critical Alerts", f"{counts['critical']}")
    print_info("High Alerts", f"{counts['high']}")
    print_info("Medium Alerts", f"{counts['medium']}")
    print_info("Low Alerts", f"{counts['low']}")
    
    # Risk score color coding
    if risk_score > 150:
        risk_color = Colors.FAIL
        risk_level = "CRITICAL"
    elif risk_score > 80:
        risk_color = Colors.WARNING
        risk_level = "HIGH"
    elif risk_score > 40:
        risk_color = Colors.OKCYAN
        risk_level = "MEDIUM"
    else:
        risk_color = Colors.OKGREEN
        risk_level = "LOW"
    
    print(f"\n{Colors.BOLD}Security Risk Assessment:{Colors.ENDC}")
    print(f"  {risk_color}Risk Score: {risk_score} ({risk_level}){Colors.ENDC}")
    
    print(f"\n{Colors.BOLD}System Information:{Colors.ENDC}")
    print_info("Wazuh Version", system_info.get('wazuh_version', 'Unknown'))
    print_info("System Updates Available", str(system_info.get('system_updates', 0)))
    print_info("Active Agents", str(system_info.get('agent_count', 0)))
    
    print(f"\n{Colors.BOLD}Report Output:{Colors.ENDC}")
    if os.path.exists(report_file):
        report_size = os.path.getsize(report_file)
        print_info("Report File", report_file)
        print_info("Report Size", f"{report_size:,} bytes ({report_size / 1024:.2f} KB)")
    else:
        print_warning(f"Report file not found: {report_file}")
    
    if email_sent:
        print_info("Email Status", "Sent successfully")
    else:
        print_warning("Email Status: Not sent (dry-run, test mode, or not configured)")
    
    if temp_files:
        print(f"\n{Colors.BOLD}Cleanup:{Colors.ENDC}")
        cleaned = 0
        for temp_file in temp_files:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                    cleaned += 1
            except Exception:
                pass
        if cleaned > 0:
            print_info(f"Cleaned up {cleaned} temporary file(s)")
    
    print_success("Leblebi execution completed successfully!")


def _parse_arguments() -> argparse.Namespace:
    """Parse command line arguments
    
    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description='Leblebi - Wazuh Security Reports Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
  %(prog)s -c /etc/leblebi/config.conf
  %(prog)s --log-level DEBUG --dry-run
  %(prog)s --alerts-file /path/to/alerts.json
  %(prog)s --apitest
  %(prog)s --config-test

Leblebi - Wazuh Security Reports Generator
        """
    )
    
    parser.add_argument(
        '-c', '--config',
        help='Path to configuration file',
        default=None
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging (DEBUG level)'
    )
    
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Enable quiet mode (ERROR level only)'
    )
    
    parser.add_argument(
        '-d', '--dry-run',
        action='store_true',
        help='Generate report but do not send email'
    )
    
    parser.add_argument(
        '--test',
        action='store_true',
        help='Test mode: Generate report in current directory without sending email'
    )
    
    parser.add_argument(
        '--log-file',
        help='Path to log file',
        default=None
    )
    
    parser.add_argument(
        '--alerts-file',
        help='Path to alerts.json file (overrides config)',
        default=None
    )
    
    parser.add_argument(
        '--apitest',
        action='store_true',
        help='Test Wazuh API connection and display detailed information'
    )
    
    parser.add_argument(
        '--config-test',
        action='store_true',
        help='Test configuration, log file, API connection, and email sending'
    )
    
    return parser.parse_args()


def _load_configuration(args: argparse.Namespace) -> Config:
    """Load and validate configuration
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        Config object
        
    Raises:
        SystemExit: If configuration cannot be loaded
    """
    try:
        return Config(args.config, require_config=True)
    except ConfigError as e:
        print_error(f"Configuration Error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Failed to load configuration: {str(e)}")
        sys.exit(1)


def _setup_logging(args: argparse.Namespace, config: Config):
    """Setup logging based on arguments and config
    
    Args:
        args: Parsed command line arguments
        config: Configuration object
        
    Returns:
        Logger instance
    """
    if args.verbose:
        log_level = 'DEBUG'
    elif args.quiet:
        log_level = 'ERROR'
    else:
        log_level = config.get('log_level', 'INFO')
    
    return get_logger(log_level, args.log_file)


def main() -> None:
    """Main entry point for Leblebi application"""
    args = _parse_arguments()
    
    # Load configuration (required)
    config = _load_configuration(args)
    
    # Handle API test mode
    if args.apitest:
        test_api_connection(config)
        sys.exit(0)
    
    # Handle configuration test mode
    if args.config_test:
        test_result = test_configuration(config)
        sys.exit(0 if test_result else 1)
    
    # Setup logging
    logger = _setup_logging(args, config)
    logger.info("=" * 60)
    logger.info("Leblebi - Wazuh Security Reports Generator")
    logger.info("Starting Wazuh Security Reports Generator...")
    logger.info("=" * 60)
    
    # Print summary header
    print_summary_header()
    
    # Track temporary files for cleanup
    temp_files: List[str] = []
    email_sent = False
    final_report = None
    
    # Lock file to prevent multiple instances
    lock_file = config.get('lock_file')
    try:
        with LockFile(lock_file) as lock:
            if lock.lock_acquired:
                logger.info(f"Lock acquired: {lock_file}")
                print_step(1, 6, "Acquiring lock and initializing")
                print_info("Lock acquired", lock_file)
            else:
                logger.warning(f"Could not create lock file ({lock_file}), continuing without lock")
                print_step(1, 6, "Initializing (lock skipped)")
                print_warning("Lock file not available, continuing without lock")
            
            # Initialize services (API service will handle API configuration)
            api_service = APIService(config, logger)
            alert_service = AlertProcessingService(config, api_service, logger)
            
            # Note: Alerts are ALWAYS read from alerts.json file (required)
            # API is only used for additional data: agent health, rootcheck, etc.
            
            # Get time range for report period
            report_period = config.get('report_period', '1d')
            start_time, end_time, period_days = get_time_range(report_period)
            
            # Format period label
            if period_days == 1:
                period_label = 'Today'
            else:
                period_label = f'Last {period_days} days'
            
            logger.info(f"Report period: {report_period} ({period_label}, {period_days} day(s))")
            if start_time and end_time:
                logger.info(f"Time range: {start_time.strftime('%Y-%m-%d %H:%M:%S')} to {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Initialize services
            api_service = APIService(config, logger)
            alert_service = AlertProcessingService(config, api_service, logger)
            
            # Initialize alert processor with config
            processor = AlertProcessor(level=config.get('level', 12), config=config)
            
            # Load alerts from Wazuh log files (supports multiple days)
            print_step(2, 6, "Locating alert log files")
            log_dir = config.get('log_dir', '/var/ossec/logs/alerts')
            
            # Find log files for the specified period
            if args.alerts_file:
                # If specific file provided, use it
                log_files = [args.alerts_file]
                missing_dates = []
                logger.info(f"Using specified alerts file: {args.alerts_file}")
                print_info("Alerts file", args.alerts_file)
            else:
                # Find log files based on Wazuh log structure
                log_files, missing_dates = find_wazuh_log_files(log_dir, period_days)
                
                if not log_files:
                    logger.error("No alert log files found")
                    logger.error(f"Searched for {period_days} day(s) in: {log_dir}")
                    error_msg = (
                        f"Error: No alert log files found for {period_label}!\n\n"
                        f"Wazuh log structure:\n"
                        f"  - Today: {log_dir}/alerts.json\n"
                        f"  - Previous days: {log_dir}/YYYY/MMM/ossec-alerts-DD.json.gz\n\n"
                        f"Please ensure:\n"
                        f"  1. Log directory exists: {log_dir}\n"
                        f"  2. Today's alerts.json file exists\n"
                        f"  3. Previous days' compressed files exist (if period > 1 day)\n"
                    )
                    logger.error(error_msg)
                    print_error("No alert log files found")
                    print(f"\n{Colors.FAIL}{error_msg}{Colors.ENDC}\n")
                    sys.exit(1)
                
                logger.info(f"Found {len(log_files)} log file(s) for {period_days} day(s)")
                print_info("Log files found", f"{len(log_files)} file(s)")
                for idx, log_file in enumerate(log_files, 1):
                    file_name = os.path.basename(log_file)
                    logger.info(f"  [{idx}] {log_file}")
                    print_info(f"  File {idx}", file_name)
                
                # Warn about missing log files
                if missing_dates:
                    missing_count = len(missing_dates)
                    logger.warning(f"Warning: {missing_count} log file(s) not found for requested period")
                    logger.warning(f"Missing dates: {', '.join(missing_dates)}")
                    logger.warning(f"Processing {len(log_files)} available log file(s) instead of {period_days} requested")
                    print_warning(f"{missing_count} log file(s) not found")
                    print_warning(f"Missing dates: {', '.join(missing_dates)}")
                    print_warning(f"Processing available {len(log_files)} file(s) instead of {period_days} requested")
            
            # Load alerts with time filtering and performance optimizations
            print_step(3, 6, "Loading and processing alerts from files")
            logger.info(f"Loading alerts from {len(log_files)} file(s)...")
            
            # Check total file size and warn if very large
            from leblebi.constants import Performance
            total_size = 0
            large_files = []
            for log_file in log_files:
                if os.path.exists(log_file):
                    file_size = os.path.getsize(log_file)
                    total_size += file_size
                    # Check if file is large (uncompressed or compressed)
                    size_mb = file_size / (1024 * 1024)
                    if (log_file.endswith('.gz') and size_mb > Performance.LARGE_COMPRESSED_FILE_SIZE_MB) or \
                       (not log_file.endswith('.gz') and size_mb > Performance.LARGE_FILE_SIZE_MB):
                        large_files.append((os.path.basename(log_file), size_mb))
            
            total_size_gb = total_size / (1024 * 1024 * 1024)
            if total_size_gb > Performance.LARGE_FILE_THRESHOLD_GB:
                logger.warning(f"Large log files detected: Total size {total_size_gb:.2f} GB")
                print_warning(f"Large log files: {total_size_gb:.2f} GB total")
                if large_files:
                    for filename, size_mb in large_files:
                        logger.warning(f"  - {filename}: {size_mb:.1f} MB")
                        print_warning(f"  - {filename}: {size_mb:.1f} MB")
                
                # Suggest performance optimizations
                if not config.get('max_alerts_to_process', 0):
                    suggested_limit = Performance.SUGGESTED_ALERT_LIMIT
                    logger.warning(f"Consider setting max_alerts_to_process = {suggested_limit} in config to prevent memory issues")
                    print_warning(f"Recommendation: Set max_alerts_to_process = {suggested_limit} in config.conf")
                if not config.get('sampling_enabled', False) and total_size_gb > Performance.VERY_LARGE_FILE_THRESHOLD_GB:
                    logger.warning("Consider enabling sampling_enabled = true for files > 2GB")
                    print_warning("Recommendation: Enable sampling_enabled = true in config.conf for very large files")
            
            # Get performance settings from config
            max_alerts = config.get('max_alerts_to_process', 0)
            if max_alerts == 0:
                max_alerts = None  # 0 means unlimited
            
            sampling_enabled = config.get('sampling_enabled', False)
            sampling_rate = float(config.get('sampling_rate', 1.0)) if sampling_enabled else 1.0
            use_streaming = config.get('use_streaming_parser', True)
            memory_limit_mb = config.get('memory_limit_mb', 0)
            
            # Check memory usage and auto-enable sampling if needed
            if memory_limit_mb > 0:
                current_memory = get_memory_usage_mb()
                logger.debug(f"Current memory usage: {current_memory:.1f} MB (limit: {memory_limit_mb} MB)")
                
                if should_enable_sampling(memory_limit_mb, sampling_enabled, total_size_gb):
                    if not sampling_enabled:
                        sampling_enabled = True
                        sampling_rate = Performance.AUTO_SAMPLING_RATE
                        logger.warning(f"Memory limit exceeded ({current_memory:.1f} MB > {memory_limit_mb} MB) - auto-enabling sampling at {Performance.AUTO_SAMPLING_RATE*100:.0f}%")
                        print_warning(f"Memory limit exceeded - auto-enabling sampling")
            
            # Force streaming for large files if ijson is available
            if not use_streaming and IJSON_AVAILABLE and total_size_gb > 0.5:
                logger.warning("Large files detected - forcing streaming parser (ijson)")
                use_streaming = True
                print_warning("Forcing streaming parser for large files")
            
            if not IJSON_AVAILABLE and total_size_gb > 0.5:
                logger.warning("Large files detected but ijson not available - install with: pip install ijson")
                print_warning("Install ijson for better memory efficiency: pip install ijson")
            
            if sampling_enabled and sampling_rate < 1.0:
                logger.info(f"Sampling enabled: processing {sampling_rate*100:.1f}% of alerts")
                print_info("Sampling mode", f"{sampling_rate*100:.1f}% of alerts")
            
            if max_alerts:
                logger.info(f"Maximum alerts limit: {max_alerts:,}")
                print_info("Alert limit", f"{max_alerts:,}")
            
            # Load alerts from multiple files
            if len(log_files) == 1:
                # Single file - use original method
                total_alerts = processor.load_alerts(
                    log_files[0],
                    start_time=start_time,
                    end_time=end_time,
                    max_alerts=max_alerts,
                    sample_rate=sampling_rate,
                    use_streaming=use_streaming
                )
            else:
                # Multiple files - use new method
                total_alerts = processor.load_alerts_from_multiple_files(
                    log_files,
                    start_time=start_time,
                    end_time=end_time,
                    max_alerts=max_alerts,
                    sample_rate=sampling_rate,
                    use_streaming=use_streaming
                )
            
            logger.info(f"Loaded {total_alerts} alerts from {len(log_files)} file(s) (period: {report_period})")
            print_info("Alerts loaded", f"{total_alerts:,} from {len(log_files)} file(s) ({period_label})")
            
            # Note: API is NOT used for alerts (Wazuh API does not provide alerts endpoint)
            # API is only used for additional data: agent health, rootcheck, etc.
            
            # Final check: Must have at least some alerts
            if len(processor.alerts) == 0:
                # Check if log files are actually empty or just filtered out
                total_file_size = sum(os.path.getsize(f) for f in log_files if os.path.exists(f))
                
                if total_file_size == 0:
                    error_msg = (
                        "No alerts found - log files are empty!\n\n"
                        "The log files exist but contain no data.\n\n"
                        f"Configuration:\n"
                        f"  - report_period: {report_period} ({period_label}, {period_days} day(s))\n"
                        f"  - log_files: {len(log_files)} file(s)\n"
                        f"  - total_file_size: {total_file_size} bytes\n\n"
                        "Possible reasons:\n"
                        "  - Wazuh is not generating alerts\n"
                        "  - Log files were recently created but no alerts logged yet\n"
                        "  - Alerts are being written to a different location\n\n"
                        "Try:\n"
                        f"  - Increase report_period (e.g., {period_days+1}d or 7d)\n"
                        "  - Check Wazuh manager status\n"
                        "  - Verify Wazuh is receiving events from agents\n"
                        "  - Check Wazuh logs for errors"
                    )
                else:
                    error_msg = (
                        "No alerts found in the selected time period!\n\n"
                        "The log files contain data, but no alerts match the time filter.\n\n"
                        f"Configuration:\n"
                        f"  - report_period: {report_period} ({period_label}, {period_days} day(s))\n"
                        f"  - log_files: {len(log_files)} file(s)\n"
                        f"  - total_file_size: {total_file_size:,} bytes\n"
                        f"  - time_range: {start_time.strftime('%Y-%m-%d %H:%M:%S')} to {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                        "Possible reasons:\n"
                        "  - No alerts in the selected time period\n"
                        "  - Time range filter too restrictive\n"
                        "  - Alerts are outside the requested date range\n\n"
                        "Try:\n"
                        f"  - Increase report_period (e.g., {period_days+1}d or 7d)\n"
                        "  - Check if alerts exist in the time range\n"
                        "  - Verify alert timestamps in log files\n"
                        "  - Use a longer time period to include more alerts"
                    )
                
                logger.error(error_msg)
                print_error("No alerts found")
                print(f"\n{Colors.WARNING}{error_msg}{Colors.ENDC}\n")
                sys.exit(1)
            
            # Calculate risk score
            risk_score, counts = processor.calculate_risk_score()
            logger.info(f"Risk Score: {risk_score} (Critical: {counts['critical']}, "
                       f"High: {counts['high']}, Medium: {counts['medium']}, Low: {counts['low']})")
            
            # Enrich alerts with MITRE ATT&CK data if API is enabled
            if api_service.is_enabled():
                processor.alerts = alert_service.enrich_alerts(processor.alerts)
            
            # Collect system information using service layer
            print_step(4, 6, "Collecting system information")
            logger.info("Collecting system information...")
            system_info = collect_system_info(config, start_time=start_time, end_time=end_time, report_period=report_period, logger=logger, api_service=api_service)
            
            # Log API status
            if system_info.get('api_enabled'):
                logger.info("Wazuh API data collected successfully")
                print_info("Wazuh API", "Connected - Advanced reports enabled")
                
            elif config.get('wazuh_api_enabled'):
                logger.warning("Wazuh API enabled but connection failed")
                print_warning("Wazuh API", "Connection failed - Using basic reports only")
            
            # Get alerts directory size
            alerts_dir = config.get('log_dir', '/var/ossec/logs/alerts')
            size_bytes, size_human = SystemInfo.get_directory_size(alerts_dir)
            if size_human:
                system_info['alerts_directory_size'] = size_human
            
            # Add report period and time range information to system_info for report generation
            system_info['report_period'] = report_period
            system_info['report_period_days'] = period_days
            system_info['report_period_label'] = period_label
            if start_time:
                system_info['report_start_time'] = start_time.strftime('%Y-%m-%d %H:%M:%S')
                system_info['report_start_date'] = start_time.strftime('%Y-%m-%d')
            if end_time:
                system_info['report_end_time'] = end_time.strftime('%Y-%m-%d %H:%M:%S')
                system_info['report_end_date'] = end_time.strftime('%Y-%m-%d')
            
            # Update agent_count from API data if available
            if system_info.get('api_enabled'):
                api_data = system_info.get('api_data', {})
                agent_summary = api_data.get('agent_summary', {})
                if agent_summary.get('enabled'):
                    system_info['agent_count'] = agent_summary.get('active', 0)
                    system_info['total_agents'] = agent_summary.get('total', 0)
            
            # Add MITRE and vulnerability data using service layer
            if api_service.is_enabled():
                try:
                    # Get MITRE statistics
                    mitre_stats = alert_service.get_mitre_statistics(processor.alerts)
                    system_info['mitre_statistics'] = mitre_stats
                    
                    # Detect APT activities
                    apt_activities = alert_service.get_apt_activities(processor.alerts)
                    system_info['apt_activities'] = apt_activities
                    if apt_activities:
                        logger.info(f"Detected {len(apt_activities)} potential APT group activities")
                    
                    # Get vulnerability data
                    if alert_service.vulnerability_detector:
                        try:
                            agents = api_service.api_client.get_agents(limit=100)
                            vuln_data = alert_service.get_vulnerability_data(agents, processor.alerts)
                            system_info.update(vuln_data)
                            logger.info("Vulnerability analysis completed")
                        except Exception as e:
                            logger.warning(f"Failed to collect vulnerability data: {e}")
                except Exception as e:
                    logger.warning(f"Failed to enrich with API data: {e}")
            
            # Add event correlation data
            try:
                correlated_events = processor.get_correlated_events(
                    time_window_minutes=60,
                    correlation_keys=['src_ip', 'agent_name', 'rule_id']
                )
                system_info['correlated_events'] = correlated_events[:20]  # Top 20
                if correlated_events:
                    logger.info(f"Found {len(correlated_events)} correlated event groups")
            except Exception as e:
                logger.warning(f"Failed to generate event correlation: {e}")
                system_info['correlated_events'] = []
            
            logger.info(f"System info collected: Wazuh {system_info['wazuh_version']}, "
                       f"{system_info['system_updates']} updates available")
            print_info("Wazuh version", system_info['wazuh_version'])
            print_info("System updates", str(system_info['system_updates']))
            active_agents = system_info.get('agent_count', 0)
            total_agents = system_info.get('total_agents', 0)
            if total_agents > 0:
                print_info("Active agents", f"{active_agents} / {total_agents}")
            else:
                print_info("Active agents", str(active_agents))
            
            # Prepare output directory
            # In test mode, use current directory; otherwise use config output_dir
            if args.test:
                output_dir = os.getcwd()
                logger.info(f"Test mode: Using current directory for output: {output_dir}")
                print_info("Test mode", f"Reports will be saved to: {output_dir}")
            else:
                output_dir = config.get('output_dir', '/var/ossec/logs/reports')
                if not safe_mkdir(output_dir):
                    logger.warning(f"Cannot create {output_dir}, using current directory")
                    output_dir = os.getcwd()
                    print_warning(f"Cannot create {output_dir}, using current directory")
            
            # Create report generator config
            report_config = {
                'level': config.get('level', 12),
                'top_alerts_count': config.get('top_alerts_count', 100),
            }
            
            # Generate HTML report (only format supported)
            print_step(5, 6, "Generating security report")
            logger.info("Generating HTML report...")
            
            temp_html = get_temp_file(suffix='.html', prefix='leblebi_report_')
            temp_files.append(temp_html)
            
            generator = HTMLReportGenerator(report_config)
            report_file = generator.generate(processor, system_info, temp_html)
            report_size = os.path.getsize(report_file)
            logger.info(f"HTML report generated: {report_file} ({report_size:,} bytes)")
            print_info("HTML report generated", f"{report_size:,} bytes")
            
            # Final HTML report location with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            final_report = os.path.join(output_dir, f'leblebi_security_report_{timestamp}.html')
            
            # Copy to final location
            try:
                shutil.copy2(report_file, final_report)
                logger.info(f"HTML report saved to {final_report}")
                print_info("HTML report saved", final_report)
            except Exception as e:
                logger.warning(f"Could not copy HTML report to {final_report}: {e}")
                print_warning(f"Could not copy HTML report to {final_report}: {e}")
                final_report = report_file  # Use temp file as final
            
            # Send email if not dry-run and not test mode
            print_step(6, 6, "Sending email notification")
            if not args.dry_run and not args.test:
                try:
                    email_config = {
                        'smtp_server': config.get('smtp_server'),
                        'smtp_port': config.get('smtp_port'),
                        'smtp_use_tls': config.get('smtp_use_tls', False),
                        'smtp_auth_user': config.get('smtp_auth_user', ''),
                        'smtp_auth_pass': config.get('smtp_auth_pass', ''),
                        'mail_from': config.get('mail_from'),
                        'mail_to': config.get('mail_to'),
                        'mail_subject_prefix': config.get('mail_subject_prefix'),
                        'mail_format': 'html_attachment',  # HTML in body + HTML as attachment
                    }
                    
                    mail_to_list = email_config['mail_to']
                    if not mail_to_list or (isinstance(mail_to_list, list) and len(mail_to_list) == 0):
                        logger.warning("Email not configured (mail_to is empty), skipping email send")
                        print_warning("Email not configured, skipping")
                    else:
                        sender = EmailSender(email_config)
                        # Send HTML report as inline email body
                        sender.send_report(report_file)
                        # Format recipients for logging
                        if isinstance(mail_to_list, list):
                            recipients_str = ', '.join(mail_to_list) if len(mail_to_list) <= 3 else f"{len(mail_to_list)} recipients"
                        else:
                            recipients_str = str(mail_to_list)
                        logger.info(f"Email sent successfully to {recipients_str} (format: html_attachment)")
                        print_info("Email sent", f"{recipients_str} (html_attachment)")
                        email_sent = True
                except Exception as e:
                    logger.error(f"Failed to send email: {e}")
                    print_error(f"Failed to send email: {e}")
                    # Don't exit on email failure, report was generated
            elif args.test:
                logger.info("Test mode: Email not sent, report saved to current directory")
                print_info("Test mode", "Email not sent, report saved to current directory")
            else:
                logger.info("Dry-run mode: Email not sent")
                print_info("Dry-run mode", "Email not sent")
            
            # Print final summary
            print_final_summary(processor, system_info, final_report or report_file, email_sent, temp_files)
            
            logger.info("=" * 60)
            logger.info("Leblebi execution completed successfully!")
            logger.info("=" * 60)
            
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        sys.exit(1)
    except RuntimeError as e:
        if "Another instance is running" in str(e):
            logger.warning(str(e))
            sys.exit(1)
        raise
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()

