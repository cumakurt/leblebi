"""Service layer for Leblebi business logic"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from leblebi.config import Config
from leblebi.alerts import AlertProcessor
from leblebi.reporting import HTMLReportGenerator
from leblebi.system_info import SystemInfo
from leblebi.wazuh_api import WazuhAPI
from leblebi.factory import WazuhAPIFactory
from leblebi.api_collector import APICollector
from leblebi.agent_health import AgentHealthMonitor
from leblebi.mitre_enrichment import MITREEnrichment
from leblebi.vulnerability_detection import VulnerabilityDetector
from leblebi.exceptions import (
    LeblebiError, APIError, ReportGenerationError, 
    AlertProcessingError, ConfigurationError
)
from leblebi.utils import safe_mkdir, get_temp_file, get_memory_usage_mb, check_memory_limit


class APIService:
    """Service for Wazuh API operations"""
    
    def __init__(self, config: Config, logger: Optional[logging.Logger] = None):
        """Initialize API service
        
        Args:
            config: Configuration object
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or logging.getLogger('leblebi')
        self.api_client: Optional[WazuhAPI] = None
        self._initialize_api()
    
    def _initialize_api(self) -> None:
        """Initialize API client if enabled"""
        if not self.config.get('wazuh_api_enabled', False):
            self.logger.debug("Wazuh API is disabled")
            return
        
        try:
            self.api_client = WazuhAPIFactory.create(self.config)
            if self.api_client:
                self.logger.info("Wazuh API client initialized successfully")
            else:
                self.logger.warning("Wazuh API client creation returned None")
        except Exception as e:
            self.logger.warning(f"Failed to initialize Wazuh API: {e}")
            self.api_client = None
    
    def is_enabled(self) -> bool:
        """Check if API is enabled and connected"""
        return self.api_client is not None
    
    def get_agent_health_data(self) -> Dict[str, Any]:
        """Get agent health monitoring data
        
        Returns:
            Dictionary with agent health information
        """
        if not self.is_enabled():
            return {'enabled': False}
        
        try:
            agent_monitor = AgentHealthMonitor(self.api_client)
            return {
                'enabled': True,
                'agent_summary': agent_monitor.get_agent_summary(),
                'disconnected_agents': agent_monitor.get_disconnected_agents(hours_threshold=24),
                'critical_agents': agent_monitor.get_critical_agents(),
                'agents_by_version': agent_monitor.get_agents_by_version(),
                'agents_by_os': agent_monitor.get_agents_by_os(),
            }
        except Exception as e:
            self.logger.warning(f"Failed to collect agent health data: {e}")
            return {'enabled': False, 'error': str(e)}
    
    def get_manager_status(self) -> Optional[Dict[str, Any]]:
        """Get Wazuh manager status
        
        Returns:
            Manager status dictionary or None
        """
        if not self.is_enabled():
            return None
        
        try:
            return self.api_client.get_manager_status()
        except Exception as e:
            self.logger.warning(f"Failed to get manager status: {e}")
            return None
    
    def collect_agent_data(
        self,
        agents: List[Dict],
        data_types: List[str]
    ) -> Dict[str, List[Dict]]:
        """Collect data from multiple agents in parallel
        
        Args:
            agents: List of agent dictionaries
            data_types: List of data types to collect
            
        Returns:
            Dictionary mapping data types to collected data
        """
        if not self.is_enabled() or not agents or not data_types:
            return {dt: [] for dt in data_types}
        
        try:
            max_workers = self.config.get('api_max_workers', 5)
            limit_per_agent = self.config.get('api_limit_per_agent', 10)
            collection_timeout = self.config.get('api_collection_timeout', 120)
            
            api_collector = APICollector(
                self.api_client,
                logger=self.logger,
                max_workers=max_workers,
                collection_timeout=collection_timeout
            )
            
            # Limit agents if configured
            max_agents = self.config.get('max_agents_to_collect', 50)
            if max_agents > 0:
                agents = agents[:max_agents]
            
            return api_collector.collect_agent_data_parallel(
                agents,
                data_types,
                limit_per_agent=limit_per_agent
            )
        except Exception as e:
            self.logger.error(f"Error collecting agent data: {e}")
            return {dt: [] for dt in data_types}
    
    def collect_manager_data(self, data_types: List[str]) -> Dict[str, Any]:
        """Collect manager-level data
        
        Args:
            data_types: List of data types to collect
            
        Returns:
            Dictionary with collected data
        """
        if not self.is_enabled() or not data_types:
            return {}
        
        try:
            max_workers = self.config.get('api_max_workers', 5)
            collection_timeout = self.config.get('api_collection_timeout', 120)
            api_collector = APICollector(
                self.api_client,
                logger=self.logger,
                max_workers=max_workers,
                collection_timeout=collection_timeout
            )
            return api_collector.collect_manager_data_parallel(data_types)
        except Exception as e:
            self.logger.warning(f"Error collecting manager data: {e}")
            return {}


class ReportService:
    """Service for report generation"""
    
    def __init__(
        self,
        config: Config,
        api_service: Optional[APIService] = None,
        logger: Optional[logging.Logger] = None
    ):
        """Initialize report service
        
        Args:
            config: Configuration object
            api_service: API service instance (optional)
            logger: Logger instance
        """
        self.config = config
        self.api_service = api_service
        self.logger = logger or logging.getLogger('leblebi')
    
    def generate_report(
        self,
        processor: AlertProcessor,
        system_info: Dict[str, Any],
        output_file: Optional[str] = None
    ) -> str:
        """Generate HTML security report
        
        Args:
            processor: Alert processor with loaded alerts
            system_info: System information dictionary
            output_file: Output file path (optional, will create temp file if not provided)
            
        Returns:
            Path to generated report file
            
        Raises:
            ReportGenerationError: If report generation fails
        """
        try:
            if not output_file:
                output_file = get_temp_file(suffix='.html', prefix='leblebi_report_')
            
            report_config = {
                'level': self.config.get('level', 12),
                'top_alerts_count': self.config.get('top_alerts_count', 100),
            }
            
            generator = HTMLReportGenerator(report_config)
            report_file = generator.generate(processor, system_info, output_file)
            
            self.logger.info(f"Report generated successfully: {report_file}")
            return report_file
            
        except Exception as e:
            error_msg = f"Failed to generate report: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            raise ReportGenerationError(error_msg) from e


class SystemInfoService:
    """Service for collecting system information"""
    
    def __init__(
        self,
        config: Config,
        api_service: Optional[APIService] = None,
        logger: Optional[logging.Logger] = None
    ):
        """Initialize system info service
        
        Args:
            config: Configuration object
            api_service: API service instance (optional)
            logger: Logger instance
        """
        self.config = config
        self.api_service = api_service
        self.logger = logger or logging.getLogger('leblebi')
        self.sys_info = SystemInfo()
    
    def collect_all(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        report_period: str = '1d'
    ) -> Dict[str, Any]:
        """Collect all system information
        
        Args:
            start_time: Start time for filtering
            end_time: End time for filtering
            report_period: Report period string
            
        Returns:
            Dictionary with all system information
        """
        system_data = {
            'wazuh_version': self.sys_info.get_wazuh_version(),
            'system_updates': self.sys_info.get_system_updates(),
            'memory_info': self.sys_info.get_memory_info(),
            'disk_usage': self.sys_info.get_disk_usage('/'),
            'swap_info': self.sys_info.get_swap_info(),
            'agent_count': self.sys_info.get_wazuh_agent_count(),
            'alerts_directory_size': None,
            'api_enabled': False,
            'api_data': {},
            'report_period': report_period
        }
        
        # Collect API data if available
        if self.api_service and self.api_service.is_enabled():
            system_data['api_enabled'] = True
            
            # Collect agent health
            if self.config.get('use_api_for_agent_health', True):
                system_data['api_data'].update(self.api_service.get_agent_health_data())
            
            # Collect manager status
            if self.config.get('use_api_for_manager_status', True):
                manager_status = self.api_service.get_manager_status()
                if manager_status:
                    system_data['api_data']['manager_status'] = manager_status
            
            # Collect agent data
            data_types_to_collect = []
            if self.config.get('use_api_for_sca', True):
                data_types_to_collect.append('sca')
            if self.config.get('use_api_for_syscheck', True):
                data_types_to_collect.append('syscheck')
            if self.config.get('use_api_for_rootcheck', True):
                data_types_to_collect.append('rootcheck')
            if self.config.get('use_api_for_syscollector', True):
                data_types_to_collect.append('syscollector')
            
            if data_types_to_collect:
                try:
                    agents = self.api_service.api_client.get_agents(status='active', limit=1000)
                    if not agents:
                        agents = self.api_service.api_client.get_agents(limit=1000)
                    
                    if agents:
                        agent_data = self.api_service.collect_agent_data(agents, data_types_to_collect)
                        system_data['api_data'].update(agent_data)
                except Exception as e:
                    self.logger.warning(f"Failed to collect agent data: {e}")
            
            # Collect manager-level data
            manager_data_types = []
            if self.config.get('use_api_for_manager_status', True):
                manager_data_types.extend(['status', 'stats'])
            if self.config.get('use_api_for_ciscat', True):
                manager_data_types.append('ciscat')
            
            if manager_data_types:
                try:
                    manager_data = self.api_service.collect_manager_data(manager_data_types)
                    system_data['api_data'].update(manager_data)
                except Exception as e:
                    self.logger.warning(f"Error collecting manager data: {e}")
        
        # Get alerts directory size
        alerts_dir = self.config.get('log_dir', '/var/ossec/logs/alerts')
        size_bytes, size_human = SystemInfo.get_directory_size(alerts_dir)
        if size_human:
            system_data['alerts_directory_size'] = size_human
        
        return system_data


class AlertProcessingService:
    """Service for alert processing operations"""
    
    def __init__(
        self,
        config: Config,
        api_service: Optional[APIService] = None,
        logger: Optional[logging.Logger] = None
    ):
        """Initialize alert processing service
        
        Args:
            config: Configuration object
            api_service: API service instance (optional)
            logger: Logger instance
        """
        self.config = config
        self.api_service = api_service
        self.logger = logger or logging.getLogger('leblebi')
        self.mitre_enrichment: Optional[MITREEnrichment] = None
        self.vulnerability_detector: Optional[VulnerabilityDetector] = None
        self._initialize_enrichment()
    
    def _initialize_enrichment(self) -> None:
        """Initialize MITRE and vulnerability enrichment"""
        if not self.api_service or not self.api_service.is_enabled():
            return
        
        try:
            # Initialize MITRE enrichment
            self.mitre_enrichment = MITREEnrichment(self.api_service.api_client)
            self.logger.info("MITRE enrichment initialized")
            
            # Initialize vulnerability detector
            self.vulnerability_detector = VulnerabilityDetector(self.api_service.api_client)
            self.logger.info("Vulnerability detector initialized")
        except Exception as e:
            self.logger.warning(f"Failed to initialize enrichment: {e}")
    
    def enrich_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich alerts with MITRE and other data
        
        Args:
            alerts: List of alert dictionaries
            
        Returns:
            Enriched alert list
        """
        if not self.mitre_enrichment:
            return alerts
        
        try:
            enriched = self.mitre_enrichment.enrich_alerts(alerts)
            alerts_with_mitre = sum(
                1 for alert in enriched 
                if alert.get('mitre_enriched', {}).get('techniques') or 
                   alert.get('mitre_enriched', {}).get('tactics')
            )
            self.logger.info(f"MITRE enrichment: {alerts_with_mitre}/{len(enriched)} alerts have MITRE data")
            return enriched
        except Exception as e:
            self.logger.warning(f"Failed to enrich alerts: {e}")
            return alerts
    
    def get_mitre_statistics(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get MITRE statistics from alerts
        
        Args:
            alerts: List of alert dictionaries
            
        Returns:
            MITRE statistics dictionary
        """
        if not self.mitre_enrichment:
            return {}
        
        try:
            return self.mitre_enrichment.get_mitre_statistics(alerts)
        except Exception as e:
            self.logger.warning(f"Failed to get MITRE statistics: {e}")
            return {}
    
    def get_apt_activities(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get APT activities from alerts
        
        Args:
            alerts: List of alert dictionaries
            
        Returns:
            List of APT activity dictionaries
        """
        if not self.mitre_enrichment:
            return []
        
        try:
            return self.mitre_enrichment.detect_apt_activity(alerts)
        except Exception as e:
            self.logger.warning(f"Failed to detect APT activities: {e}")
            return []
    
    def get_vulnerability_data(
        self,
        agents: List[Dict],
        alerts: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Get vulnerability detection data
        
        Args:
            agents: List of agent dictionaries
            alerts: List of alert dictionaries
            
        Returns:
            Dictionary with vulnerability data
        """
        if not self.vulnerability_detector:
            return {}
        
        try:
            vuln_summary = self.vulnerability_detector.get_vulnerability_summary(agents)
            cve_data = self.vulnerability_detector.get_cve_alerts_from_alerts(alerts)
            patch_recommendations = self.vulnerability_detector.get_patch_priority_recommendations(agents)
            
            return {
                'vulnerability_summary': vuln_summary,
                'cve_data': cve_data,
                'patch_recommendations': patch_recommendations
            }
        except Exception as e:
            self.logger.warning(f"Failed to get vulnerability data: {e}")
            return {}

