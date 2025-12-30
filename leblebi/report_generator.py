"""Report generation workflow functions"""

import os
import shutil
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from leblebi.config import Config
from leblebi.alerts import AlertProcessor
from leblebi.services import (
    APIService, ReportService, SystemInfoService, AlertProcessingService
)
from leblebi.exceptions import LeblebiError, AlertProcessingError
from leblebi.utils import safe_mkdir, get_temp_file, get_memory_usage_mb, should_enable_sampling
# Import CLI utilities from cli module
from leblebi.cli import Colors, print_step, print_info, print_warning, print_error

# Import utility functions from proper modules
from leblebi.log_utils import find_wazuh_log_files, get_time_range


def load_alerts_for_report(
    config: Config,
    processor: AlertProcessor,
    log_files: List[str],
    start_time: datetime,
    end_time: datetime,
    period_days: int,
    logger: logging.Logger
) -> int:
    """Load alerts from log files with performance optimizations
    
    Args:
        config: Configuration object
        processor: Alert processor instance
        log_files: List of log file paths
        start_time: Start time for filtering
        end_time: End time for filtering
        period_days: Number of days in period
        logger: Logger instance
        
    Returns:
        Number of alerts loaded
    """
    # Check total file size
    total_size = sum(os.path.getsize(f) for f in log_files if os.path.exists(f))
    total_size_gb = total_size / (1024 * 1024 * 1024)
    
    if total_size_gb > 1.0:
        logger.warning(f"Large log files detected: Total size {total_size_gb:.2f} GB")
    
    # Get performance settings
    max_alerts = config.get('max_alerts_to_process', 0)
    if max_alerts == 0:
        max_alerts = None
    
    sampling_enabled = config.get('sampling_enabled', False)
    sampling_rate = float(config.get('sampling_rate', 1.0)) if sampling_enabled else 1.0
    use_streaming = config.get('use_streaming_parser', True)
    memory_limit_mb = config.get('memory_limit_mb', 0)
    
    # Check memory and auto-enable sampling if needed
    if memory_limit_mb > 0:
        current_memory = get_memory_usage_mb()
        if should_enable_sampling(memory_limit_mb, sampling_enabled, total_size_gb):
            if not sampling_enabled:
                sampling_enabled = True
                sampling_rate = 0.1
                logger.warning(f"Memory limit exceeded - auto-enabling sampling at 10%")
    
    # Load alerts
    if len(log_files) == 1:
        total_alerts = processor.load_alerts(
            log_files[0],
            start_time=start_time,
            end_time=end_time,
            max_alerts=max_alerts,
            sample_rate=sampling_rate,
            use_streaming=use_streaming
        )
    else:
        total_alerts = processor.load_alerts_from_multiple_files(
            log_files,
            start_time=start_time,
            end_time=end_time,
            max_alerts=max_alerts,
            sample_rate=sampling_rate,
            use_streaming=use_streaming
        )
    
    logger.info(f"Loaded {total_alerts} alerts from {len(log_files)} file(s)")
    return total_alerts


def enrich_alerts_with_api_data(
    processor: AlertProcessor,
    alert_service: AlertProcessingService,
    api_service: APIService,
    system_info: Dict[str, Any],
    config: Config,
    logger: logging.Logger
) -> None:
    """Enrich alerts and system info with API data
    
    Args:
        processor: Alert processor with loaded alerts
        alert_service: Alert processing service
        api_service: API service instance
        system_info: System information dictionary to update
        config: Configuration object
        logger: Logger instance
    """
    if not api_service.is_enabled():
        return
    
    try:
        # Enrich alerts with MITRE data
        processor.alerts = alert_service.enrich_alerts(processor.alerts)
        
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
        logger.warning(f"Failed to enrich alerts with API data: {e}")


def generate_security_report(
    config: Config,
    processor: AlertProcessor,
    system_info: Dict[str, Any],
    output_dir: str,
    logger: logging.Logger
) -> str:
    """Generate security report file
    
    Args:
        config: Configuration object
        processor: Alert processor with alerts
        system_info: System information dictionary
        output_dir: Output directory for report
        logger: Logger instance
        
    Returns:
        Path to generated report file
    """
    report_service = ReportService(config, logger=logger)
    
    # Create temporary report file
    temp_html = get_temp_file(suffix='.html', prefix='leblebi_report_')
    
    # Generate report
    report_file = report_service.generate_report(processor, system_info, temp_html)
    
    # Copy to final location with timestamp
    from datetime import datetime
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    final_report = os.path.join(output_dir, f'leblebi_security_report_{timestamp}.html')
    try:
        shutil.copy2(report_file, final_report)
        logger.info(f"Report saved to {final_report}")
        return final_report
    except Exception as e:
        logger.warning(f"Could not copy report to {final_report}: {e}")
        return report_file

