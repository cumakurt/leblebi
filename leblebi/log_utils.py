"""Log file utilities for Leblebi

This module provides utilities for finding and working with Wazuh log files.
"""

import os
from datetime import datetime, timedelta
from typing import List, Tuple, Optional


def find_alerts_file(log_dir: str) -> Optional[str]:
    """Find alerts.json file in standard locations
    
    Args:
        log_dir: Base log directory
        
    Returns:
        Path to alerts.json file if found, None otherwise
    """
    # Standard locations
    locations = [
        "/var/ossec/logs/alerts/alerts.json",
        os.path.join(log_dir, "alerts.json"),
        "./alerts.json",
    ]
    
    for location in locations:
        if os.path.exists(location):
            return location
    
    return None


def find_wazuh_log_files(log_dir: str, days: int) -> Tuple[List[str], List[str]]:
    """Find Wazuh log files for specified number of days
    
    Wazuh log structure:
    - Today: /var/ossec/logs/alerts/alerts.json (uncompressed)
    - Previous days: /var/ossec/logs/alerts/YYYY/MMM/ossec-alerts-DD.json.gz (compressed)
      or /var/ossec/logs/alerts/YYYY/MMM/ossec-alerts-DD.json (uncompressed, if not yet compressed)
    
    Args:
        log_dir: Base log directory (e.g., /var/ossec/logs/alerts)
        days: Number of days to include (1 = today only, 2 = today + yesterday, etc.)
        
    Returns:
        Tuple of (list of log file paths, list of missing dates)
        Log files are in chronological order (oldest first)
        Missing dates list contains dates for which log files were not found
    """
    log_files = []
    missing_dates = []
    today = datetime.now()
    
    # Month abbreviations in English (Wazuh uses English month names)
    month_abbr = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 
                  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    
    # Iterate backwards from today
    for day_offset in range(days - 1, -1, -1):
        target_date = today - timedelta(days=day_offset)
        year = target_date.year
        month = month_abbr[target_date.month - 1]
        day = target_date.day
        date_str = target_date.strftime('%Y-%m-%d')
        
        file_found = False
        
        if day_offset == 0:
            # Today - use uncompressed alerts.json
            today_file = os.path.join(log_dir, "alerts.json")
            if os.path.exists(today_file):
                log_files.append(today_file)
                file_found = True
            else:
                # Also check standard location
                standard_today = "/var/ossec/logs/alerts/alerts.json"
                if os.path.exists(standard_today):
                    log_files.append(standard_today)
                    file_found = True
            
            if not file_found:
                missing_dates.append(date_str)
        else:
            # Previous days - check both compressed (.gz) and uncompressed (.json) files
            # Path: /var/ossec/logs/alerts/YYYY/MMM/ossec-alerts-DD.json.gz or .json
            compressed_file = os.path.join(log_dir, str(year), month, f"ossec-alerts-{day:02d}.json.gz")
            uncompressed_file = os.path.join(log_dir, str(year), month, f"ossec-alerts-{day:02d}.json")
            
            # Check compressed file first
            if os.path.exists(compressed_file):
                log_files.append(compressed_file)
                file_found = True
            # Check uncompressed file
            elif os.path.exists(uncompressed_file):
                log_files.append(uncompressed_file)
                file_found = True
            else:
                # Also check standard location
                standard_compressed = os.path.join("/var/ossec/logs/alerts", str(year), month, f"ossec-alerts-{day:02d}.json.gz")
                standard_uncompressed = os.path.join("/var/ossec/logs/alerts", str(year), month, f"ossec-alerts-{day:02d}.json")
                
                if os.path.exists(standard_compressed):
                    log_files.append(standard_compressed)
                    file_found = True
                elif os.path.exists(standard_uncompressed):
                    log_files.append(standard_uncompressed)
                    file_found = True
            
            if not file_found:
                missing_dates.append(date_str)
    
    return log_files, missing_dates


def get_time_range(period: str) -> Tuple[datetime, datetime, int]:
    """Get start and end time for report period
    
    Args:
        period: Report period in format 'Nd' where N is number of days (e.g., '1d', '2d', '7d')
        
    Returns:
        Tuple of (start_time, end_time, days)
    """
    end_time = datetime.now()
    
    # Parse period format: 'Nd' where N is number of days
    try:
        if period.lower().endswith('d'):
            days = int(period.lower().rstrip('d'))
            if days < 1:
                days = 1
        else:
            # Try to parse as integer (backward compatibility)
            days = int(period)
            if days < 1:
                days = 1
    except (ValueError, AttributeError):
        # Default to 1 day if parsing fails
        days = 1
    
    # Calculate start time
    if days == 1:
        # Today only (0 days back, just today)
        start_time = end_time.replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        # Last N days (N-1 days back from today)
        start_time = (end_time - timedelta(days=days-1)).replace(hour=0, minute=0, second=0, microsecond=0)
    
    return start_time, end_time, days

