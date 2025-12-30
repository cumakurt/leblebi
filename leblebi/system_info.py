"""System information collection module for Leblebi

This module provides system information collection functions including
Wazuh version, system updates, memory, disk usage, and agent counts.
"""

import os
import subprocess
from typing import Dict, Optional, List, Tuple
from pathlib import Path
from leblebi.utils import safe_subprocess_run


class SystemInfo:
    """Collect system information"""
    
    @staticmethod
    def get_wazuh_version() -> str:
        """Get installed Wazuh version
        
        Returns:
            Wazuh version string or "Unknown" if not found
        """
        wazuh_control = Path('/var/ossec/bin/wazuh-control')
        if not wazuh_control.exists():
            return "Unknown"
        
        returncode, stdout, stderr = safe_subprocess_run(
            [str(wazuh_control), 'info'],
            timeout=10
        )
        
        if returncode == 0 and stdout:
            for line in stdout.split('\n'):
                if 'version' in line.lower():
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
        
        return "Unknown"
    
    @staticmethod
    def get_system_updates() -> int:
        """Get count of available system updates (Ubuntu/Debian)
        
        Returns:
            Number of available updates, or 0 if unable to determine
        """
        returncode, stdout, stderr = safe_subprocess_run(
            ['apt', 'list', '--upgradable'],
            timeout=30
        )
        
        if returncode == 0 and stdout:
            # Count lines with 'upgradable' (excluding header)
            count = sum(1 for line in stdout.split('\n') if 'upgradable' in line.lower())
            return max(0, count - 1)  # Subtract header
        
        return 0
    
    @staticmethod
    def get_memory_info() -> Dict[str, str]:
        """Get memory usage information
        
        Returns:
            Dictionary with memory information (total, used, free, etc.) or empty dict
        """
        returncode, stdout, stderr = safe_subprocess_run(
            ['free', '-h'],
            timeout=10
        )
        
        if returncode == 0 and stdout:
            lines = stdout.split('\n')
            if len(lines) >= 2:
                mem_line = lines[1].split()
                if len(mem_line) >= 7:
                    return {
                        'total': mem_line[1],
                        'used': mem_line[2],
                        'free': mem_line[3],
                        'shared': mem_line[4],
                        'buff_cache': mem_line[5],
                        'available': mem_line[6]
                    }
        
        return {}
    
    @staticmethod
    def get_disk_usage(path: str = '/') -> List[Dict[str, str]]:
        """Get disk usage information
        
        Args:
            path: Path to check disk usage for (default: '/')
            
        Returns:
            List of dictionaries with disk usage information
        """
        returncode, stdout, stderr = safe_subprocess_run(
            ['df', '-h', path],
            timeout=10
        )
        
        if returncode == 0 and stdout:
            lines = stdout.strip().split('\n')
            disk_info = []
            for line in lines[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 6:
                    disk_info.append({
                        'filesystem': parts[0],
                        'size': parts[1],
                        'used': parts[2],
                        'available': parts[3],
                        'use_percent': parts[4],
                        'mounted': parts[5]
                    })
            return disk_info
        
        return []
    
    @staticmethod
    def get_directory_size(path: str) -> Tuple[Optional[int], Optional[str]]:
        """Get directory size in bytes and human-readable format
        
        Args:
            path: Directory path to check
            
        Returns:
            Tuple of (size_bytes, size_human) or (None, None) if error
        """
        returncode, stdout, stderr = safe_subprocess_run(
            ['du', '-sb', path],
            timeout=30
        )
        
        if returncode == 0 and stdout:
            try:
                size_bytes = int(stdout.split()[0])
                # Get human readable format
                returncode_h, stdout_h, stderr_h = safe_subprocess_run(
                    ['du', '-sh', path],
                    timeout=30
                )
                size_human = stdout_h.split()[0] if returncode_h == 0 and stdout_h else None
                return size_bytes, size_human
            except (ValueError, IndexError):
                pass
        
        return None, None
    
    @staticmethod
    def get_directory_breakdown(path: str) -> List[Tuple[str, int, str]]:
        """Get directory size breakdown
        
        Args:
            path: Directory path to analyze
            
        Returns:
            List of tuples (item_path, size) sorted by size descending
        """
        returncode, stdout, stderr = safe_subprocess_run(
            ['find', path, '-mindepth', '1', '-maxdepth', '1', '-exec', 'du', '-sb', '{}', '+'],
            timeout=60
        )
        
        if returncode == 0 and stdout:
            items = []
            for line in stdout.split('\n'):
                if line.strip():
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        try:
                            size = int(parts[0])
                            item_path = parts[1]
                            # Skip jq error logs
                            if 'jq' not in item_path.lower():
                                items.append((item_path, size))
                        except ValueError:
                            continue
            # Sort by size descending
            items.sort(key=lambda x: x[1], reverse=True)
            return items
        
        return []
    
    @staticmethod
    def get_swap_info() -> Dict[str, str]:
        """Get swap usage information
        
        Returns:
            Dictionary with swap information (total, used, free) or empty dict
        """
        returncode, stdout, stderr = safe_subprocess_run(
            ['free', '-h'],
            timeout=10
        )
        
        if returncode == 0 and stdout:
            lines = stdout.split('\n')
            if len(lines) >= 3:
                swap_line = lines[2].split()
                if len(swap_line) >= 4:
                    return {
                        'total': swap_line[1],
                        'used': swap_line[2],
                        'free': swap_line[3]
                    }
        
        return {}
    
    @staticmethod
    def get_wazuh_agent_count() -> int:
        """Get count of Wazuh agents
        
        Returns:
            Number of agents found, or 0 if unable to determine
        """
        agent_info_dir = Path('/var/ossec/queue/agent-info')
        if not agent_info_dir.exists():
            return 0
        
        try:
            return len(list(agent_info_dir.glob('*.json')))
        except (PermissionError, OSError):
            return 0

