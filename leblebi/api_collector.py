"""Parallel API data collection module for Leblebi

This module provides parallel API request handling for improved performance.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutureTimeoutError
from typing import Dict, List, Any, Optional, Callable, Tuple
from leblebi.wazuh_api import WazuhAPI


class APICollector:
    """Collect API data in parallel for improved performance"""
    
    def __init__(
        self,
        api_client: WazuhAPI,
        logger: Optional[logging.Logger] = None,
        max_workers: int = 5,
        collection_timeout: int = 120
    ):
        """Initialize API collector
        
        Args:
            api_client: WazuhAPI instance
            logger: Logger instance
            max_workers: Maximum number of parallel workers
            collection_timeout: Timeout for collection operations in seconds
        """
        self.api_client = api_client
        self.logger = logger or logging.getLogger('leblebi')
        self.max_workers = max_workers
        self.collection_timeout = collection_timeout
    
    def collect_agent_data_parallel(
        self,
        agents: List[Dict],
        data_types: List[str],
        limit_per_agent: int = 10
    ) -> Dict[str, List[Dict]]:
        """Collect multiple data types from agents in parallel
        
        Args:
            agents: List of agent dictionaries
            data_types: List of data types to collect ('sca', 'syscheck', 'rootcheck', 'syscollector')
            limit_per_agent: Limit per agent for each data type
            
        Returns:
            Dictionary mapping data types to collected data
        """
        results = {data_type: [] for data_type in data_types}
        
        if not agents:
            self.logger.warning("No agents provided for data collection")
            return results
        
        # Create tasks for parallel execution
        tasks = []
        agents_to_check = agents  # Process all provided agents
        self.logger.debug(f"Creating tasks for {len(agents_to_check)} agents: {[a.get('id') for a in agents_to_check[:10] if a.get('id')]} (showing first 10)")
        
        for agent in agents_to_check:
            agent_id = agent.get('id')
            agent_name = agent.get('name', 'N/A')
            
            if not agent_id:
                self.logger.warning(f"Skipping agent without ID: {agent}")
                continue
            
            # Convert agent_id to string if it's not already
            agent_id = str(agent_id)
            
            for data_type in data_types:
                tasks.append((agent_id, agent_name, data_type, limit_per_agent))
        
        # Execute tasks in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_task = {
                executor.submit(self._collect_single_agent_data, agent_id, agent_name, data_type, limit_per_agent): 
                (agent_id, agent_name, data_type)
                for agent_id, agent_name, data_type, limit_per_agent in tasks
            }
            
            for future in as_completed(future_to_task, timeout=self.collection_timeout):
                task_info = future_to_task[future]
                agent_id, agent_name, data_type = task_info
                
                try:
                    data = future.result(timeout=30)
                    if data:
                        results[data_type].append({
                            'agent_id': agent_id,
                            'agent_name': agent_name,
                            **data
                        })
                except FutureTimeoutError:
                    self.logger.warning(f"Timeout collecting {data_type} for agent {agent_id} ({agent_name})")
                except Exception as e:
                    self.logger.warning(f"Failed to collect {data_type} for agent {agent_id} ({agent_name}): {e}")
        
        return results
    
    def _collect_single_agent_data(
        self,
        agent_id: str,
        agent_name: str,
        data_type: str,
        limit: int
    ) -> Optional[Dict[str, Any]]:
        """Collect single data type for a single agent
        
        Args:
            agent_id: Agent ID
            agent_name: Agent name
            data_type: Type of data to collect
            limit: Limit for data collection
            
        Returns:
            Dictionary with collected data or None
        """
        try:
            if data_type == 'sca':
                sca_results = self.api_client.get_sca_results(agent_id=agent_id, limit=limit)
                if sca_results:
                    return {'policies': sca_results}
            
            elif data_type == 'syscheck':
                syscheck_results = self.api_client.get_syscheck(agent_id=agent_id, limit=limit)
                last_scan = self.api_client.get_syscheck_last_scan(agent_id=agent_id)
                if syscheck_results or last_scan:
                    return {
                        'findings': syscheck_results[:limit] if syscheck_results else [],
                        'last_scan': last_scan
                    }
            
            elif data_type == 'rootcheck':
                rootcheck = self.api_client.get_rootcheck(agent_id=agent_id, limit=limit)
                if rootcheck:
                    return {'results': rootcheck[:limit]}
            
            elif data_type == 'syscollector':
                hardware = self.api_client.get_syscollector_hardware(agent_id=agent_id)
                network = self.api_client.get_syscollector_network(agent_id=agent_id)
                packages = self.api_client.get_syscollector_packages(agent_id=agent_id, limit=50)
                ports = self.api_client.get_syscollector_ports(agent_id=agent_id, limit=20)
                processes = self.api_client.get_syscollector_processes(agent_id=agent_id, limit=20)
                
                if hardware or network or packages or ports or processes:
                    return {
                        'hardware': hardware,
                        'network_interfaces': network[:5] if network else [],
                        'packages_count': len(packages) if packages else 0,
                        'packages_sample': packages[:10] if packages else [],
                        'listening_ports': ports[:10] if ports else [],
                        'running_processes': processes[:10] if processes else []
                    }
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error collecting {data_type} for agent {agent_id}: {e}")
            return None
    
    def collect_manager_data_parallel(
        self,
        data_types: List[str]
    ) -> Dict[str, Any]:
        """Collect manager-level data in parallel
        
        Args:
            data_types: List of data types ('status', 'stats', 'ciscat')
            
        Returns:
            Dictionary with collected data
        """
        results = {}
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_to_type = {}
            
            if 'status' in data_types:
                future_to_type[executor.submit(self.api_client.get_manager_status)] = 'status'
            
            if 'stats' in data_types:
                future_to_type[executor.submit(self.api_client.get_stats, 'hourly')] = 'stats'
            
            if 'ciscat' in data_types:
                future_to_type[executor.submit(self.api_client.get_ciscat_results, None, 20)] = 'ciscat'
            
            for future in as_completed(future_to_type, timeout=self.collection_timeout):
                data_type = future_to_type[future]
                try:
                    data = future.result(timeout=30)
                    if data:
                        results[data_type] = data
                except FutureTimeoutError:
                    self.logger.warning(f"Timeout collecting manager {data_type}")
                except Exception as e:
                    self.logger.warning(f"Failed to collect manager {data_type}: {e}")
        
        return results



