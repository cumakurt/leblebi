"""Agent Health Monitoring module for Leblebi

This module uses Wazuh API to collect agent health information.
It complements log-based alert processing with real-time agent status.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from leblebi.wazuh_api import WazuhAPI


class AgentHealthMonitor:
    """Monitor agent health using Wazuh API"""
    
    def __init__(self, api_client: Optional[WazuhAPI] = None):
        """Initialize agent health monitor
        
        Args:
            api_client: WazuhAPI instance. If None, monitoring is disabled.
        """
        self.api = api_client
        self.enabled = api_client is not None
    
    def get_agent_summary(self) -> Dict[str, Any]:
        """Get summary of all agents
        
        Returns:
            Dictionary with agent statistics
        """
        if not self.enabled:
            return {
                'enabled': False,
                'total': 0,
                'active': 0,
                'disconnected': 0,
                'never_connected': 0,
                'pending': 0
            }
        
        try:
            all_agents = self.api.get_agents(limit=1000)
            active_agents = self.api.get_agents(status='active', limit=1000)
            disconnected_agents = self.api.get_agents(status='disconnected', limit=1000)
            never_connected = self.api.get_agents(status='never_connected', limit=1000)
            pending_agents = self.api.get_agents(status='pending', limit=1000)
            
            return {
                'enabled': True,
                'total': len(all_agents),
                'active': len(active_agents),
                'disconnected': len(disconnected_agents),
                'never_connected': len(never_connected),
                'pending': len(pending_agents),
                'health_percentage': (len(active_agents) / len(all_agents) * 100) if all_agents else 0
            }
        except AttributeError:
            return {
                'enabled': False,
                'error': 'API client error'
            }
        except Exception:
            return {
                'enabled': False,
                'error': 'Failed to fetch agent data'
            }
    
    def get_disconnected_agents(self, hours_threshold: int = 24) -> List[Dict[str, Any]]:
        """Get list of disconnected agents
        
        Args:
            hours_threshold: Consider agents disconnected if offline for more than this many hours
            
        Returns:
            List of disconnected agent information
        """
        if not self.enabled:
            return []
        
        try:
            disconnected = self.api.get_agents(status='disconnected', limit=1000)
            never_connected = self.api.get_agents(status='never_connected', limit=1000)
            
            result = []
            threshold_time = datetime.now() - timedelta(hours=hours_threshold)
            
            for agent in disconnected + never_connected:
                agent_id = agent.get('id', 'N/A')
                agent_name = agent.get('name', 'N/A')
                last_keepalive = agent.get('lastKeepAlive', '')
                
                # Parse last keepalive time
                last_seen = None
                if last_keepalive:
                    try:
                        # Wazuh API returns ISO format
                        last_seen = datetime.fromisoformat(last_keepalive.replace('Z', '+00:00'))
                    except ValueError:
                        # Invalid date format
                        pass
                    except Exception:
                        pass
                
                hours_offline = None
                if last_seen:
                    hours_offline = (datetime.now() - last_seen.replace(tzinfo=None)).total_seconds() / 3600
                
                result.append({
                    'id': agent_id,
                    'name': agent_name,
                    'status': agent.get('status', 'unknown'),
                    'version': agent.get('version', 'N/A'),
                    'last_keepalive': last_keepalive,
                    'hours_offline': hours_offline,
                    'ip': agent.get('ip', 'N/A'),
                    'os': agent.get('os', {}).get('name', 'N/A') if isinstance(agent.get('os'), dict) else 'N/A'
                })
            
            # Sort by hours offline (most critical first)
            result.sort(key=lambda x: x['hours_offline'] if x['hours_offline'] else 0, reverse=True)
            
            return result
        except AttributeError:
            # API client error
            return []
        except Exception:
            return []
    
    def get_agent_details(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific agent
        
        Args:
            agent_id: Agent ID
            
        Returns:
            Detailed agent information or None
        """
        if not self.enabled:
            return None
        
        try:
            return self.api.get_agent_status(agent_id)
        except AttributeError:
            # API client error
            return None
        except Exception:
            return None
    
    def get_agents_by_version(self) -> Dict[str, int]:
        """Get distribution of agents by version
        
        Returns:
            Dictionary mapping version to count
        """
        if not self.enabled:
            return {}
        
        try:
            agents = self.api.get_agents(limit=1000)
            version_counts = {}
            
            for agent in agents:
                version = agent.get('version', 'Unknown')
                version_counts[version] = version_counts.get(version, 0) + 1
            
            return version_counts
        except AttributeError:
            # API client error
            return {}
        except Exception:
            return {}
    
    def get_agents_by_os(self) -> Dict[str, int]:
        """Get distribution of agents by operating system
        
        Returns:
            Dictionary mapping OS to count
        """
        if not self.enabled:
            return {}
        
        try:
            agents = self.api.get_agents(limit=1000)
            os_counts = {}
            
            for agent in agents:
                os_info = agent.get('os', {})
                if isinstance(os_info, dict):
                    os_name = os_info.get('name', 'Unknown')
                else:
                    os_name = 'Unknown'
                
                os_counts[os_name] = os_counts.get(os_name, 0) + 1
            
            return os_counts
        except AttributeError:
            # API client error
            return {}
        except Exception:
            return {}
    
    def get_critical_agents(self) -> List[Dict[str, Any]]:
        """Get agents that need immediate attention
        
        Returns:
            List of critical agents (disconnected > 24h, outdated versions, etc.)
        """
        if not self.enabled:
            return []
        
        critical = []
        
        # Disconnected agents
        disconnected = self.get_disconnected_agents(hours_threshold=24)
        for agent in disconnected:
            if agent.get('hours_offline', 0) > 24:
                critical.append({
                    'id': agent['id'],
                    'name': agent['name'],
                    'issue': f"Disconnected for {agent['hours_offline']:.1f} hours",
                    'severity': 'high' if agent['hours_offline'] > 72 else 'medium',
                    'type': 'disconnected'
                })
        
        return critical



