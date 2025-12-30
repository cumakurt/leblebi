"""Wazuh API client module for Leblebi

This module provides access to Wazuh API for real-time data collection.
It complements the log-based alert processing with live system information.
"""

import json
import base64
import ssl
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta


class WazuhAPI:
    """Wazuh API client for fetching real-time data"""
    
    def __init__(
        self,
        host: str = 'localhost',
        port: int = 55000,
        username: str = 'wazuh',
        password: str = 'wazuh',
        protocol: str = 'https',
        verify_ssl: bool = False
    ):
        """Initialize Wazuh API client
        
        Args:
            host: Wazuh manager hostname or IP
            port: Wazuh API port (default: 55000)
            username: API username
            password: API password
            protocol: http or https
            verify_ssl: Verify SSL certificates (default: False for self-signed)
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.protocol = protocol
        self.verify_ssl = verify_ssl
        self.base_url = f"{protocol}://{host}:{port}"
        self.token = None
        self.token_expires = None
        
        # Create SSL context once for reuse
        if not verify_ssl:
            self.ssl_context = ssl.create_default_context()
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
        else:
            self.ssl_context = None
        
    def _authenticate(self) -> bool:
        """Authenticate with Wazuh API and get token
        
        Returns:
            True if authentication successful, False otherwise
        """
        try:
            auth_url = f"{self.base_url}/security/user/authenticate"
            credentials = f"{self.username}:{self.password}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            
            req = urllib.request.Request(auth_url)
            req.add_header('Authorization', f'Basic {encoded_credentials}')
            req.add_header('Content-Type', 'application/json')
            
            with urllib.request.urlopen(req, context=self.ssl_context, timeout=10) as response:
                data = json.loads(response.read().decode())
                self.token = data.get('data', {}).get('token')
                
                # Try to get token expiration from response, default to 14 minutes
                expires_in = data.get('data', {}).get('expires_in', 840)  # Default 14 minutes in seconds
                if isinstance(expires_in, int):
                    # Refresh token 1 minute before expiration for safety
                    self.token_expires = datetime.now() + timedelta(seconds=expires_in - 60)
                else:
                    # Fallback to 14 minutes if expiration not provided
                    self.token_expires = datetime.now() + timedelta(minutes=14)
                
                return self.token is not None
        except urllib.error.HTTPError as e:
            # Authentication failed - HTTP error
            return False
        except urllib.error.URLError as e:
            # Network error
            return False
        except json.JSONDecodeError as e:
            # Invalid JSON response
            return False
        except (ValueError, KeyError) as e:
            # Invalid response structure
            return False
        except Exception as e:
            # Other unexpected errors
            return False
    
    def _get_token(self) -> Optional[str]:
        """Get valid authentication token with automatic refresh
        
        Returns:
            Valid token string or None if authentication fails
        """
        # Check if token exists and is still valid (with 30 second buffer)
        if (self.token and self.token_expires and 
            datetime.now() < (self.token_expires - timedelta(seconds=30))):
            return self.token
        
        # Token expired or doesn't exist, authenticate
        if not self._authenticate():
            return None
        
        return self.token
    
    def _make_request(
        self,
        endpoint: str,
        method: str = 'GET',
        params: Optional[Dict] = None,
        body: Optional[Dict] = None
    ) -> Optional[Dict]:
        """Make API request to Wazuh"""
        token = self._get_token()
        if not token:
            return None
        
        url = f"{self.base_url}{endpoint}"
        if params:
            url += '?' + urllib.parse.urlencode(params)
        
        req = urllib.request.Request(url)
        req.add_header('Authorization', f'Bearer {token}')
        req.add_header('Content-Type', 'application/json')
        req.method = method
        
        if body:
            req.data = json.dumps(body).encode()
        
        try:
            with urllib.request.urlopen(req, context=self.ssl_context, timeout=30) as response:
                return json.loads(response.read().decode())
        except urllib.error.HTTPError as e:
            # API might return error in response body
            try:
                error_body = e.read()
                if error_body:
                    error_data = json.loads(error_body.decode())
                    return error_data
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Invalid JSON or encoding in error response
                pass
            except AttributeError:
                # Error response doesn't have read() method
                pass
            return None
        except urllib.error.URLError as e:
            # Network error (connection refused, timeout, etc.)
            return None
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            # Invalid JSON response or encoding issue
            return None
        except (ValueError, KeyError) as e:
            # Invalid response structure
            return None
        except Exception as e:
            # Other unexpected errors - log but don't expose
            return None
    
    def get_agents(
        self,
        status: Optional[str] = None,
        limit: int = 500,
        offset: int = 0
    ) -> List[Dict]:
        """Get list of agents
        
        Args:
            status: Filter by status (active, disconnected, never_connected, pending)
            limit: Maximum number of results
            offset: Offset for pagination
            
        Returns:
            List of agent dictionaries
        """
        params = {
            'limit': limit,
            'offset': offset
        }
        if status:
            params['status'] = status
        
        response = self._make_request('/agents', params=params)
        if response and 'data' in response:
            return response['data'].get('affected_items', [])
        return []
    
    def get_agent_status(self, agent_id: str) -> Optional[Dict]:
        """Get detailed status of a specific agent"""
        response = self._make_request(f'/agents/{agent_id}')
        if response and 'data' in response:
            return response['data'].get('affected_items', [{}])[0]
        return None
    
    def get_manager_status(self) -> Optional[Dict]:
        """Get Wazuh manager status and statistics"""
        response = self._make_request('/manager/status')
        if response and 'data' in response:
            return response['data']
        return None
    
    def get_manager_configuration(self) -> Optional[Dict]:
        """Get manager configuration"""
        response = self._make_request('/manager/configuration')
        if response and 'data' in response:
            return response['data']
        return None
    
    def get_cluster_status(self) -> Optional[Dict]:
        """Get cluster status (if cluster is enabled)"""
        response = self._make_request('/cluster/status')
        if response and 'data' in response:
            return response['data']
        return None
    
    def get_rules(self, limit: int = 100) -> List[Dict]:
        """Get list of rules"""
        params = {'limit': limit}
        response = self._make_request('/rules', params=params)
        if response and 'data' in response:
            return response['data'].get('affected_items', [])
        return []
    
    def get_decoders(self, limit: int = 100) -> List[Dict]:
        """Get list of decoders"""
        params = {'limit': limit}
        response = self._make_request('/decoders', params=params)
        if response and 'data' in response:
            return response['data'].get('affected_items', [])
        return []
    
    def get_rootcheck(
        self,
        agent_id: str,
        limit: int = 100
    ) -> List[Dict]:
        """Get rootcheck results for an agent"""
        params = {'limit': limit}
        response = self._make_request(f'/rootcheck/{agent_id}', params=params)
        if response and 'data' in response:
            return response['data'].get('affected_items', [])
        return []
    
    def get_syscollector(
        self,
        agent_id: str,
        component: Optional[str] = None
    ) -> Optional[Dict]:
        """Get system collector information for an agent
        
        Args:
            agent_id: Agent ID
            component: Optional component (hardware, network, os, packages, ports, processes)
        """
        if component:
            endpoint = f'/syscollector/{agent_id}/{component}'
        else:
            endpoint = f'/syscollector/{agent_id}'
        
        response = self._make_request(endpoint)
        if response and 'data' in response:
            return response['data']
        return None
    
    def get_active_responses(
        self,
        limit: int = 100
    ) -> List[Dict]:
        """Get active response logs"""
        params = {'limit': limit}
        response = self._make_request('/active-response', params=params)
        if response and 'data' in response:
            return response['data'].get('affected_items', [])
        return []
    
    def get_stats(self, component: str = 'hourly') -> Optional[Dict]:
        """Get statistics
        
        Args:
            component: Statistics component (hourly, weekly, monthly, agents, rules)
        """
        response = self._make_request(f'/stats/{component}')
        if response and 'data' in response:
            return response['data']
        return None
    
    def get_alerts(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 1000
    ) -> List[Dict]:
        """Get alerts from API with time filtering
        
        Note: Wazuh API may not have a direct /events endpoint for alerts.
        Alerts are typically stored in alerts.json file. This function attempts
        to fetch events, but may return empty if endpoint is not available.
        
        Args:
            start_time: Filter alerts after this time
            end_time: Filter alerts before this time
            limit: Maximum number of alerts to return
        """
        # Wazuh API doesn't have a standard /events endpoint for alerts
        # Alerts are typically read from alerts.json file
        # However, we can try to get recent events/security events
        
        params = {'limit': limit}
        
        # Try to add time filters if provided
        # Note: Wazuh API time filtering may use different parameter names
        if start_time:
            # Try different date parameter formats
            date_str = start_time.strftime('%Y-%m-%dT%H:%M:%S')
            params['date_from'] = date_str
            params['date'] = date_str  # Alternative parameter name
        
        if end_time:
            date_str = end_time.strftime('%Y-%m-%dT%H:%M:%S')
            params['date_to'] = date_str
        
        # Try /events endpoint (may not be available in all Wazuh versions)
        response = self._make_request('/events', params=params)
        
        if response:
            # Check for errors
            if isinstance(response, dict) and 'error' in response:
                error_info = response.get('error', {})
                error_code = error_info.get('code', 'Unknown')
                error_msg = error_info.get('message', 'Unknown error')
                # Log but don't fail - this endpoint may not be available
                return []
            
            # Check for data
            if isinstance(response, dict) and 'data' in response:
                items = response['data'].get('affected_items', [])
                if items:
                    return items
            
            # Some API versions return list directly
            if isinstance(response, list):
                return response
        
        # /events endpoint may not be available
        # Return empty list - alerts should be read from alerts.json file
        return []
    
    def get_sca_results(
        self,
        agent_id: str,
        limit: int = 100
    ) -> List[Dict]:
        """Get SCA (Security Configuration Assessment) results for an agent
        
        Args:
            agent_id: Agent ID
            limit: Maximum number of results
            
        Returns:
            List of SCA policy results
        """
        params = {'limit': limit}
        response = self._make_request(f'/sca/{agent_id}', params=params)
        if response and 'data' in response:
            return response['data'].get('affected_items', [])
        return []
    
    def get_sca_checks(
        self,
        agent_id: str,
        policy_id: str,
        limit: int = 100
    ) -> List[Dict]:
        """Get SCA policy checks for an agent
        
        Args:
            agent_id: Agent ID
            policy_id: Policy ID
            limit: Maximum number of results
            
        Returns:
            List of SCA check results
        """
        params = {'limit': limit}
        response = self._make_request(f'/sca/{agent_id}/checks/{policy_id}', params=params)
        if response and 'data' in response:
            return response['data'].get('affected_items', [])
        return []
    
    def get_syscheck(
        self,
        agent_id: str,
        limit: int = 100
    ) -> List[Dict]:
        """Get syscheck (FIM - File Integrity Monitoring) results for an agent
        
        Args:
            agent_id: Agent ID
            limit: Maximum number of results
            
        Returns:
            List of FIM findings
        """
        params = {'limit': limit}
        response = self._make_request(f'/syscheck/{agent_id}', params=params)
        if response and 'data' in response:
            return response['data'].get('affected_items', [])
        return []
    
    def get_syscheck_last_scan(
        self,
        agent_id: str
    ) -> Optional[Dict]:
        """Get last syscheck scan datetime for an agent
        
        Args:
            agent_id: Agent ID
            
        Returns:
            Dictionary with start and end scan times
        """
        response = self._make_request(f'/syscheck/{agent_id}/last_scan')
        if response and 'data' in response:
            items = response['data'].get('affected_items', [])
            if items:
                return items[0]
        return None
    
    def get_ciscat_results(
        self,
        agents_list: Optional[List[str]] = None,
        limit: int = 100
    ) -> List[Dict]:
        """Get CIS-CAT compliance results for agents
        
        Args:
            agents_list: Optional list of agent IDs (comma-separated string or list)
            limit: Maximum number of results
            
        Returns:
            List of CIS-CAT results
        """
        params = {'limit': limit}
        if agents_list:
            if isinstance(agents_list, list):
                agents_list = ','.join(agents_list)
            params['agents_list'] = agents_list
        
        response = self._make_request('/experimental/ciscat/results', params=params)
        if response and 'data' in response:
            return response['data'].get('affected_items', [])
        return []
    
    def get_syscollector_hardware(
        self,
        agent_id: str
    ) -> Optional[Dict]:
        """Get hardware information from syscollector for an agent
        
        Args:
            agent_id: Agent ID
            
        Returns:
            Hardware information dictionary
        """
        response = self._make_request(f'/syscollector/{agent_id}/hardware')
        if response and 'data' in response:
            items = response['data'].get('affected_items', [])
            if items:
                return items[0]
        return None
    
    def get_syscollector_network(
        self,
        agent_id: str
    ) -> List[Dict]:
        """Get network information from syscollector for an agent
        
        Args:
            agent_id: Agent ID
            
        Returns:
            List of network interfaces
        """
        response = self._make_request(f'/syscollector/{agent_id}/network')
        if response and 'data' in response:
            return response['data'].get('affected_items', [])
        return []
    
    def get_syscollector_packages(
        self,
        agent_id: str,
        limit: int = 100
    ) -> List[Dict]:
        """Get installed packages from syscollector for an agent
        
        Args:
            agent_id: Agent ID
            limit: Maximum number of results
            
        Returns:
            List of installed packages
        """
        params = {'limit': limit}
        response = self._make_request(f'/syscollector/{agent_id}/packages', params=params)
        if response and 'data' in response:
            return response['data'].get('affected_items', [])
        return []
    
    def get_syscollector_ports(
        self,
        agent_id: str,
        limit: int = 100
    ) -> List[Dict]:
        """Get listening ports from syscollector for an agent
        
        Args:
            agent_id: Agent ID
            limit: Maximum number of results
            
        Returns:
            List of listening ports
        """
        params = {'limit': limit}
        response = self._make_request(f'/syscollector/{agent_id}/ports', params=params)
        if response and 'data' in response:
            return response['data'].get('affected_items', [])
        return []
    
    def get_syscollector_processes(
        self,
        agent_id: str,
        limit: int = 100
    ) -> List[Dict]:
        """Get running processes from syscollector for an agent
        
        Args:
            agent_id: Agent ID
            limit: Maximum number of results
            
        Returns:
            List of running processes
        """
        params = {'limit': limit}
        response = self._make_request(f'/syscollector/{agent_id}/processes', params=params)
        if response and 'data' in response:
            return response['data'].get('affected_items', [])
        return []
    
    def get_agents_summary(self) -> Optional[Dict]:
        """Get agents summary information
        
        Returns:
            Dictionary with agent summary statistics
        """
        response = self._make_request('/agents/summary')
        if response and 'data' in response:
            return response['data']
        return None
    
    def get_agents_summary_status(self) -> Optional[Dict]:
        """Get agents summary by status
        
        Returns:
            Dictionary with agent status summary
        """
        response = self._make_request('/agents/summary/status')
        if response and 'data' in response:
            return response['data']
        return None
    
    def get_agents_summary_os(self) -> Optional[Dict]:
        """Get agents summary by operating system
        
        Returns:
            Dictionary with agent OS distribution
        """
        response = self._make_request('/agents/summary/os')
        if response and 'data' in response:
            return response['data']
        return None
    
    def get_outdated_agents(self, limit: int = 100) -> List[Dict]:
        """Get list of outdated agents
        
        Args:
            limit: Maximum number of results
            
        Returns:
            List of outdated agent information
        """
        params = {'limit': limit}
        response = self._make_request('/agents/outdated', params=params)
        if response and 'data' in response:
            return response['data'].get('affected_items', [])
        return []
    
    def get_upgrade_results(self, limit: int = 100) -> List[Dict]:
        """Get agent upgrade results
        
        Args:
            limit: Maximum number of results
            
        Returns:
            List of upgrade result information
        """
        params = {'limit': limit}
        response = self._make_request('/agents/upgrade_result', params=params)
        if response and 'data' in response:
            return response['data'].get('affected_items', [])
        return []
    
    def get_mitre_groups(
        self,
        group_ids: Optional[List[str]] = None,
        limit: int = 100
    ) -> List[Dict]:
        """Get MITRE ATT&CK groups (APT groups)
        
        Args:
            group_ids: Optional list of specific group IDs to filter
            limit: Maximum number of results
            
        Returns:
            List of MITRE group information
        """
        params = {'limit': limit}
        if group_ids:
            params['group_ids'] = ','.join(group_ids)
        
        response = self._make_request('/mitre/groups', params=params)
        if response and 'data' in response:
            return response['data'].get('affected_items', [])
        return []
    
    def get_mitre_techniques(
        self,
        technique_ids: Optional[List[str]] = None,
        limit: int = 100
    ) -> List[Dict]:
        """Get MITRE ATT&CK techniques
        
        Args:
            technique_ids: Optional list of specific technique IDs to filter
            limit: Maximum number of results
            
        Returns:
            List of MITRE technique information
        """
        params = {'limit': limit}
        if technique_ids:
            params['technique_ids'] = ','.join(technique_ids)
        
        response = self._make_request('/mitre/techniques', params=params)
        if response and 'data' in response:
            return response['data'].get('affected_items', [])
        return []
    
    def get_mitre_tactics(
        self,
        tactic_ids: Optional[List[str]] = None,
        limit: int = 100
    ) -> List[Dict]:
        """Get MITRE ATT&CK tactics
        
        Args:
            tactic_ids: Optional list of specific tactic IDs to filter
            limit: Maximum number of results
            
        Returns:
            List of MITRE tactic information
        """
        params = {'limit': limit}
        if tactic_ids:
            params['tactic_ids'] = ','.join(tactic_ids)
        
        response = self._make_request('/mitre/tactics', params=params)
        if response and 'data' in response:
            return response['data'].get('affected_items', [])
        return []
    
    def get_mitre_mitigations(
        self,
        mitigation_ids: Optional[List[str]] = None,
        limit: int = 100
    ) -> List[Dict]:
        """Get MITRE ATT&CK mitigations
        
        Args:
            mitigation_ids: Optional list of specific mitigation IDs to filter
            limit: Maximum number of results
            
        Returns:
            List of MITRE mitigation information
        """
        params = {'limit': limit}
        if mitigation_ids:
            params['mitigation_ids'] = ','.join(mitigation_ids)
        
        response = self._make_request('/mitre/mitigations', params=params)
        if response and 'data' in response:
            return response['data'].get('affected_items', [])
        return []
    
    def get_mitre_software(
        self,
        software_ids: Optional[List[str]] = None,
        limit: int = 100
    ) -> List[Dict]:
        """Get MITRE ATT&CK software (malware/tools)
        
        Args:
            software_ids: Optional list of specific software IDs to filter
            limit: Maximum number of results
            
        Returns:
            List of MITRE software information
        """
        params = {'limit': limit}
        if software_ids:
            params['software_ids'] = ','.join(software_ids)
        
        response = self._make_request('/mitre/software', params=params)
        if response and 'data' in response:
            return response['data'].get('affected_items', [])
        return []
    
    def get_mitre_references(
        self,
        reference_ids: Optional[List[str]] = None,
        limit: int = 100
    ) -> List[Dict]:
        """Get MITRE ATT&CK references
        
        Args:
            reference_ids: Optional list of specific reference IDs to filter
            limit: Maximum number of results
            
        Returns:
            List of MITRE reference information
        """
        params = {'limit': limit}
        if reference_ids:
            params['reference_ids'] = ','.join(reference_ids)
        
        response = self._make_request('/mitre/references', params=params)
        if response and 'data' in response:
            return response['data'].get('affected_items', [])
        return []
    
    def get_mitre_metadata(self) -> Optional[Dict]:
        """Get MITRE ATT&CK metadata
        
        Returns:
            Dictionary with MITRE metadata (version, etc.)
        """
        response = self._make_request('/mitre/metadata')
        if response and 'data' in response:
            items = response['data'].get('affected_items', [])
            if items:
                return {item.get('key'): item.get('value') for item in items}
        return None
    
    def get_vulnerability_data(
        self,
        agent_id: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        """Get vulnerability detection data from agent stats
        
        Note: Vulnerability data is available in agent statistics.
        This method attempts to extract vulnerability information.
        
        Args:
            agent_id: Optional agent ID to filter
            limit: Maximum number of results
            
        Returns:
            List of vulnerability information
        """
        # Vulnerability data is typically in agent stats
        # We'll need to get agent stats and extract vulnerability info
        if agent_id:
            agent_status = self.get_agent_status(agent_id)
            if agent_status:
                stats = agent_status.get('stats', {})
                vulnerability = stats.get('vulnerability', {})
                if vulnerability:
                    return [{'agent_id': agent_id, 'vulnerability': vulnerability}]
        return []
    
    def test_connection(self) -> bool:
        """Test API connection"""
        return self._authenticate()


