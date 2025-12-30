"""MITRE ATT&CK enrichment module for Leblebi

This module enriches alerts with MITRE ATT&CK framework information,
providing threat intelligence and attack pattern mapping.
"""

from typing import Dict, List, Any, Optional, Set
from collections import defaultdict
from leblebi.wazuh_api import WazuhAPI


class MITREEnrichment:
    """Enrich alerts with MITRE ATT&CK framework data"""
    
    def __init__(self, api_client: Optional[WazuhAPI] = None):
        """Initialize MITRE enrichment
        
        Args:
            api_client: WazuhAPI instance for fetching MITRE data
        """
        self.api = api_client
        self.enabled = api_client is not None
        
        # Cache for MITRE data
        self._techniques_cache: Dict[str, Dict] = {}
        self._tactics_cache: Dict[str, Dict] = {}
        self._groups_cache: Dict[str, Dict] = {}
        self._mitigations_cache: Dict[str, Dict] = {}
        self._software_cache: Dict[str, Dict] = {}
        
        # Load MITRE data if API is available
        if self.enabled:
            self._load_mitre_data()
    
    def _load_mitre_data(self):
        """Load MITRE ATT&CK data from API"""
        if not self.enabled:
            return
        
        try:
            # Load techniques
            techniques = self.api.get_mitre_techniques(limit=500)
            for technique in techniques:
                tech_id = technique.get('id', '')
                if tech_id:
                    self._techniques_cache[tech_id] = technique
            
            # Load tactics
            tactics = self.api.get_mitre_tactics(limit=100)
            for tactic in tactics:
                tactic_id = tactic.get('id', '')
                if tactic_id:
                    self._tactics_cache[tactic_id] = tactic
            
            # Load groups (APT groups)
            groups = self.api.get_mitre_groups(limit=200)
            for group in groups:
                group_id = group.get('id', '')
                if group_id:
                    self._groups_cache[group_id] = group
            
            # Load mitigations
            mitigations = self.api.get_mitre_mitigations(limit=300)
            for mitigation in mitigations:
                mit_id = mitigation.get('id', '')
                if mit_id:
                    self._mitigations_cache[mit_id] = mitigation
            
            # Load software
            software = self.api.get_mitre_software(limit=300)
            for sw in software:
                sw_id = sw.get('id', '')
                if sw_id:
                    self._software_cache[sw_id] = sw
                    
        except Exception:
            # If MITRE data loading fails, continue without enrichment
            pass
    
    def enrich_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a single alert with MITRE information
        
        Args:
            alert: Alert dictionary
            
        Returns:
            Enriched alert dictionary
        """
        if not self.enabled:
            return alert
        
        rule = alert.get('rule', {})
        mitre_data = rule.get('mitre', {})
        
        # Extract MITRE IDs from alert
        technique_ids = mitre_data.get('technique', []) or []
        tactic_ids = mitre_data.get('tactic', []) or []
        
        enriched_mitre = {
            'techniques': [],
            'tactics': [],
            'groups': [],
            'mitigations': [],
            'software': []
        }
        
        # Enrich techniques
        for tech_id in technique_ids:
            if tech_id in self._techniques_cache:
                tech = self._techniques_cache[tech_id]
                enriched_mitre['techniques'].append({
                    'id': tech_id,
                    'name': tech.get('name', ''),
                    'external_id': tech.get('external_id', ''),
                    'url': tech.get('url', ''),
                    'description': tech.get('description', '')
                })
        
        # Enrich tactics
        for tactic_id in tactic_ids:
            if tactic_id in self._tactics_cache:
                tactic = self._tactics_cache[tactic_id]
                enriched_mitre['tactics'].append({
                    'id': tactic_id,
                    'name': tactic.get('name', ''),
                    'external_id': tactic.get('external_id', ''),
                    'url': tactic.get('url', ''),
                    'description': tactic.get('description', '')
                })
        
        # Find related APT groups based on techniques
        related_groups = self._find_related_groups(technique_ids)
        for group_id in related_groups:
            if group_id in self._groups_cache:
                group = self._groups_cache[group_id]
                enriched_mitre['groups'].append({
                    'id': group_id,
                    'name': group.get('name', ''),
                    'external_id': group.get('external_id', ''),
                    'url': group.get('url', ''),
                    'description': group.get('description', '')
                })
        
        # Find mitigations for techniques
        related_mitigations = self._find_mitigations_for_techniques(technique_ids)
        for mit_id in related_mitigations:
            if mit_id in self._mitigations_cache:
                mitigation = self._mitigations_cache[mit_id]
                enriched_mitre['mitigations'].append({
                    'id': mit_id,
                    'name': mitigation.get('name', ''),
                    'external_id': mitigation.get('external_id', ''),
                    'url': mitigation.get('url', ''),
                    'description': mitigation.get('description', '')
                })
        
        # Add enriched MITRE data to alert
        alert['mitre_enriched'] = enriched_mitre
        
        return alert
    
    def _find_related_groups(self, technique_ids: List[str]) -> Set[str]:
        """Find APT groups that use the given techniques
        
        Args:
            technique_ids: List of MITRE technique IDs
            
        Returns:
            Set of related group IDs
        """
        related_groups = set()
        
        for group_id, group in self._groups_cache.items():
            group_techniques = group.get('techniques', [])
            if any(tech_id in group_techniques for tech_id in technique_ids):
                related_groups.add(group_id)
        
        return related_groups
    
    def _find_mitigations_for_techniques(self, technique_ids: List[str]) -> Set[str]:
        """Find mitigations that apply to the given techniques
        
        Args:
            technique_ids: List of MITRE technique IDs
            
        Returns:
            Set of related mitigation IDs
        """
        related_mitigations = set()
        
        for mit_id, mitigation in self._mitigations_cache.items():
            mit_techniques = mitigation.get('techniques', [])
            if any(tech_id in mit_techniques for tech_id in technique_ids):
                related_mitigations.add(mit_id)
        
        return related_mitigations
    
    def enrich_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich multiple alerts with MITRE information
        
        Args:
            alerts: List of alert dictionaries
            
        Returns:
            List of enriched alert dictionaries
        """
        if not self.enabled:
            return alerts
        
        return [self.enrich_alert(alert) for alert in alerts]
    
    def get_mitre_statistics(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get MITRE statistics from alerts
        
        Args:
            alerts: List of alert dictionaries
            
        Returns:
            Dictionary with MITRE statistics
        """
        if not self.enabled:
            return {}
        
        technique_counts = defaultdict(int)
        tactic_counts = defaultdict(int)
        group_counts = defaultdict(int)
        
        # Also check original MITRE data in rules (before enrichment)
        for alert in alerts:
            # First check enriched data
            mitre_enriched = alert.get('mitre_enriched', {})
            
            # Count techniques from enriched data
            for tech in mitre_enriched.get('techniques', []):
                tech_id = tech.get('external_id') or tech.get('id', '')
                if tech_id:
                    technique_counts[tech_id] += 1
            
            # Count tactics from enriched data
            for tactic in mitre_enriched.get('tactics', []):
                tactic_id = tactic.get('external_id') or tactic.get('id', '')
                if tactic_id:
                    tactic_counts[tactic_id] += 1
            
            # Count groups from enriched data
            for group in mitre_enriched.get('groups', []):
                group_id = group.get('external_id') or group.get('id', '')
                if group_id:
                    group_counts[group_id] += 1
            
            # Also check original MITRE data in rule (if enrichment didn't find it)
            if not mitre_enriched.get('techniques') and not mitre_enriched.get('tactics'):
                rule = alert.get('rule', {})
                mitre_data = rule.get('mitre', {})
                
                # Extract technique IDs from original data
                technique_ids = mitre_data.get('technique', []) or []
                tactic_ids = mitre_data.get('tactic', []) or []
                
                # Count techniques (use ID directly if external_id not available)
                for tech_id in technique_ids:
                    if isinstance(tech_id, str):
                        # Try to extract external_id format (T####)
                        if tech_id.startswith('attack-pattern--'):
                            # This is a full ID, try to find external_id in cache
                            if tech_id in self._techniques_cache:
                                ext_id = self._techniques_cache[tech_id].get('external_id', '')
                                if ext_id:
                                    technique_counts[ext_id] += 1
                            else:
                                # Use ID as-is
                                technique_counts[tech_id] += 1
                        else:
                            technique_counts[tech_id] += 1
                
                # Count tactics
                for tactic_id in tactic_ids:
                    if isinstance(tactic_id, str):
                        if tactic_id.startswith('x-mitre-tactic--'):
                            if tactic_id in self._tactics_cache:
                                ext_id = self._tactics_cache[tactic_id].get('external_id', '')
                                if ext_id:
                                    tactic_counts[ext_id] += 1
                            else:
                                tactic_counts[tactic_id] += 1
                        else:
                            tactic_counts[tactic_id] += 1
        
        return {
            'top_techniques': sorted(
                technique_counts.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10],
            'top_tactics': sorted(
                tactic_counts.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10],
            'top_groups': sorted(
                group_counts.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10],
            'total_techniques': len(technique_counts),
            'total_tactics': len(tactic_counts),
            'total_groups': len(group_counts)
        }
    
    def detect_apt_activity(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect potential APT group activity based on MITRE techniques
        
        Args:
            alerts: List of alert dictionaries
            
        Returns:
            List of detected APT activity information
        """
        if not self.enabled:
            return []
        
        apt_activities = []
        group_alerts = defaultdict(list)
        
        for alert in alerts:
            mitre_enriched = alert.get('mitre_enriched', {})
            groups = mitre_enriched.get('groups', [])
            
            for group in groups:
                group_id = group.get('id', '')
                group_name = group.get('name', '')
                
                if group_id:
                    group_alerts[group_id].append({
                        'alert': alert,
                        'group': group
                    })
        
        # Create APT activity reports
        for group_id, alert_list in group_alerts.items():
            if len(alert_list) >= 2:  # At least 2 alerts for same group
                group_info = alert_list[0]['group']
                apt_activities.append({
                    'group_id': group_id,
                    'group_name': group_info.get('name', ''),
                    'group_url': group_info.get('url', ''),
                    'alert_count': len(alert_list),
                    'techniques': list(set(
                        tech.get('external_id', '') 
                        for alert_data in alert_list 
                        for tech in alert_data['alert'].get('mitre_enriched', {}).get('techniques', [])
                    )),
                    'sample_alerts': alert_list[:5]  # First 5 alerts
                })
        
        return sorted(apt_activities, key=lambda x: x['alert_count'], reverse=True)

