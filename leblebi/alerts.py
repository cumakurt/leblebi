"""Alert processing and analysis module for Leblebi"""

import json
import gzip
import re
import os
import random
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from collections import Counter, defaultdict
from datetime import datetime, timezone

# Try to import ijson for streaming JSON parsing
try:
    import ijson
    IJSON_AVAILABLE = True
except ImportError:
    IJSON_AVAILABLE = False


class AlertProcessor:
    """Process and analyze Wazuh alerts"""
    
    def __init__(self, level: int = None, config: Optional[Any] = None):
        """Initialize alert processor
        
        Args:
            level: Alert level threshold (defaults to AlertLevels.CRITICAL_THRESHOLD_DEFAULT)
            config: Optional configuration object for accessing config values
        """
        from leblebi.constants import AlertLevels
        
        if level is None:
            level = AlertLevels.CRITICAL_THRESHOLD_DEFAULT
        self.level = level
        self.alerts: List[Dict[str, Any]] = []
        self.config = config
        # Set attack timeline defaults from config if available
        if config:
            self._attack_timeline_min_level = config.get('attack_timeline_min_level', 12)
            self._attack_timeline_limit = config.get('attack_timeline_limit', 500)
        else:
            from leblebi.constants import AlertLevels
            self._attack_timeline_min_level = AlertLevels.ATTACK_TIMELINE_MIN_LEVEL_DEFAULT
            self._attack_timeline_limit = 500
    
    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Fast timestamp parsing with error handling"""
        if not timestamp_str:
            return None
        
        try:
            # Most common format: ISO with Z
            timestamp_clean = timestamp_str.replace('Z', '+00:00')
            alert_time = datetime.fromisoformat(timestamp_clean)
            
            # Normalize to UTC for comparison
            if alert_time.tzinfo is not None:
                alert_time = alert_time.astimezone(timezone.utc).replace(tzinfo=None)
            
            return alert_time
        except (ValueError, AttributeError):
            # Try alternative formats
            try:
                # Try without timezone
                return datetime.fromisoformat(timestamp_str.split('+')[0].split('Z')[0])
            except (ValueError, AttributeError, IndexError):
                return None
    
    def _should_include_alert(
        self,
        alert: Dict[str, Any],
        start_time: Optional[datetime],
        end_time: Optional[datetime],
        sample_rate: float = 1.0
    ) -> bool:
        """Check if alert should be included based on filters (early filtering)"""
        if not alert or alert is None:
            return False
        
        # Sampling for very large datasets
        if sample_rate < 1.0 and random.random() > sample_rate:
            return False
        
        # Early time filtering (most important optimization)
        if start_time or end_time:
            timestamp = alert.get('timestamp', '')
            if not timestamp:
                return False
            
            alert_time = self._parse_timestamp(timestamp)
            if alert_time is None:
                # Invalid timestamp - include to avoid data loss
                return True
            
            # Normalize start_time and end_time to UTC if timezone-aware
            start_compare = start_time
            end_compare = end_time
            if start_time and start_time.tzinfo is not None:
                start_compare = start_time.astimezone(timezone.utc).replace(tzinfo=None)
            if end_time and end_time.tzinfo is not None:
                end_compare = end_time.astimezone(timezone.utc).replace(tzinfo=None)
            
            if start_compare and alert_time < start_compare:
                return False
            if end_compare and alert_time > end_compare:
                return False
        
        return True
    
    def load_alerts(
        self,
        file_path: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_alerts: Optional[int] = None,
        sample_rate: float = 1.0,
        use_streaming: bool = True
    ) -> int:
        """Load alerts from JSON file with streaming, early filtering, and sampling
        
        Optimized for large files (200GB+ daily logs):
        - Streaming JSON parsing (memory-efficient)
        - Early filtering (filter during read, not after)
        - Sampling support for very large datasets
        - Chunk-based processing
        
        Args:
            file_path: Path to alerts JSON file
            start_time: Filter alerts after this time (inclusive)
            end_time: Filter alerts before this time (inclusive)
            max_alerts: Maximum number of alerts to process (0 = unlimited)
            sample_rate: Sampling rate (0.0-1.0, 1.0 = process all)
            use_streaming: Use streaming parser if available (default: True)
        """
        alerts = []
        total_read = 0
        is_gzipped = False
        
        # Check for gzipped file
        if not os.path.exists(file_path):
            if os.path.exists(f"{file_path}.gz"):
                file_path = f"{file_path}.gz"
                is_gzipped = True
            else:
                raise FileNotFoundError(f"Alert file not found: {file_path}")
        
        # Check if file is gzipped by extension or magic bytes
        if not is_gzipped and file_path.endswith('.gz'):
            is_gzipped = True
        
        try:
            # Open file (gzipped or regular)
            if is_gzipped:
                # Open gzip file in binary mode first, then decode
                file_handle = gzip.open(file_path, 'rb')
                # Wrap with TextIOWrapper for text reading
                import io
                file_handle = io.TextIOWrapper(file_handle, encoding='utf-8', errors='replace')
            else:
                file_handle = open(file_path, 'r', encoding='utf-8', errors='replace')
            
            with file_handle as f:
                # Peek first character to determine format
                first_char = f.read(1)
                f.seek(0)
                
                if first_char == '[':
                    # Array format - use streaming parser if available
                    if use_streaming and IJSON_AVAILABLE:
                        # Use ijson for streaming JSON array parsing
                        try:
                            parser = ijson.items(f, 'item')
                            for alert in parser:
                                total_read += 1
                                if self._should_include_alert(alert, start_time, end_time, sample_rate):
                                    alerts.append(alert)
                                    if max_alerts and len(alerts) >= max_alerts:
                                        break
                        except Exception as e:
                            # Fallback to line-by-line if streaming fails
                            f.seek(0)
                            first_char = f.read(1)
                            f.seek(0)
                            # Fall through to line-by-line processing
                            use_streaming = False
                    
                    if not use_streaming or not IJSON_AVAILABLE:
                        # Fallback: Load entire array (less memory-efficient but reliable)
                        # For very large files, recommend installing ijson
                        try:
                            all_alerts = json.load(f)
                            if isinstance(all_alerts, list):
                                for alert in all_alerts:
                                    total_read += 1
                                    if self._should_include_alert(alert, start_time, end_time, sample_rate):
                                        alerts.append(alert)
                                        if max_alerts and len(alerts) >= max_alerts:
                                            break
                        except json.JSONDecodeError as e:
                            # If JSON parsing fails, try line-by-line as fallback
                            f.seek(0)
                            # Skip opening bracket
                            f.read(1)
                            buffer = ""
                            for line in f:
                                line = line.strip().rstrip(',')
                                if not line or line == ']':
                                    continue
                                try:
                                    alert = json.loads(line)
                                    total_read += 1
                                    if self._should_include_alert(alert, start_time, end_time, sample_rate):
                                        alerts.append(alert)
                                        if max_alerts and len(alerts) >= max_alerts:
                                            break
                                except json.JSONDecodeError:
                                    continue
                else:
                    # Newline-delimited format - stream line by line (most memory-efficient)
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        
                        total_read += 1
                        try:
                            alert = json.loads(line)
                            if self._should_include_alert(alert, start_time, end_time, sample_rate):
                                alerts.append(alert)
                                if max_alerts and len(alerts) >= max_alerts:
                                    break
                        except json.JSONDecodeError:
                            # Skip invalid JSON lines
                            continue
        
        except FileNotFoundError:
            raise FileNotFoundError(f"Alert file not found: {file_path}")
        except gzip.BadGzipFile:
            raise FileNotFoundError(f"Invalid gzip file: {file_path}")
        except Exception as e:
            raise Exception(f"Error reading alert file {file_path}: {e}")
        
        # Filter out None values
        alerts = [a for a in alerts if a is not None]
        
        self.alerts = alerts
        return len(self.alerts)
    
    def load_alerts_from_multiple_files(
        self,
        file_paths: List[str],
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_alerts: Optional[int] = None,
        sample_rate: float = 1.0,
        use_streaming: bool = True
    ) -> int:
        """Load alerts from multiple files (for Wazuh log structure)
        
        Memory-efficient processing: Each file is processed separately and alerts
        are accumulated incrementally to minimize memory usage.
        
        Args:
            file_paths: List of alert file paths to load
            start_time: Filter alerts after this time (inclusive)
            end_time: Filter alerts before this time (inclusive)
            max_alerts: Maximum number of alerts to process (0 = unlimited)
            sample_rate: Sampling rate (0.0-1.0, 1.0 = process all)
            use_streaming: Use streaming parser if available (default: True)
            
        Returns:
            Total number of alerts loaded
        """
        all_alerts = []
        
        for file_idx, file_path in enumerate(file_paths, 1):
            if not os.path.exists(file_path):
                continue  # Skip missing files
            
            try:
                # Load alerts from this file using the single-file method
                # This reuses the optimized load_alerts method
                file_alerts_before = len(all_alerts)
                
                # Calculate remaining alerts limit
                remaining_limit = None
                if max_alerts:
                    remaining_limit = max_alerts - len(all_alerts)
                    if remaining_limit <= 0:
                        break  # Already reached limit
                
                # Use load_alerts for this single file (memory-efficient)
                # We'll merge the alerts after
                temp_processor = AlertProcessor(level=self.level)
                alerts_count = temp_processor.load_alerts(
                    file_path,
                    start_time=start_time,
                    end_time=end_time,
                    max_alerts=remaining_limit,
                    sample_rate=sample_rate,
                    use_streaming=use_streaming
                )
                
                # Merge alerts from this file
                all_alerts.extend(temp_processor.alerts)
                
                # Clear temp processor to free memory
                del temp_processor
                
                # Stop if we've reached max_alerts
                if max_alerts and len(all_alerts) >= max_alerts:
                    break
                    
            except MemoryError as e:
                # Memory error - suggest optimizations
                import sys
                error_msg = (
                    f"Memory error processing {os.path.basename(file_path)}!\n"
                    f"File {file_idx}/{len(file_paths)}: {file_path}\n"
                    f"Suggestions:\n"
                    f"  1. Set max_alerts_to_process in config.conf (e.g., 1000000)\n"
                    f"  2. Enable sampling_enabled = true in config.conf\n"
                    f"  3. Install ijson: pip install ijson\n"
                    f"  4. Process fewer days (reduce report_period)"
                )
                print(f"ERROR: {error_msg}", file=sys.stderr)
                raise MemoryError(error_msg) from e
            except Exception as e:
                # Log error but continue with other files
                import sys
                print(f"Warning: Failed to load alerts from {file_path}: {e}", file=sys.stderr)
                continue
        
        # Filter out None values
        all_alerts = [a for a in all_alerts if a is not None]
        
        self.alerts = all_alerts
        return len(self.alerts)
    
    def get_rule_level(self, alert: Dict[str, Any]) -> int:
        """Extract rule level from alert"""
        rule = alert.get('rule', {})
        level = rule.get('level')
        if isinstance(level, (int, float)):
            return int(level)
        return 0
    
    def filter_critical(self, alerts: Optional[List[Dict]] = None) -> List[Dict]:
        """Filter critical alerts (level >= threshold)"""
        if alerts is None:
            alerts = self.alerts
        return [
            a for a in alerts
            if self.get_rule_level(a) >= self.level
        ]
    
    def filter_non_critical(self, alerts: Optional[List[Dict]] = None) -> List[Dict]:
        """Filter non-critical alerts (level < threshold)"""
        if alerts is None:
            alerts = self.alerts
        return [
            a for a in alerts
            if self.get_rule_level(a) < self.level
        ]
    
    def get_top_alerts_by_rule(
        self,
        alerts: List[Dict],
        top_n: int = 100
    ) -> List[Tuple[int, int, str, str]]:
        """Get top alerts grouped by rule (count, level, rule_id, description)"""
        rule_counts = Counter()
        
        for alert in alerts:
            rule = alert.get('rule', {})
            level = self.get_rule_level(alert)
            rule_id = rule.get('id', 'N/A')
            description = rule.get('description', 'N/A')
            
            if rule_id != 'N/A':
                rule_counts[(level, rule_id, description)] += 1
        
        # Sort by count descending
        top_rules = rule_counts.most_common(top_n)
        return [(count, level, rule_id, desc) for (level, rule_id, desc), count in top_rules]
    
    def get_top_agents(self, top_n: int = None) -> List[Tuple[int, str]]:
        """Get top alerting agents"""
        agent_counts = Counter()
        
        for alert in self.alerts:
            agent = alert.get('agent', {})
            agent_name = agent.get('name') or agent.get('id') or 'Unknown'
            agent_counts[agent_name] += 1
        
        return [(count, name) for name, count in agent_counts.most_common(top_n)]
    
    def get_alert_categories(self, top_n: int = 10) -> List[Tuple[int, str]]:
        """Get alert categories distribution"""
        categories = []
        
        for alert in self.alerts:
            rule = alert.get('rule', {})
            groups = rule.get('groups', [])
            if isinstance(groups, list):
                categories.extend(groups)
        
        category_counts = Counter(categories)
        return [(count, cat) for cat, count in category_counts.most_common(top_n)]
    
    def get_hourly_distribution(self) -> Dict[int, int]:
        """Get hourly alert distribution"""
        hourly = defaultdict(int)
        
        for alert in self.alerts:
            timestamp = alert.get('timestamp', '')
            try:
                # Parse ISO format timestamp
                timestamp_clean = timestamp.replace('Z', '+00:00')
                dt = datetime.fromisoformat(timestamp_clean)
                hour = dt.hour
                hourly[hour] += 1
            except ValueError:
                # Invalid timestamp format, skip
                continue
            except Exception:
                # Other parsing errors, skip
                continue
        
        return dict(hourly)
    
    def get_highest_level_alerts(self, top_n: int = None) -> List[Dict]:
        """Get highest severity alerts"""
        critical = self.filter_critical()
        critical.sort(key=self.get_rule_level, reverse=True)
        return critical[:top_n]
    
    def calculate_risk_score(self) -> Tuple[int, Dict[str, int]]:
        """Calculate risk score and alert counts by severity
        
        More realistic risk scoring:
        - Critical alerts (level >= threshold): Higher weight but logarithmic scaling
        - High alerts (8-11): Moderate weight
        - Medium alerts (5-7): Low weight
        - Low alerts (<5): Minimal weight, only unique rules count
        """
        critical = self.filter_critical()
        from leblebi.constants import AlertLevels
        
        high = [
            a for a in self.alerts
            if AlertLevels.HIGH_MIN <= self.get_rule_level(a) < self.level
        ]
        medium = [
            a for a in self.alerts
            if AlertLevels.MEDIUM_MIN <= self.get_rule_level(a) < AlertLevels.MEDIUM_MAX + 1
        ]
        low = [
            a for a in self.alerts
            if self.get_rule_level(a) <= AlertLevels.LOW_MAX
        ]
        
        counts = {
            'critical': len(critical),
            'high': len(high),
            'medium': len(medium),
            'low': len(low)
        }
        
        # More realistic risk scoring with logarithmic scaling for critical
        import math
        from leblebi.constants import RiskScoring
        
        # Critical: Use logarithmic scale to prevent false positives
        # Base score for first critical, then logarithmic growth
        critical_score = 0
        if counts['critical'] > 0:
            critical_score = RiskScoring.CRITICAL_BASE_SCORE + int(
                math.log(counts['critical'] + 1) * RiskScoring.CRITICAL_LOG_MULTIPLIER
            )
            # Cap at max to prevent extreme scores
            critical_score = min(critical_score, RiskScoring.CRITICAL_MAX_SCORE)
        
        # High: Moderate weight, but less aggressive
        high_score = counts['high'] * RiskScoring.HIGH_MULTIPLIER
        
        # Medium: Low weight
        medium_score = counts['medium'] * RiskScoring.MEDIUM_MULTIPLIER
        
        # Low: Only count unique rules, not all alerts (prevents false positives from noise)
        unique_low_rules = len(set(
            a.get('rule', {}).get('id', 'N/A')
            for a in low
            if a.get('rule', {}).get('id', 'N/A') != 'N/A'
        ))
        low_score = min(unique_low_rules * RiskScoring.LOW_MULTIPLIER, RiskScoring.LOW_MAX_SCORE)
        
        risk_score = int(critical_score + high_score + medium_score + low_score)
        
        return risk_score, counts
    
    def get_unique_rules(self) -> int:
        """Get count of unique rule IDs"""
        rule_ids = set()
        for alert in self.alerts:
            rule = alert.get('rule', {})
            rule_id = rule.get('id')
            if rule_id:
                rule_ids.add(str(rule_id))
        return len(rule_ids)
    
    def get_top_source_ips(self, top_n: int = 10) -> List[Tuple[int, str]]:
        """Get top source IPs"""
        ip_counts = Counter()
        
        for alert in self.alerts:
            data = alert.get('data', {})
            src_ip = data.get('srcip') or data.get('src_ip')
            if src_ip:
                ip_counts[src_ip] += 1
        
        return [(count, ip) for ip, count in ip_counts.most_common(top_n)]
    
    def get_top_targeted_users(self, top_n: int = 10) -> List[Tuple[int, str]]:
        """Get top targeted users"""
        user_counts = Counter()
        
        for alert in self.alerts:
            data = alert.get('data', {})
            win_data = data.get('win', {}).get('eventdata', {})
            
            user = (
                win_data.get('targetUserName') or
                data.get('dstuser') or
                data.get('user')
            )
            if user:
                user_counts[user] += 1
        
        return [(count, user) for user, count in user_counts.most_common(top_n)]
    
    def get_auth_summary(self) -> Tuple[int, int]:
        """Get authentication success/failure counts"""
        success = 0
        failure = 0
        
        for alert in self.alerts:
            rule = alert.get('rule', {})
            groups = rule.get('groups', [])
            if isinstance(groups, list):
                if any('authentication_success' in str(g).lower() for g in groups):
                    success += 1
                elif any('authentication_failed' in str(g).lower() for g in groups):
                    failure += 1
        
        return success, failure
    
    def get_user_mgmt_alerts(self, limit: int = None) -> List[Dict]:
        """Get user account management alerts"""
        user_mgmt = []
        
        for alert in self.alerts:
            rule = alert.get('rule', {})
            groups = rule.get('groups', [])
            description = rule.get('description', '').lower()
            data = alert.get('data', {})
            win_system = data.get('win', {}).get('system', {})
            event_id = win_system.get('eventID')
            
            # Check if it's a user management event
            is_user_mgmt = False
            if isinstance(groups, list):
                is_user_mgmt = any(
                    'account_management' in str(g).lower() or
                    'user_management' in str(g).lower() or
                    'group_management' in str(g).lower()
                    for g in groups
                )
            
            if (is_user_mgmt or
                any(keyword in description for keyword in ['user account', 'new user', 'user created', 'user deleted', 'user changed']) or
                event_id in ['4720', '4726', '4738', '4722', '4725']):
                user_mgmt.append(alert)
                if len(user_mgmt) >= limit:
                    break
        
        return user_mgmt
    
    def get_mitre_tactics(self, top_n: int = 10) -> List[Tuple[int, str]]:
        """Get MITRE ATT&CK tactics distribution"""
        tactics = []
        
        for alert in self.alerts:
            rule = alert.get('rule', {})
            mitre = rule.get('mitre', {})
            tactic_list = mitre.get('tactic', [])
            if isinstance(tactic_list, list):
                tactics.extend(tactic_list)
        
        tactic_counts = Counter(tactics)
        return [(count, tactic) for tactic, count in tactic_counts.most_common(top_n)]
    
    def get_windows_event_ids(self, top_n: int = 10) -> List[Tuple[int, str]]:
        """Get top Windows Event IDs"""
        event_ids = Counter()
        
        for alert in self.alerts:
            data = alert.get('data', {})
            win_system = data.get('win', {}).get('system', {})
            event_id = win_system.get('eventID')
            if event_id:
                event_ids[str(event_id)] += 1
        
        return [(count, eid) for eid, count in event_ids.most_common(top_n)]
    
    def get_detailed_alerts_by_rule(
        self,
        rule_id: str,
        is_critical: bool = True,
        limit: int = 20
    ) -> List[Dict]:
        """Get detailed alerts for a specific rule ID"""
        filtered = self.filter_critical() if is_critical else self.filter_non_critical()
        
        detailed = []
        for alert in filtered:
            rule = alert.get('rule', {})
            alert_rule_id = rule.get('id')
            if alert_rule_id and str(alert_rule_id) == str(rule_id):
                detailed.append(alert)
                if len(detailed) >= limit:
                    break
        
        return detailed
    
    def get_cve_alerts(self, top_n: int = 10) -> List[Tuple[int, Dict]]:
        """Get CVE-related alerts"""
        cve_alerts = []
        
        for alert in self.alerts:
            rule = alert.get('rule', {})
            cve = rule.get('cve')
            description = rule.get('description', '')
            
            # Check in rule.cve, rule.description, and full_log
            full_log = str(alert.get('full_log', '')).upper()
            
            if cve or 'CVE-' in description.upper() or 'CVE-' in full_log:
                cve_alerts.append(alert)
        
        # Group by CVE
        cve_counts = Counter()
        for alert in cve_alerts:
            rule = alert.get('rule', {})
            cve = rule.get('cve', 'N/A')
            description = rule.get('description', '')
            full_log = str(alert.get('full_log', ''))
            
            # Extract CVE from various sources
            if cve == 'N/A':
                # Try description first
                match = re.search(r'CVE-\d{4}-\d+', description, re.IGNORECASE)
                if match:
                    cve = match.group(0).upper()
                else:
                    # Try full_log
                    match = re.search(r'CVE-\d{4}-\d+', full_log, re.IGNORECASE)
                    if match:
                        cve = match.group(0).upper()
            
            if cve != 'N/A':
                cve_counts[(cve, description or 'N/A', self.get_rule_level(alert))] += 1
        
        return [
            (count, {'cve': cve, 'description': desc, 'level': level})
            for (cve, desc, level), count in cve_counts.most_common(top_n)
        ]
    
    def get_malware_alerts(self, top_n: int = None) -> List[Tuple[int, Dict]]:
        """Get malware detection alerts"""
        malware_alerts = []
        malware_keywords = ['malware', 'virus', 'trojan', 'worm', 'rootkit', 'backdoor', 'spyware', 'adware', 'ransomware']
        
        for alert in self.alerts:
            rule = alert.get('rule', {})
            groups = rule.get('groups', [])
            description = rule.get('description', '').lower()
            full_log = str(alert.get('full_log', '')).lower()
            
            is_malware = False
            
            # Check groups
            if isinstance(groups, list):
                if any(any(keyword in str(group).lower() for keyword in malware_keywords) for group in groups):
                    is_malware = True
            
            # Check description
            if not is_malware and any(keyword in description for keyword in malware_keywords):
                is_malware = True
            
            # Check full_log
            if not is_malware and any(keyword in full_log for keyword in malware_keywords):
                is_malware = True
            
            if is_malware:
                malware_alerts.append(alert)
        
        # Group by rule
        rule_counts = Counter()
        for alert in malware_alerts:
            rule = alert.get('rule', {})
            rule_id = rule.get('id', 'N/A')
            description = rule.get('description', 'N/A')
            level = self.get_rule_level(alert)
            rule_counts[(rule_id, description, level)] += 1
        
        return [
            (count, {'rule_id': rid, 'description': desc, 'level': level})
            for (rid, desc, level), count in rule_counts.most_common(top_n)
        ]
    
    def get_intrusion_alerts(self, top_n: int = None) -> List[Tuple[int, Dict]]:
        """Get intrusion detection alerts"""
        from leblebi.constants import SecurityKeywords
        intrusion_alerts = []
        intrusion_keywords = SecurityKeywords.INTRUSION_KEYWORDS
        
        for alert in self.alerts:
            rule = alert.get('rule', {})
            groups = rule.get('groups', [])
            description = rule.get('description', '').lower()
            full_log = str(alert.get('full_log', '')).lower()
            
            is_intrusion = False
            
            # Check groups
            if isinstance(groups, list):
                if any(any(keyword in str(group).lower() for keyword in intrusion_keywords) for group in groups):
                    is_intrusion = True
            
            # Check description
            if not is_intrusion and any(keyword in description for keyword in intrusion_keywords):
                is_intrusion = True
            
            # Check full_log
            if not is_intrusion and any(keyword in full_log for keyword in intrusion_keywords):
                is_intrusion = True
            
            if is_intrusion:
                intrusion_alerts.append(alert)
        
        # Group by rule
        rule_counts = Counter()
        for alert in intrusion_alerts:
            rule = alert.get('rule', {})
            rule_id = rule.get('id', 'N/A')
            description = rule.get('description', 'N/A')
            level = self.get_rule_level(alert)
            rule_counts[(rule_id, description, level)] += 1
        
        return [
            (count, {'rule_id': rid, 'description': desc, 'level': level})
            for (rid, desc, level), count in rule_counts.most_common(top_n)
        ]
    
    def get_timeline_data(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Get timeline data for visualization
        
        Args:
            limit: Maximum number of alerts to include
            
        Returns:
            List of alert dictionaries with timeline information
        """
        timeline_alerts = []
        
        for alert in self.alerts[:limit]:
            timestamp = alert.get('timestamp', '')
            if not timestamp:
                continue
            
            alert_time = self._parse_timestamp(timestamp)
            if alert_time is None:
                continue
            
            rule = alert.get('rule', {})
            level = self.get_rule_level(alert)
            rule_id = rule.get('id', 'N/A')
            description = rule.get('description', 'N/A')
            
            agent = alert.get('agent', {})
            agent_name = agent.get('name') or agent.get('id') or 'Unknown'
            agent_ip = agent.get('ip', 'N/A')
            
            data = alert.get('data', {})
            src_ip = data.get('srcip') or data.get('src_ip', 'N/A')
            dst_ip = data.get('dstip') or data.get('dst_ip', 'N/A')
            
            # Get MITRE tactics
            mitre = rule.get('mitre', {})
            tactics = mitre.get('tactic', []) if isinstance(mitre, dict) else []
            
            timeline_alerts.append({
                'timestamp': alert_time.isoformat(),
                'timestamp_ms': int(alert_time.timestamp() * 1000),
                'level': level,
                'rule_id': rule_id,
                'description': description,
                'agent_name': agent_name,
                'agent_ip': agent_ip,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'tactics': tactics if isinstance(tactics, list) else [],
                'full_alert': alert
            })
        
        # Sort by timestamp
        timeline_alerts.sort(key=lambda x: x['timestamp_ms'])
        return timeline_alerts
    
    def get_attack_timeline(self, min_level: Optional[int] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get attack timeline with correlated events
        
        Args:
            min_level: Minimum alert level to include (uses config if None)
            limit: Maximum number of alerts (uses config if None)
            
        Returns:
            List of attack events with correlation data
        """
        # Use config values if available, otherwise use defaults
        if min_level is None:
            min_level = getattr(self, '_attack_timeline_min_level', 12)
        if limit is None:
            limit = getattr(self, '_attack_timeline_limit', 500)
        
        attack_events = []
        
        # Filter critical alerts
        critical_alerts = [a for a in self.alerts if self.get_rule_level(a) >= min_level]
        
        for alert in critical_alerts[:limit]:
            timestamp = alert.get('timestamp', '')
            if not timestamp:
                continue
            
            alert_time = self._parse_timestamp(timestamp)
            if alert_time is None:
                continue
            
            rule = alert.get('rule', {})
            level = self.get_rule_level(alert)
            rule_id = rule.get('id', 'N/A')
            description = rule.get('description', 'N/A')
            
            agent = alert.get('agent', {})
            agent_name = agent.get('name') or agent.get('id') or 'Unknown'
            
            data = alert.get('data', {})
            src_ip = data.get('srcip') or data.get('src_ip', 'N/A')
            
            # Determine attack type
            attack_type = 'Unknown'
            description_lower = description.lower()
            if any(kw in description_lower for kw in ['malware', 'virus', 'trojan']):
                attack_type = 'Malware'
            elif any(kw in description_lower for kw in ['intrusion', 'exploit', 'attack']):
                attack_type = 'Intrusion'
            elif any(kw in description_lower for kw in ['authentication', 'login', 'logon']):
                attack_type = 'Authentication'
            elif any(kw in description_lower for kw in ['privilege', 'escalation']):
                attack_type = 'Privilege Escalation'
            elif any(kw in description_lower for kw in ['network', 'connection']):
                attack_type = 'Network'
            
            attack_events.append({
                'timestamp': alert_time.isoformat(),
                'timestamp_ms': int(alert_time.timestamp() * 1000),
                'level': level,
                'rule_id': rule_id,
                'description': description,
                'agent_name': agent_name,
                'src_ip': src_ip,
                'attack_type': attack_type,
                'severity': 'critical' if level >= 15 else 'high' if level >= 12 else 'medium'
            })
        
        # Sort by timestamp
        attack_events.sort(key=lambda x: x['timestamp_ms'])
        return attack_events
    
    def get_correlated_events(
        self,
        time_window_minutes: int = 60,
        correlation_keys: List[str] = None
    ) -> List[Dict[str, Any]]:
        """Get correlated events within a time window
        
        Args:
            time_window_minutes: Time window in minutes for correlation
            correlation_keys: Keys to use for correlation (default: ['src_ip', 'agent_name', 'rule_id'])
            
        Returns:
            List of correlated event groups (no duplicates)
        """
        if correlation_keys is None:
            correlation_keys = ['src_ip', 'agent_name', 'rule_id']
        
        # Get timeline data
        timeline_data = self.get_timeline_data(limit=5000)
        
        if not timeline_data:
            return []
        
        # Group events by correlation keys within time window
        correlated_groups = []
        time_window_ms = time_window_minutes * 60 * 1000
        used_event_indices = set()  # Track which events have been used
        
        i = 0
        while i < len(timeline_data):
            # Skip if event already used
            if i in used_event_indices:
                i += 1
                continue
            
            current_event = timeline_data[i]
            group = [current_event]
            used_event_indices.add(i)
            
            # Get correlation values for current event
            current_values = {
                key: str(current_event.get(key, '')) for key in correlation_keys
            }
            
            # Find related events within time window
            j = i + 1
            while j < len(timeline_data):
                # Skip if already used or outside time window
                if j in used_event_indices:
                    j += 1
                    continue
                
                next_event = timeline_data[j]
                time_diff = next_event['timestamp_ms'] - current_event['timestamp_ms']
                
                if time_diff > time_window_ms:
                    break
                
                # Get correlation values for next event
                next_values = {
                    key: str(next_event.get(key, '')) for key in correlation_keys
                }
                
                # Check if events share at least one non-empty correlation key
                shared_keys = []
                for key in correlation_keys:
                    if (current_values[key] == next_values[key] and 
                        current_values[key] != '' and 
                        current_values[key] != 'N/A'):
                        shared_keys.append(key)
                
                if shared_keys:
                    group.append(next_event)
                    used_event_indices.add(j)
                
                j += 1
            
            # Only create group if we have multiple events
            if len(group) > 1:
                # Create unique group signature to avoid duplicates
                group_signature = tuple(sorted([
                    (e.get('timestamp_ms', 0), e.get('rule_id', ''), e.get('agent_name', ''))
                    for e in group
                ]))
                
                # Check if similar group already exists
                is_duplicate = False
                for existing_group in correlated_groups:
                    existing_signature = tuple(sorted([
                        (e.get('timestamp_ms', 0), e.get('rule_id', ''), e.get('agent_name', ''))
                        for e in existing_group['events']
                    ]))
                    # If more than 80% of events match, consider it duplicate
                    if len(set(group_signature) & set(existing_signature)) / len(group_signature) > 0.8:
                        is_duplicate = True
                        break
                
                if not is_duplicate:
                    # Determine primary correlation key (most common)
                    primary_key = None
                    primary_value = None
                    for key in correlation_keys:
                        values = [str(e.get(key, '')) for e in group if str(e.get(key, '')) not in ('', 'N/A')]
                        if values:
                            from collections import Counter
                            most_common = Counter(values).most_common(1)
                            if most_common and most_common[0][1] > 1:
                                primary_key = key
                                primary_value = most_common[0][0]
                                break
                    
                    # Use first event's values if no primary found
                    if primary_key is None:
                        primary_key = correlation_keys[0]
                        primary_value = str(group[0].get(primary_key, 'N/A'))
                    
                    correlated_groups.append({
                        'group_id': f"corr_{len(correlated_groups)}",
                        'events': group,
                        'event_count': len(group),
                        'start_time': group[0]['timestamp'],
                        'end_time': group[-1]['timestamp'],
                        'duration_minutes': (group[-1]['timestamp_ms'] - group[0]['timestamp_ms']) / 60000,
                        'correlation_keys': {
                            key: str(group[0].get(key, 'N/A')) for key in correlation_keys
                        },
                        'primary_correlation': {
                            'key': primary_key,
                            'value': primary_value
                        }
                    })
            
            i += 1
        
        # Sort by event count (most correlated first)
        correlated_groups.sort(key=lambda x: x['event_count'], reverse=True)
        return correlated_groups[:20]  # Top 20 unique correlated groups

