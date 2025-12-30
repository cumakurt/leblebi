"""Constants for Leblebi application

This module contains all magic numbers and hardcoded values used throughout
the application. This improves maintainability and makes it easier to
configure behavior.
"""


class AlertLevels:
    """Alert severity level constants"""
    CRITICAL_THRESHOLD_DEFAULT = 12
    HIGH_MIN = 8
    HIGH_MAX = 11
    MEDIUM_MIN = 5
    MEDIUM_MAX = 7
    LOW_MAX = 4
    ATTACK_TIMELINE_MIN_LEVEL_DEFAULT = 12


class RiskScoring:
    """Risk scoring calculation constants"""
    CRITICAL_BASE_SCORE = 50
    CRITICAL_LOG_MULTIPLIER = 20
    CRITICAL_MAX_SCORE = 200
    HIGH_MULTIPLIER = 3
    MEDIUM_MULTIPLIER = 1
    LOW_MULTIPLIER = 0.5
    LOW_MAX_SCORE = 20


class Defaults:
    """Default configuration values"""
    TOP_ALERTS_COUNT = 100
    LOCK_TIMEOUT = 3600  # 1 hour in seconds
    MAX_ALERTS_TO_PROCESS = 1000000  # 1 million
    SAMPLING_RATE = 0.1  # 10%
    TOP_AGENTS_COUNT = 100
    HIGHEST_LEVEL_ALERTS_COUNT = 5
    USER_MGMT_ALERTS_LIMIT = 100
    WINDOWS_EVENT_IDS_LIMIT = 20
    MALWARE_ALERTS_COUNT = 5
    INTRUSION_ALERTS_COUNT = 5
    CORRELATED_GROUPS_LIMIT = 20
    CORRELATION_SIMILARITY_THRESHOLD = 0.8  # 80% similarity


class FilePaths:
    """Standard file paths"""
    DEFAULT_LOG_DIR = '/var/ossec/logs/alerts'
    DEFAULT_OUTPUT_DIR = '/var/ossec/logs/reports'
    DEFAULT_LOCK_FILE = '/var/run/leblebi_report.lock'
    DEFAULT_LOG_FILE = '/var/log/leblebi/leblebi.log'


class Network:
    """Network-related constants"""
    DEFAULT_SMTP_PORT = 25
    SMTP_PORT_MIN = 1
    SMTP_PORT_MAX = 65535
    DEFAULT_WAZUH_API_PORT = 55000
    DEFAULT_API_TIMEOUT = 30  # seconds
    DEFAULT_API_COLLECTION_TIMEOUT = 120  # seconds


class Performance:
    """Performance-related constants"""
    DEFAULT_MAX_AGENTS_TO_COLLECT = 50
    DEFAULT_API_MAX_WORKERS = 5
    DEFAULT_API_LIMIT_PER_AGENT = 10
    DEFAULT_ATTACK_TIMELINE_LIMIT = 500
    SUGGESTED_ALERT_LIMIT = 1000000  # 1 million
    LARGE_FILE_THRESHOLD_GB = 1.0
    VERY_LARGE_FILE_THRESHOLD_GB = 2.0
    AUTO_SAMPLING_RATE = 0.1  # 10%
    LARGE_FILE_SIZE_MB = 500  # MB for uncompressed files
    LARGE_COMPRESSED_FILE_SIZE_MB = 200  # MB for compressed files


class TimeConstants:
    """Time-related constants"""
    MILLISECONDS_PER_MINUTE = 60000
    SECONDS_PER_MINUTE = 60
    MINUTES_PER_HOUR = 60
    HOURS_PER_DAY = 24


class SecurityKeywords:
    """Security-related keywords for alert classification"""
    INTRUSION_KEYWORDS = [
        'intrusion', 'exploit', 'attack', 'breach', 'unauthorized',
        'penetration', 'hack', 'compromise', 'injection', 'sqli',
        'xss', 'csrf'
    ]

