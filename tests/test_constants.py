"""Tests for constants module"""

import unittest
from leblebi.constants import (
    AlertLevels, RiskScoring, Defaults, FilePaths,
    Network, Performance, TimeConstants, SecurityKeywords
)


class TestConstants(unittest.TestCase):
    """Test constants module"""
    
    def test_alert_levels(self):
        """Test AlertLevels constants"""
        self.assertIsInstance(AlertLevels.CRITICAL_THRESHOLD_DEFAULT, int)
        self.assertGreater(AlertLevels.CRITICAL_THRESHOLD_DEFAULT, 0)
        self.assertGreater(AlertLevels.HIGH_MAX, AlertLevels.HIGH_MIN)
        self.assertGreater(AlertLevels.MEDIUM_MAX, AlertLevels.MEDIUM_MIN)
    
    def test_risk_scoring(self):
        """Test RiskScoring constants"""
        self.assertIsInstance(RiskScoring.CRITICAL_BASE_SCORE, int)
        self.assertGreater(RiskScoring.CRITICAL_BASE_SCORE, 0)
        self.assertIsInstance(RiskScoring.HIGH_MULTIPLIER, (int, float))
        self.assertIsInstance(RiskScoring.MEDIUM_MULTIPLIER, (int, float))
        self.assertIsInstance(RiskScoring.LOW_MULTIPLIER, float)
    
    def test_defaults(self):
        """Test Defaults constants"""
        self.assertIsInstance(Defaults.TOP_ALERTS_COUNT, int)
        self.assertGreater(Defaults.TOP_ALERTS_COUNT, 0)
        self.assertIsInstance(Defaults.LOCK_TIMEOUT, int)
        self.assertGreater(Defaults.LOCK_TIMEOUT, 0)
    
    def test_file_paths(self):
        """Test FilePaths constants"""
        self.assertIsInstance(FilePaths.DEFAULT_LOG_DIR, str)
        self.assertIsInstance(FilePaths.DEFAULT_OUTPUT_DIR, str)
        self.assertIsInstance(FilePaths.DEFAULT_LOCK_FILE, str)
    
    def test_network(self):
        """Test Network constants"""
        self.assertIsInstance(Network.DEFAULT_SMTP_PORT, int)
        self.assertGreater(Network.DEFAULT_SMTP_PORT, 0)
        self.assertLessEqual(Network.DEFAULT_SMTP_PORT, Network.SMTP_PORT_MAX)
        self.assertGreaterEqual(Network.DEFAULT_SMTP_PORT, Network.SMTP_PORT_MIN)
    
    def test_performance(self):
        """Test Performance constants"""
        self.assertIsInstance(Performance.DEFAULT_MAX_AGENTS_TO_COLLECT, int)
        self.assertGreater(Performance.DEFAULT_MAX_AGENTS_TO_COLLECT, 0)
        self.assertIsInstance(Performance.SUGGESTED_ALERT_LIMIT, int)
        self.assertGreater(Performance.SUGGESTED_ALERT_LIMIT, 0)
        self.assertIsInstance(Performance.AUTO_SAMPLING_RATE, float)
        self.assertGreater(Performance.AUTO_SAMPLING_RATE, 0)
        self.assertLessEqual(Performance.AUTO_SAMPLING_RATE, 1.0)
    
    def test_time_constants(self):
        """Test TimeConstants"""
        self.assertEqual(TimeConstants.SECONDS_PER_MINUTE, 60)
        self.assertEqual(TimeConstants.MINUTES_PER_HOUR, 60)
        self.assertEqual(TimeConstants.HOURS_PER_DAY, 24)
    
    def test_security_keywords(self):
        """Test SecurityKeywords"""
        self.assertIsInstance(SecurityKeywords.INTRUSION_KEYWORDS, list)
        self.assertGreater(len(SecurityKeywords.INTRUSION_KEYWORDS), 0)
        self.assertTrue(all(isinstance(kw, str) for kw in SecurityKeywords.INTRUSION_KEYWORDS))


if __name__ == '__main__':
    unittest.main()
