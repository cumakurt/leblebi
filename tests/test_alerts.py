"""Tests for alerts module"""

import unittest
from leblebi.alerts import AlertProcessor
from leblebi.constants import AlertLevels, RiskScoring, Defaults


class TestAlertProcessor(unittest.TestCase):
    """Test AlertProcessor class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.processor = AlertProcessor(level=AlertLevels.CRITICAL_THRESHOLD_DEFAULT)
    
    def test_init_with_default_level(self):
        """Test initialization with default level"""
        processor = AlertProcessor()
        self.assertEqual(processor.level, AlertLevels.CRITICAL_THRESHOLD_DEFAULT)
    
    def test_init_with_custom_level(self):
        """Test initialization with custom level"""
        processor = AlertProcessor(level=10)
        self.assertEqual(processor.level, 10)
    
    def test_calculate_risk_score_empty(self):
        """Test risk score calculation with no alerts"""
        score, counts = self.processor.calculate_risk_score()
        self.assertEqual(score, 0)
        self.assertEqual(counts['critical'], 0)
        self.assertEqual(counts['high'], 0)
        self.assertEqual(counts['medium'], 0)
        self.assertEqual(counts['low'], 0)
    
    def test_get_top_alerts_by_rule_default(self):
        """Test get_top_alerts_by_rule with default top_n"""
        result = self.processor.get_top_alerts_by_rule([])
        self.assertIsInstance(result, list)
        # Should use Defaults.TOP_ALERTS_COUNT when top_n is None
    
    def test_get_top_agents_default(self):
        """Test get_top_agents with default top_n"""
        result = self.processor.get_top_agents()
        self.assertIsInstance(result, list)
    
    def test_get_highest_level_alerts_default(self):
        """Test get_highest_level_alerts with default top_n"""
        result = self.processor.get_highest_level_alerts()
        self.assertIsInstance(result, list)


if __name__ == '__main__':
    unittest.main()

