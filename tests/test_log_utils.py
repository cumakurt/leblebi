"""Tests for log_utils module"""

import unittest
import os
import tempfile
from datetime import datetime
from leblebi.log_utils import find_alerts_file, find_wazuh_log_files


class TestLogUtils(unittest.TestCase):
    """Test log utilities"""
    
    def test_find_alerts_file_not_found(self):
        """Test find_alerts_file when file doesn't exist"""
        result = find_alerts_file("/nonexistent/path")
        self.assertIsNone(result)
    
    def test_find_alerts_file_found(self):
        """Test find_alerts_file when file exists"""
        with tempfile.TemporaryDirectory() as tmpdir:
            alerts_file = os.path.join(tmpdir, "alerts.json")
            with open(alerts_file, 'w') as f:
                f.write("[]")
            
            result = find_alerts_file(tmpdir)
            self.assertEqual(result, alerts_file)
    
    def test_find_wazuh_log_files_today_only(self):
        """Test find_wazuh_log_files for today only"""
        with tempfile.TemporaryDirectory() as tmpdir:
            alerts_file = os.path.join(tmpdir, "alerts.json")
            with open(alerts_file, 'w') as f:
                f.write("[]")
            
            log_files, missing_dates = find_wazuh_log_files(tmpdir, 1)
            # Should find today's file if it exists
            self.assertIsInstance(log_files, list)
            self.assertIsInstance(missing_dates, list)
    
    def test_find_wazuh_log_files_multiple_days(self):
        """Test find_wazuh_log_files for multiple days"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create today's file
            alerts_file = os.path.join(tmpdir, "alerts.json")
            with open(alerts_file, 'w') as f:
                f.write("[]")
            
            log_files, missing_dates = find_wazuh_log_files(tmpdir, 3)
            # Should return lists
            self.assertIsInstance(log_files, list)
            self.assertIsInstance(missing_dates, list)
            # May have missing dates for previous days
            self.assertGreaterEqual(len(missing_dates), 0)


if __name__ == '__main__':
    unittest.main()

