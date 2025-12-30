"""Tests for CLI module"""

import unittest
import sys
from io import StringIO
from leblebi.cli import Colors, print_info, print_warning, print_error, print_step


class TestCLI(unittest.TestCase):
    """Test CLI utility functions"""
    
    def test_colors(self):
        """Test color constants"""
        self.assertIsInstance(Colors.HEADER, str)
        self.assertIsInstance(Colors.OKGREEN, str)
        self.assertIsInstance(Colors.WARNING, str)
        self.assertIsInstance(Colors.FAIL, str)
        self.assertIsInstance(Colors.ENDC, str)
    
    def test_print_info(self):
        """Test print_info function"""
        output = StringIO()
        sys.stdout = output
        try:
            print_info("Test message", "value")
            output_str = output.getvalue()
            self.assertIn("Test message", output_str)
            self.assertIn("value", output_str)
        finally:
            sys.stdout = sys.__stdout__
    
    def test_print_warning(self):
        """Test print_warning function"""
        output = StringIO()
        sys.stdout = output
        try:
            print_warning("Test warning")
            output_str = output.getvalue()
            self.assertIn("Test warning", output_str)
        finally:
            sys.stdout = sys.__stdout__
    
    def test_print_error(self):
        """Test print_error function"""
        output = StringIO()
        sys.stdout = output
        try:
            print_error("Test error")
            output_str = output.getvalue()
            self.assertIn("Test error", output_str)
        finally:
            sys.stdout = sys.__stdout__
    
    def test_print_step(self):
        """Test print_step function"""
        output = StringIO()
        sys.stdout = output
        try:
            print_step(1, 5, "Test step")
            output_str = output.getvalue()
            self.assertIn("Test step", output_str)
            self.assertIn("1/5", output_str)
        finally:
            sys.stdout = sys.__stdout__


if __name__ == '__main__':
    unittest.main()

