"""CLI utility functions for Leblebi

This module contains all command-line interface utility functions
including color codes, print functions, and formatting helpers.
"""


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_summary_header():
    """Print summary header"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}{Colors.BOLD}  Leblebi - Wazuh Security Reports Generator{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}\n")


def print_step(step_num: int, total_steps: int, message: str):
    """Print step information"""
    print(f"{Colors.OKCYAN}[{step_num}/{total_steps}]{Colors.ENDC} {Colors.BOLD}{message}{Colors.ENDC}")


def print_info(message: str, value: str = ""):
    """Print info message"""
    if value:
        print(f"{Colors.OKGREEN}✓{Colors.ENDC} {message}: {Colors.BOLD}{value}{Colors.ENDC}")
    else:
        print(f"{Colors.OKGREEN}✓{Colors.ENDC} {message}")


def print_warning(message: str, value: str = ""):
    """Print warning message"""
    if value:
        print(f"{Colors.WARNING}⚠{Colors.ENDC} {message}: {Colors.BOLD}{value}{Colors.ENDC}")
    else:
        print(f"{Colors.WARNING}⚠{Colors.ENDC} {message}")


def print_error(message: str):
    """Print error message"""
    print(f"{Colors.FAIL}✗{Colors.ENDC} {Colors.BOLD}{message}{Colors.ENDC}")


def print_success(message: str):
    """Print success message"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}{Colors.BOLD}  ✓ {message}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}\n")

