"""Utility functions for Leblebi

This module provides common utility functions used throughout the application,
including file operations, system commands, and error handling helpers.
"""

import os
import fcntl
import subprocess
import tempfile
import logging
import psutil
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple, Callable, TypeVar
from contextlib import contextmanager

T = TypeVar('T')


class LockFile:
    """File-based locking mechanism to prevent multiple instances
    
    This class provides file-based locking using fcntl to ensure
    only one instance of Leblebi runs at a time.
    
    Attributes:
        lock_file: Path to lock file
        timeout: Lock timeout in seconds
        fd: File descriptor for lock file
        lock_acquired: Whether lock was successfully acquired
    """
    
    def __init__(self, lock_file: str, timeout: int = 3600):
        """Initialize lock file
        
        Args:
            lock_file: Path to lock file
            timeout: Lock timeout in seconds (default: 3600)
        """
        self.lock_file = lock_file
        self.timeout = timeout
        self.fd = None
        self.lock_acquired = False
    
    def __enter__(self):
        """Acquire lock
        
        Returns:
            Self instance
            
        Raises:
            RuntimeError: If another instance is already running
        """
        # Try to create lock file, but skip if permission denied
        try:
            # Try to create lock file in a writable location
            lock_dir = os.path.dirname(self.lock_file)
            if lock_dir and not os.path.exists(lock_dir):
                # Try to create directory, but skip if permission denied
                try:
                    os.makedirs(lock_dir, exist_ok=True)
                except (PermissionError, OSError):
                    # Can't create directory, try alternative location
                    self.lock_file = os.path.join(os.getenv('HOME', '/tmp'), '.leblebi_report.lock')
            
            self.fd = open(self.lock_file, 'w')
            try:
                fcntl.flock(self.fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.fd.write(f"{os.getpid()}\n")
                self.fd.flush()
                self.lock_acquired = True
                return self
            except BlockingIOError:
                self.fd.close()
                raise RuntimeError(
                    f"Another instance is running (Lock: {self.lock_file}). Exiting."
                )
        except (PermissionError, OSError) as e:
            # Can't create lock file - skip locking mechanism
            # This is acceptable for non-critical operations
            if self.fd:
                try:
                    self.fd.close()
                except (OSError, IOError):
                    pass
                except Exception:
                    pass
            self.lock_acquired = False
            return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Release lock
        
        Args:
            exc_type: Exception type (if any)
            exc_val: Exception value (if any)
            exc_tb: Exception traceback (if any)
        """
        if self.lock_acquired and self.fd:
            try:
                fcntl.flock(self.fd.fileno(), fcntl.LOCK_UN)
            except (OSError, IOError):
                pass
            except Exception:
                pass
            try:
                self.fd.close()
            except (OSError, IOError):
                pass
            except Exception:
                pass
            try:
                os.remove(self.lock_file)
            except FileNotFoundError:
                # Lock file already removed
                pass
            except (OSError, IOError):
                pass
            except Exception:
                pass


def safe_mkdir(directory: str) -> bool:
    """Safely create directory with error handling
    
    Args:
        directory: Directory path to create
        
    Returns:
        True if directory was created or already exists, False on error
    """
    try:
        Path(directory).mkdir(parents=True, exist_ok=True)
        return True
    except PermissionError:
        return False
    except OSError:
        return False
    except Exception:
        return False


def get_temp_file(suffix: str = '', prefix: str = 'leblebi_') -> str:
    """Get temporary file path
    
    Creates a temporary file and returns its path. The file is created
    but immediately closed, so it exists but is empty.
    
    Args:
        suffix: File suffix (e.g., '.html', '.json')
        prefix: File prefix (default: 'leblebi_')
        
    Returns:
        Path to temporary file
    """
    fd, path = tempfile.mkstemp(suffix=suffix, prefix=prefix)
    os.close(fd)
    return path


def run_command(cmd: List[str], capture_output: bool = True) -> tuple:
    """Run system command safely with timeout
    
    Args:
        cmd: Command to run as list of strings
        capture_output: Whether to capture stdout/stderr (default: True)
        
    Returns:
        Tuple of (returncode, stdout, stderr)
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            timeout=30
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timeout"
    except Exception as e:
        return -1, "", str(e)


def normalize_rule_id(rule_id: Any) -> str:
    """Normalize rule ID to string for comparison
    
    Args:
        rule_id: Rule ID (can be int, str, or None)
        
    Returns:
        String representation of rule ID, or "N/A" if None
    """
    if rule_id is None:
        return "N/A"
    return str(rule_id)


def get_nested_value(data: Dict, keys: List[str], default: Any = "N/A") -> Any:
    """Safely get nested dictionary value
    
    Traverses a nested dictionary using a list of keys and returns
    the value, or default if any key is missing.
    
    Args:
        data: Dictionary to traverse
        keys: List of keys to traverse (e.g., ['a', 'b', 'c'] for data['a']['b']['c'])
        default: Default value if key path doesn't exist
        
    Returns:
        Value at nested path or default
    """
    current = data
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current if current is not None else default


def get_memory_usage_mb() -> float:
    """Get current process memory usage in megabytes
    
    Returns:
        Memory usage in MB, or 0.0 if psutil is not available
    """
    try:
        process = psutil.Process(os.getpid())
        memory_info = process.memory_info()
        return memory_info.rss / (1024 * 1024)  # Convert bytes to MB
    except (ImportError, AttributeError, OSError):
        # psutil not available or error getting memory info
        return 0.0


def check_memory_limit(memory_limit_mb: int) -> Tuple[bool, float]:
    """Check if current memory usage exceeds limit
    
    Args:
        memory_limit_mb: Memory limit in megabytes (0 = disabled)
        
    Returns:
        Tuple of (exceeds_limit, current_usage_mb)
    """
    if memory_limit_mb <= 0:
        return False, 0.0
    
    current_usage = get_memory_usage_mb()
    exceeds_limit = current_usage > memory_limit_mb
    
    return exceeds_limit, current_usage


def should_enable_sampling(
    memory_limit_mb: int,
    current_sampling_enabled: bool,
    file_size_gb: float = 0.0
) -> bool:
    """Determine if sampling should be enabled based on memory and file size
    
    Args:
        memory_limit_mb: Memory limit in megabytes
        current_sampling_enabled: Current sampling state
        file_size_gb: Size of file being processed in GB
        
    Returns:
        True if sampling should be enabled
    """
    # Check memory limit
    if memory_limit_mb > 0:
        exceeds_limit, current_usage = check_memory_limit(memory_limit_mb)
        if exceeds_limit:
            return True
    
    # Auto-enable sampling for very large files (>2GB) if not already enabled
    if not current_sampling_enabled and file_size_gb > 2.0:
        return True
    
    return False


def safe_execute(
    func: Callable[[], T],
    default: T,
    logger: Optional[logging.Logger] = None,
    error_message: Optional[str] = None,
    log_level: str = 'warning'
) -> T:
    """Safely execute a function and return default value on any exception
    
    This is a common pattern used throughout the codebase to handle
    exceptions gracefully without code duplication.
    
    Args:
        func: Function to execute
        default: Default value to return on exception
        logger: Optional logger instance
        error_message: Optional custom error message
        log_level: Logging level ('debug', 'info', 'warning', 'error')
        
    Returns:
        Result of func() or default if exception occurs
    """
    try:
        return func()
    except Exception as e:
        if logger:
            log_func = getattr(logger, log_level, logger.warning)
            msg = error_message or f"Error executing {func.__name__}: {e}"
            log_func(msg)
        return default


def safe_subprocess_run(
    cmd: List[str],
    timeout: int = 30,
    logger: Optional[logging.Logger] = None,
    default_returncode: int = -1,
    default_output: str = "",
    default_error: str = ""
) -> Tuple[int, str, str]:
    """Safely run subprocess command with consistent error handling
    
    This function standardizes subprocess error handling across the codebase.
    
    Args:
        cmd: Command to run as list of strings
        timeout: Command timeout in seconds
        logger: Optional logger instance
        default_returncode: Default return code on error
        default_output: Default stdout on error
        default_error: Default stderr on error
        
    Returns:
        Tuple of (returncode, stdout, stderr)
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        if logger:
            logger.warning(f"Command timeout after {timeout}s: {' '.join(cmd)}")
        return default_returncode, default_output, f"Command timeout after {timeout}s"
    except FileNotFoundError:
        if logger:
            logger.debug(f"Command not found: {' '.join(cmd)}")
        return default_returncode, default_output, "Command not found"
    except PermissionError as e:
        if logger:
            logger.warning(f"Permission denied running command: {' '.join(cmd)} - {e}")
        return default_returncode, default_output, f"Permission denied: {e}"
    except Exception as e:
        if logger:
            logger.warning(f"Error running command {' '.join(cmd)}: {e}")
        return default_returncode, default_output, str(e)

