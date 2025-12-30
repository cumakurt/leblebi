"""Retry mechanism for API calls and other operations"""

import time
import logging
from typing import Callable, TypeVar, Optional, List, Type
from functools import wraps
from leblebi.exceptions import APIError, APITimeoutError, APIConnectionError

T = TypeVar('T')
logger = logging.getLogger('leblebi')


def retry_on_failure(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple = (Exception,),
    logger: Optional[logging.Logger] = None
):
    """Decorator for retrying function calls on failure
    
    Args:
        max_attempts: Maximum number of retry attempts
        delay: Initial delay between retries in seconds
        backoff: Multiplier for delay after each retry
        exceptions: Tuple of exceptions to catch and retry
        logger: Logger instance for logging retries
        
    Returns:
        Decorated function
    """
    log = logger or logging.getLogger('leblebi')
    
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            current_delay = delay
            last_exception = None
            
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts:
                        log.warning(
                            f"{func.__name__} failed (attempt {attempt}/{max_attempts}): {str(e)}. "
                            f"Retrying in {current_delay:.1f}s..."
                        )
                        time.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        log.error(
                            f"{func.__name__} failed after {max_attempts} attempts: {str(e)}"
                        )
            
            # All attempts failed, raise last exception
            raise last_exception
        
        return wrapper
    return decorator


def retry_api_call(
    max_attempts: int = 3,
    delay: float = 2.0,
    backoff: float = 2.0
):
    """Decorator specifically for API calls with appropriate exception handling
    
    Args:
        max_attempts: Maximum number of retry attempts
        delay: Initial delay between retries in seconds
        backoff: Multiplier for delay after each retry
        
    Returns:
        Decorated function
    """
    return retry_on_failure(
        max_attempts=max_attempts,
        delay=delay,
        backoff=backoff,
        exceptions=(APIConnectionError, APITimeoutError, APIError),
        logger=logger
    )


class RetryHandler:
    """Handler for retrying operations with custom logic"""
    
    def __init__(
        self,
        max_attempts: int = 3,
        delay: float = 1.0,
        backoff: float = 2.0,
        exceptions: tuple = (Exception,),
        logger: Optional[logging.Logger] = None
    ):
        """Initialize retry handler
        
        Args:
            max_attempts: Maximum number of retry attempts
            delay: Initial delay between retries in seconds
            backoff: Multiplier for delay after each retry
            exceptions: Tuple of exceptions to catch and retry
            logger: Logger instance
        """
        self.max_attempts = max_attempts
        self.delay = delay
        self.backoff = backoff
        self.exceptions = exceptions
        self.logger = logger or logging.getLogger('leblebi')
    
    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute function with retry logic
        
        Args:
            func: Function to execute
            *args: Positional arguments for function
            **kwargs: Keyword arguments for function
            
        Returns:
            Function result
            
        Raises:
            Last exception if all attempts fail
        """
        current_delay = self.delay
        last_exception = None
        
        for attempt in range(1, self.max_attempts + 1):
            try:
                return func(*args, **kwargs)
            except self.exceptions as e:
                last_exception = e
                if attempt < self.max_attempts:
                    self.logger.warning(
                        f"{func.__name__} failed (attempt {attempt}/{self.max_attempts}): {str(e)}. "
                        f"Retrying in {current_delay:.1f}s..."
                    )
                    time.sleep(current_delay)
                    current_delay *= self.backoff
                else:
                    self.logger.error(
                        f"{func.__name__} failed after {self.max_attempts} attempts: {str(e)}"
                    )
        
        # All attempts failed
        raise last_exception

