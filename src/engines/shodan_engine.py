"""
Shodan search engine integration for AASRT.

This module provides a production-ready integration with the Shodan API
for security reconnaissance. Features include:

- Automatic retry with exponential backoff for transient failures
- Rate limiting to prevent API quota exhaustion
- Comprehensive error handling with specific exception types
- Detailed logging for debugging and monitoring
- Graceful degradation when API is unavailable

Example:
    >>> from src.engines.shodan_engine import ShodanEngine
    >>> engine = ShodanEngine(api_key="your_key")
    >>> engine.validate_credentials()
    True
    >>> results = engine.search("http.html:clawdbot", max_results=10)
"""

from typing import Any, Callable, Dict, List, Optional, TypeVar
from datetime import datetime
from functools import wraps
import time
import socket

import shodan
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
    RetryError
)

from .base import BaseSearchEngine, SearchResult
from src.utils.logger import get_logger
from src.utils.validators import validate_ip, sanitize_output
from src.utils.exceptions import (
    APIException,
    RateLimitException,
    AuthenticationException,
    TimeoutException
)

logger = get_logger(__name__)

# Type variable for generic retry decorator
T = TypeVar('T')

# =============================================================================
# Retry Configuration
# =============================================================================

# Exceptions that should trigger a retry (transient failures)
RETRYABLE_EXCEPTIONS = (
    socket.timeout,
    ConnectionError,
    ConnectionResetError,
    TimeoutError,
)

# Maximum number of retry attempts
MAX_RETRY_ATTEMPTS = 3

# Base delay for exponential backoff (seconds)
RETRY_BASE_DELAY = 2

# Maximum delay between retries (seconds)
RETRY_MAX_DELAY = 30


def with_retry(func: Callable[..., T]) -> Callable[..., T]:
    """
    Decorator that adds retry logic with exponential backoff.

    Retries on transient network errors but not on authentication
    or validation errors.

    Args:
        func: Function to wrap with retry logic.

    Returns:
        Wrapped function with retry capability.
    """
    @wraps(func)
    def wrapper(*args, **kwargs) -> T:
        last_exception = None

        for attempt in range(1, MAX_RETRY_ATTEMPTS + 1):
            try:
                return func(*args, **kwargs)
            except RETRYABLE_EXCEPTIONS as e:
                last_exception = e
                if attempt < MAX_RETRY_ATTEMPTS:
                    delay = min(RETRY_BASE_DELAY ** attempt, RETRY_MAX_DELAY)
                    logger.warning(
                        f"Retry {attempt}/{MAX_RETRY_ATTEMPTS} for {func.__name__} "
                        f"after {delay}s delay. Error: {e}"
                    )
                    time.sleep(delay)
                else:
                    logger.error(
                        f"All {MAX_RETRY_ATTEMPTS} retries exhausted for {func.__name__}. "
                        f"Last error: {e}"
                    )
            except (AuthenticationException, RateLimitException):
                # Don't retry auth or rate limit errors
                raise
            except shodan.APIError as e:
                error_msg = str(e).lower()
                # Don't retry permanent errors
                if "invalid api key" in error_msg:
                    raise AuthenticationException(
                        "Invalid Shodan API key",
                        engine="shodan"
                    )
                if "rate limit" in error_msg:
                    raise RateLimitException(
                        f"Shodan rate limit exceeded: {e}",
                        engine="shodan"
                    )
                # Retry other API errors
                last_exception = e
                if attempt < MAX_RETRY_ATTEMPTS:
                    delay = min(RETRY_BASE_DELAY ** attempt, RETRY_MAX_DELAY)
                    logger.warning(
                        f"Retry {attempt}/{MAX_RETRY_ATTEMPTS} for {func.__name__} "
                        f"after {delay}s delay. API Error: {e}"
                    )
                    time.sleep(delay)

        # All retries exhausted
        if last_exception:
            raise APIException(
                f"Operation failed after {MAX_RETRY_ATTEMPTS} retries: {last_exception}",
                engine="shodan"
            )
        raise APIException("Unexpected retry failure", engine="shodan")

    return wrapper


class ShodanEngine(BaseSearchEngine):
    """
    Shodan search engine integration for security reconnaissance.

    This class provides a production-ready interface to the Shodan API with:
    - Automatic rate limiting to respect API quotas
    - Retry logic with exponential backoff for transient failures
    - Comprehensive error handling and logging
    - Result parsing with vulnerability detection

    Attributes:
        name: Engine identifier ("shodan").
        api_key: Shodan API key (masked in logs).
        rate_limit: Maximum requests per second.
        timeout: Request timeout in seconds.
        max_results: Default maximum results per search.

    Example:
        >>> engine = ShodanEngine(api_key="your_key")
        >>> if engine.validate_credentials():
        ...     results = engine.search("http.html:agent", max_results=50)
        ...     for result in results:
        ...         print(f"{result.ip}:{result.port}")
    """

    def __init__(
        self,
        api_key: str,
        rate_limit: float = 1.0,
        timeout: int = 30,
        max_results: int = 100
    ) -> None:
        """
        Initialize Shodan engine with API credentials.

        Args:
            api_key: Shodan API key from https://account.shodan.io/.
                     Never log or expose this value.
            rate_limit: Maximum queries per second. Default 1.0 to respect
                       Shodan's free tier limits.
            timeout: Request timeout in seconds. Increase for slow connections.
            max_results: Maximum results per query. Higher values consume
                        more query credits.

        Raises:
            ValueError: If api_key is empty or None.
        """
        if not api_key or not api_key.strip():
            raise ValueError("Shodan API key is required")

        super().__init__(api_key, rate_limit, timeout, max_results)
        self._client = shodan.Shodan(api_key)
        self._api_key_preview = f"{api_key[:4]}...{api_key[-4:]}" if len(api_key) > 8 else "***"
        logger.debug(f"ShodanEngine initialized with key: {self._api_key_preview}")

    @property
    def name(self) -> str:
        """Return engine identifier."""
        return "shodan"

    @with_retry
    def validate_credentials(self) -> bool:
        """
        Validate Shodan API credentials by making a test API call.

        This method performs a lightweight API call to verify the API key
        is valid and has not been revoked.

        Returns:
            True if credentials are valid and API is accessible.

        Raises:
            AuthenticationException: If API key is invalid or revoked.
            APIException: If API call fails for other reasons.

        Example:
            >>> engine = ShodanEngine(api_key="your_key")
            >>> try:
            ...     engine.validate_credentials()
            ...     print("API key is valid")
            ... except AuthenticationException:
            ...     print("Invalid API key")
        """
        try:
            info = self._client.info()
            plan = info.get('plan', 'unknown')
            credits = info.get('query_credits', 0)
            logger.info(
                f"Shodan API validated. Plan: {plan}, "
                f"Query credits: {credits}"
            )
            return True
        except shodan.APIError as e:
            error_msg = str(e)
            if "Invalid API key" in error_msg:
                logger.error("Shodan authentication failed: Invalid API key")
                raise AuthenticationException(
                    "Invalid Shodan API key",
                    engine=self.name
                )
            logger.error(f"Shodan API validation error: {sanitize_output(error_msg)}")
            raise APIException(f"Shodan API error: {e}", engine=self.name)

    @with_retry
    def get_quota_info(self) -> Dict[str, Any]:
        """
        Get Shodan API quota and usage information.

        Returns:
            Dictionary containing:
                - engine: Engine name ("shodan")
                - plan: API plan type (e.g., "dev", "edu", "corp")
                - query_credits: Remaining query credits
                - scan_credits: Remaining scan credits
                - monitored_ips: Number of monitored IPs
                - unlocked: Whether account has unlocked features
                - error: Error message if call failed (optional)

        Note:
            This call does not consume query credits.
        """
        try:
            info = self._client.info()
            quota = {
                'engine': self.name,
                'plan': info.get('plan', 'unknown'),
                'query_credits': info.get('query_credits', 0),
                'scan_credits': info.get('scan_credits', 0),
                'monitored_ips': info.get('monitored_ips', 0),
                'unlocked': info.get('unlocked', False),
                'timestamp': datetime.utcnow().isoformat()
            }
            logger.debug(f"Shodan quota retrieved: {quota['query_credits']} credits remaining")
            return quota
        except shodan.APIError as e:
            logger.error(f"Failed to get Shodan quota: {sanitize_output(str(e))}")
            return {
                'engine': self.name,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }

    def search(self, query: str, max_results: Optional[int] = None) -> List[SearchResult]:
        """
        Execute a Shodan search query with automatic pagination.

        This method handles pagination automatically, respecting rate limits
        and the specified maximum results. Each page consumes one query credit.

        Args:
            query: Shodan search query string. Supports Shodan's query syntax
                   including filters like http.html:, port:, country:, etc.
            max_results: Maximum number of results to return. Defaults to
                        the engine's max_results setting. Set to None for default.

        Returns:
            List of SearchResult objects containing parsed Shodan data.
            May return fewer results than max_results if not enough matches.

        Raises:
            APIException: If API call fails after all retries.
            RateLimitException: If rate limit is exceeded.
            AuthenticationException: If API key is invalid.
            ValidationException: If query is invalid.

        Example:
            >>> results = engine.search("http.html:clawdbot", max_results=50)
            >>> for r in results:
            ...     print(f"{r.ip}:{r.port} - {r.service}")

        Note:
            - Shodan returns max 100 results per page
            - Multiple pages consume multiple query credits
            - Consider using count() first to check total results
        """
        # Validate and sanitize query
        if not query or not query.strip():
            raise APIException("Search query cannot be empty", engine=self.name)

        query = query.strip()
        limit = max_results or self.max_results

        # Log sanitized query (remove potential sensitive data)
        safe_query = sanitize_output(query)
        logger.info(f"Executing Shodan search: {safe_query} (limit: {limit})")

        results: List[SearchResult] = []
        page = 1
        total_pages = 0
        start_time = time.time()

        try:
            while len(results) < limit:
                # Apply rate limiting before each request
                self._rate_limit_wait()

                # Execute search with retry logic
                response = self._execute_search_page(query, page)

                if response is None or not response.get('matches'):
                    logger.debug(f"No more matches at page {page}")
                    break

                # Parse matches
                matches = response.get('matches', [])
                for match in matches:
                    if len(results) >= limit:
                        break

                    try:
                        result = self._parse_result(match)
                        results.append(result)
                    except Exception as e:
                        # Log but continue on parse errors
                        logger.warning(f"Failed to parse result: {e}")
                        continue

                # Check pagination limits
                total = response.get('total', 0)
                total_pages = (total + 99) // 100  # Ceiling division

                if len(results) >= total or len(results) >= limit:
                    break

                page += 1

                # Safety limit to prevent infinite loops
                if page > 100:
                    logger.warning("Reached maximum page limit (100)")
                    break

            # Log completion stats
            elapsed = time.time() - start_time
            logger.info(
                f"Shodan search complete: {len(results)} results "
                f"from {page} pages in {elapsed:.2f}s"
            )

            return results

        except (AuthenticationException, RateLimitException):
            # Re-raise known exceptions without wrapping
            raise
        except shodan.APIError as e:
            error_msg = str(e).lower()
            if "rate limit" in error_msg:
                logger.error("Shodan rate limit exceeded during search")
                raise RateLimitException(
                    f"Shodan rate limit exceeded: {e}",
                    engine=self.name
                )
            elif "invalid api key" in error_msg:
                logger.error("Shodan authentication failed during search")
                raise AuthenticationException(
                    "Invalid Shodan API key",
                    engine=self.name
                )
            else:
                logger.error(f"Shodan API error: {sanitize_output(str(e))}")
                raise APIException(
                    f"Shodan search failed: {e}",
                    engine=self.name
                )
        except Exception as e:
            logger.exception(f"Unexpected error in Shodan search: {e}")
            raise APIException(
                f"Shodan search error: {type(e).__name__}: {e}",
                engine=self.name
            )

    @with_retry
    def _execute_search_page(self, query: str, page: int) -> Optional[Dict[str, Any]]:
        """
        Execute a single page of Shodan search with retry logic.

        Args:
            query: Search query string.
            page: Page number (1-indexed).

        Returns:
            Shodan API response dictionary or None on failure.
        """
        logger.debug(f"Fetching Shodan results page {page}")
        return self._client.search(query, page=page)

    def _parse_result(self, match: Dict[str, Any]) -> SearchResult:
        """
        Parse a Shodan match into a SearchResult.

        Args:
            match: Raw Shodan match data

        Returns:
            SearchResult object
        """
        # Extract vulnerability indicators from data
        vulnerabilities = []
        data = match.get('data', '')

        # Check for common vulnerability indicators
        if 'debug' in data.lower() or 'DEBUG=True' in data:
            vulnerabilities.append('debug_mode_enabled')

        if 'api_key' in data.lower() or 'apikey' in data.lower():
            vulnerabilities.append('potential_api_key_exposure')

        ssl_data = match.get('ssl') or {}
        ssl_cert = ssl_data.get('cert') or {}
        if ssl_cert.get('expired', False):
            vulnerabilities.append('expired_ssl_certificate')

        # Check HTTP response for issues
        http_data = match.get('http') or {}
        if http_data:
            if not http_data.get('securitytxt'):
                vulnerabilities.append('no_security_txt')

        # Build metadata
        location_data = match.get('location') or {}
        metadata = {
            'asn': match.get('asn'),
            'isp': match.get('isp'),
            'org': match.get('org'),
            'os': match.get('os'),
            'transport': match.get('transport'),
            'product': match.get('product'),
            'version': match.get('version'),
            'cpe': match.get('cpe', []),
            'http': http_data,
            'ssl': ssl_data,
            'location': {
                'country': location_data.get('country_name'),
                'city': location_data.get('city'),
                'latitude': location_data.get('latitude'),
                'longitude': location_data.get('longitude')
            }
        }

        # Extract hostnames
        hostnames = match.get('hostnames', [])
        hostname = hostnames[0] if hostnames else None

        return SearchResult(
            ip=match.get('ip_str', ''),
            port=match.get('port', 0),
            hostname=hostname,
            service=match.get('product') or match.get('_shodan', {}).get('module'),
            banner=data[:1000] if data else None,  # Truncate long banners
            vulnerabilities=vulnerabilities,
            metadata=metadata,
            source_engine=self.name,
            timestamp=match.get('timestamp', datetime.utcnow().isoformat())
        )

    @with_retry
    def host_info(self, ip: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific host.

        This method retrieves comprehensive information about a host
        including all open ports, services, banners, and historical data.

        Args:
            ip: IP address to lookup. Must be a valid IPv4 address.

        Returns:
            Dictionary containing:
                - ip_str: IP address as string
                - ports: List of open ports
                - data: List of service banners per port
                - hostnames: List of hostnames
                - vulns: List of vulnerabilities (if any)
                - location: Geographic information

        Raises:
            APIException: If lookup fails.
            ValidationException: If IP address is invalid.

        Example:
            >>> info = engine.host_info("8.8.8.8")
            >>> print(f"Ports: {info.get('ports', [])}")
        """
        # Validate IP address
        try:
            validate_ip(ip)
        except Exception as e:
            raise APIException(f"Invalid IP address: {ip}", engine=self.name)

        self._rate_limit_wait()
        logger.debug(f"Looking up host info for: {ip}")

        try:
            host_data = self._client.host(ip)
            logger.info(f"Retrieved host info for {ip}: {len(host_data.get('ports', []))} ports")
            return host_data
        except shodan.APIError as e:
            error_msg = str(e).lower()
            if "no information available" in error_msg:
                logger.info(f"No Shodan data available for {ip}")
                return {'ip_str': ip, 'ports': [], 'data': []}
            logger.error(f"Failed to get host info for {ip}: {sanitize_output(str(e))}")
            raise APIException(f"Shodan host lookup failed: {e}", engine=self.name)

    @with_retry
    def count(self, query: str) -> int:
        """
        Get the count of results for a query without consuming query credits.

        Use this method to estimate result count before running a full search
        to avoid consuming query credits unnecessarily.

        Args:
            query: Shodan search query string.

        Returns:
            Estimated number of matching results. Returns 0 on error.

        Note:
            - Does not consume query credits
            - Count may be approximate for large result sets
            - Useful for validating queries before running searches

        Example:
            >>> count = engine.count("http.html:clawdbot")
            >>> if count > 0:
            ...     results = engine.search("http.html:clawdbot")
        """
        if not query or not query.strip():
            logger.warning("Empty query provided to count()")
            return 0

        self._rate_limit_wait()
        logger.debug(f"Counting results for query: {sanitize_output(query)}")

        try:
            result = self._client.count(query)
            total = result.get('total', 0)
            logger.info(f"Query '{sanitize_output(query)}' has {total} results")
            return total
        except shodan.APIError as e:
            logger.error(f"Failed to count results: {sanitize_output(str(e))}")
            return 0
        except Exception as e:
            logger.exception(f"Unexpected error in count: {e}")
            return 0
