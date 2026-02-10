"""Abstract base class for search engine integrations."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import time

from src.utils.logger import get_logger
from src.utils.exceptions import RateLimitException

logger = get_logger(__name__)


@dataclass
class SearchResult:
    """Represents a single search result from any engine."""

    ip: str
    port: int
    hostname: Optional[str] = None
    service: Optional[str] = None
    banner: Optional[str] = None
    vulnerabilities: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    source_engine: Optional[str] = None
    timestamp: Optional[str] = None
    risk_score: float = 0.0
    confidence: int = 100

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'ip': self.ip,
            'port': self.port,
            'hostname': self.hostname,
            'service': self.service,
            'banner': self.banner,
            'vulnerabilities': self.vulnerabilities,
            'metadata': self.metadata,
            'source_engine': self.source_engine,
            'timestamp': self.timestamp,
            'risk_score': self.risk_score,
            'confidence': self.confidence
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SearchResult':
        """Create from dictionary."""
        return cls(
            ip=data.get('ip', ''),
            port=data.get('port', 0),
            hostname=data.get('hostname'),
            service=data.get('service'),
            banner=data.get('banner'),
            vulnerabilities=data.get('vulnerabilities', []),
            metadata=data.get('metadata', {}),
            source_engine=data.get('source_engine'),
            timestamp=data.get('timestamp'),
            risk_score=data.get('risk_score', 0.0),
            confidence=data.get('confidence', 100)
        )


class BaseSearchEngine(ABC):
    """Abstract base class for all search engine integrations."""

    def __init__(
        self,
        api_key: str,
        rate_limit: float = 1.0,
        timeout: int = 30,
        max_results: int = 100
    ):
        """
        Initialize the search engine.

        Args:
            api_key: API key for authentication
            rate_limit: Maximum queries per second
            timeout: Request timeout in seconds
            max_results: Maximum results to return per query
        """
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.max_results = max_results
        self._last_request_time = 0.0
        self._request_count = 0

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the engine name."""
        pass

    @abstractmethod
    def search(self, query: str, max_results: Optional[int] = None) -> List[SearchResult]:
        """
        Execute a search query and return results.

        Args:
            query: Search query string
            max_results: Maximum number of results to return (overrides default)

        Returns:
            List of SearchResult objects

        Raises:
            APIException: If API call fails
            RateLimitException: If rate limit exceeded
        """
        pass

    @abstractmethod
    def validate_credentials(self) -> bool:
        """
        Validate API credentials.

        Returns:
            True if credentials are valid

        Raises:
            AuthenticationException: If credentials are invalid
        """
        pass

    @abstractmethod
    def get_quota_info(self) -> Dict[str, Any]:
        """
        Get API quota/usage information.

        Returns:
            Dictionary with quota information
        """
        pass

    def _rate_limit_wait(self) -> None:
        """Enforce rate limiting between requests."""
        if self.rate_limit <= 0:
            return

        min_interval = 1.0 / self.rate_limit
        elapsed = time.time() - self._last_request_time

        if elapsed < min_interval:
            wait_time = min_interval - elapsed
            logger.debug(f"Rate limiting: waiting {wait_time:.2f}s")
            time.sleep(wait_time)

        self._last_request_time = time.time()
        self._request_count += 1

    def _check_rate_limit(self) -> None:
        """Check if rate limit is being approached."""
        # This can be overridden by specific engines with their own rate limit logic
        pass

    def _parse_result(self, raw_result: Dict[str, Any]) -> SearchResult:
        """
        Parse a raw API result into a SearchResult.

        Args:
            raw_result: Raw result from API

        Returns:
            SearchResult object
        """
        # Default implementation - should be overridden by specific engines
        return SearchResult(
            ip=raw_result.get('ip', ''),
            port=raw_result.get('port', 0),
            source_engine=self.name
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        return {
            'engine': self.name,
            'request_count': self._request_count,
            'rate_limit': self.rate_limit,
            'timeout': self.timeout,
            'max_results': self.max_results
        }
