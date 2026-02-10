"""ClawSec Threat Intelligence Feed Manager for AASRT."""

import json
import os
import stat
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from src.utils.logger import get_logger

logger = get_logger(__name__)

# Security: Restrictive file permissions for cache files (owner read/write only)
SECURE_FILE_PERMISSIONS = stat.S_IRUSR | stat.S_IWUSR  # 0o600


@dataclass
class ClawSecAdvisory:
    """Represents a single ClawSec CVE advisory."""

    cve_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    vuln_type: str  # e.g., "prompt_injection", "missing_authentication"
    cvss_score: float
    title: str
    description: str
    affected: List[str] = field(default_factory=list)
    action: str = ""
    nvd_url: Optional[str] = None
    cwe_id: Optional[str] = None
    published_date: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'cve_id': self.cve_id,
            'severity': self.severity,
            'vuln_type': self.vuln_type,
            'cvss_score': self.cvss_score,
            'title': self.title,
            'description': self.description,
            'affected': self.affected,
            'action': self.action,
            'nvd_url': self.nvd_url,
            'cwe_id': self.cwe_id,
            'published_date': self.published_date.isoformat() if self.published_date else None
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ClawSecAdvisory':
        """Create from dictionary."""
        published = data.get('published')
        if published and isinstance(published, str):
            try:
                published = datetime.fromisoformat(published.replace('Z', '+00:00'))
            except (ValueError, TypeError) as e:
                logger.debug(f"Failed to parse published date: {e}")
                published = None

        return cls(
            cve_id=data.get('id', ''),
            severity=data.get('severity', 'MEDIUM').upper(),
            vuln_type=data.get('type', 'unknown'),
            cvss_score=float(data.get('cvss_score', 0.0)),
            title=data.get('title', ''),
            description=data.get('description', ''),
            affected=data.get('affected', []),
            action=data.get('action', ''),
            nvd_url=data.get('nvd_url'),
            cwe_id=data.get('nvd_category_id'),
            published_date=published
        )


@dataclass
class ClawSecFeed:
    """Container for the full ClawSec advisory feed."""

    advisories: List[ClawSecAdvisory]
    last_updated: datetime
    feed_version: str
    total_count: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for caching."""
        return {
            'advisories': [a.to_dict() for a in self.advisories],
            'last_updated': self.last_updated.isoformat(),
            'feed_version': self.feed_version,
            'total_count': self.total_count
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ClawSecFeed':
        """Create from dictionary."""
        return cls(
            advisories=[ClawSecAdvisory.from_dict(a) for a in data.get('advisories', [])],
            last_updated=datetime.fromisoformat(data.get('last_updated', datetime.utcnow().isoformat())),
            feed_version=data.get('feed_version', '0.0.0'),
            total_count=data.get('total_count', 0)
        )


class ClawSecFeedManager:
    """
    Manages ClawSec threat intelligence feed with caching and offline support.

    Features:
    - HTTP fetch with configurable timeout
    - Local file caching for offline mode
    - Advisory matching by product/version/banner
    - Non-blocking background updates
    """

    DEFAULT_FEED_URL = "https://clawsec.prompt.security/advisories/feed.json"
    DEFAULT_CACHE_FILE = "./data/clawsec_cache.json"
    DEFAULT_TTL = 86400  # 24 hours

    def __init__(self, config=None):
        """
        Initialize ClawSecFeedManager.

        Args:
            config: Configuration object with clawsec settings
        """
        self.config = config

        # Get configuration values
        if config:
            clawsec_config = config.get('clawsec', default={})
            self.feed_url = clawsec_config.get('feed_url', self.DEFAULT_FEED_URL)
            self.cache_file = clawsec_config.get('cache_file', self.DEFAULT_CACHE_FILE)
            self.cache_ttl = clawsec_config.get('cache_ttl_seconds', self.DEFAULT_TTL)
            self.offline_mode = clawsec_config.get('offline_mode', False)
            self.timeout = clawsec_config.get('timeout', 30)
        else:
            self.feed_url = self.DEFAULT_FEED_URL
            self.cache_file = self.DEFAULT_CACHE_FILE
            self.cache_ttl = self.DEFAULT_TTL
            self.offline_mode = False
            self.timeout = 30

        self._cache: Optional[ClawSecFeed] = None
        self._cache_timestamp: Optional[datetime] = None
        self._lock = threading.Lock()

    def fetch_feed(self, force_refresh: bool = False) -> Optional[ClawSecFeed]:
        """
        Fetch the ClawSec advisory feed.

        Args:
            force_refresh: Force fetch from URL even if cache is valid

        Returns:
            ClawSecFeed object or None if fetch fails
        """
        # Check cache first
        if not force_refresh and self.is_cache_valid():
            logger.debug("Using cached ClawSec feed")
            return self._cache

        # In offline mode, only use cache
        if self.offline_mode:
            logger.info("ClawSec offline mode - using cached data only")
            return self.get_cached_feed()

        try:
            logger.info(f"Fetching ClawSec feed from {self.feed_url}")
            # Security: Explicit SSL verification to prevent MITM attacks
            response = requests.get(
                self.feed_url,
                timeout=self.timeout,
                verify=True  # Explicitly verify SSL certificates
            )
            response.raise_for_status()

            data = response.json()
            feed = self._parse_feed(data)

            with self._lock:
                self._cache = feed
                self._cache_timestamp = datetime.utcnow()

            # Persist to disk
            self.save_cache()

            logger.info(f"ClawSec feed loaded: {feed.total_count} advisories")
            return feed

        except requests.RequestException as e:
            logger.warning(f"Failed to fetch ClawSec feed: {e}")
            # Fall back to cache
            return self.get_cached_feed()
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse ClawSec feed: {e}")
            return self.get_cached_feed()

    def _parse_feed(self, data: Dict[str, Any]) -> ClawSecFeed:
        """Parse raw feed JSON into ClawSecFeed object."""
        advisories = []

        for advisory_data in data.get('advisories', []):
            try:
                advisory = ClawSecAdvisory.from_dict(advisory_data)
                advisories.append(advisory)
            except Exception as e:
                logger.warning(f"Failed to parse advisory: {e}")
                continue

        return ClawSecFeed(
            advisories=advisories,
            last_updated=datetime.utcnow(),
            feed_version=data.get('version', '0.0.0'),
            total_count=len(advisories)
        )

    def get_cached_feed(self) -> Optional[ClawSecFeed]:
        """Return cached feed without network call."""
        if self._cache:
            return self._cache

        # Try loading from disk
        self.load_cache()
        return self._cache

    def is_cache_valid(self) -> bool:
        """Check if cache is within TTL."""
        if not self._cache or not self._cache_timestamp:
            return False

        age = datetime.utcnow() - self._cache_timestamp
        return age.total_seconds() < self.cache_ttl

    def save_cache(self) -> None:
        """Persist cache to local file for offline mode."""
        if not self._cache:
            return

        try:
            cache_path = Path(self.cache_file)
            cache_path.parent.mkdir(parents=True, exist_ok=True)

            cache_data = {
                'feed': self._cache.to_dict(),
                'cached_at': datetime.utcnow().isoformat()
            }

            # Security: Write with restrictive permissions (owner read/write only)
            fd = os.open(str(cache_path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, SECURE_FILE_PERMISSIONS)
            try:
                with os.fdopen(fd, 'w') as f:
                    json.dump(cache_data, f, indent=2)
            except Exception:
                os.close(fd)
                raise

            logger.debug(f"ClawSec cache saved to {self.cache_file}")

        except Exception as e:
            logger.warning(f"Failed to save ClawSec cache: {e}")

    def load_cache(self) -> bool:
        """Load cache from local file."""
        try:
            cache_path = Path(self.cache_file)
            if not cache_path.exists():
                return False

            with open(cache_path, 'r') as f:
                cache_data = json.load(f)

            self._cache = ClawSecFeed.from_dict(cache_data.get('feed', {}))
            cached_at = cache_data.get('cached_at')
            if cached_at:
                self._cache_timestamp = datetime.fromisoformat(cached_at)

            logger.info(f"ClawSec cache loaded: {self._cache.total_count} advisories")
            return True

        except Exception as e:
            logger.warning(f"Failed to load ClawSec cache: {e}")
            return False

    def match_advisories(
        self,
        product: Optional[str] = None,
        version: Optional[str] = None,
        banner: Optional[str] = None
    ) -> List[ClawSecAdvisory]:
        """
        Find matching advisories for a product/version/banner.

        Matching strategies (in order):
        1. Exact product name match in affected list
        2. Fuzzy product match (clawdbot, clawbot, claw-bot)
        3. Banner text contains product from affected

        Args:
            product: Product name to match
            version: Version string to check
            banner: Banner text to search

        Returns:
            List of matching ClawSecAdvisory objects
        """
        feed = self.get_cached_feed()
        if not feed:
            return []

        matches = []
        product_lower = (product or '').lower()
        banner_lower = (banner or '').lower()

        # AI agent keywords to look for
        ai_keywords = ['clawdbot', 'clawbot', 'moltbot', 'openclaw', 'autogpt', 'langchain']

        for advisory in feed.advisories:
            matched = False

            # Check each affected product
            for affected in advisory.affected:
                affected_lower = affected.lower()

                # Strategy 1: Direct product match
                if product_lower and product_lower in affected_lower:
                    matched = True
                    break

                # Strategy 2: Check AI keywords in affected and product/banner
                for keyword in ai_keywords:
                    if keyword in affected_lower:
                        if keyword in product_lower or keyword in banner_lower:
                            matched = True
                            break

                if matched:
                    break

                # Strategy 3: Banner contains affected product
                if banner_lower:
                    # Extract product name from affected (e.g., "ClawdBot < 2.0" -> "clawdbot")
                    affected_product = affected_lower.split('<')[0].split('>')[0].strip()
                    if affected_product and affected_product in banner_lower:
                        matched = True
                        break

            if matched and advisory not in matches:
                matches.append(advisory)

        logger.debug(f"ClawSec matched {len(matches)} advisories for product={product}")
        return matches

    def background_refresh(self) -> None:
        """Start background thread to refresh feed."""
        def _refresh():
            try:
                self.fetch_feed(force_refresh=True)
            except Exception as e:
                logger.warning(f"Background ClawSec refresh failed: {e}")

        thread = threading.Thread(target=_refresh, daemon=True)
        thread.start()
        logger.debug("ClawSec background refresh started")

    def get_statistics(self) -> Dict[str, Any]:
        """Get feed statistics for UI display."""
        feed = self.get_cached_feed()
        if not feed:
            return {
                'total_advisories': 0,
                'critical_count': 0,
                'high_count': 0,
                'last_updated': None,
                'is_stale': True
            }

        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for advisory in feed.advisories:
            if advisory.severity in severity_counts:
                severity_counts[advisory.severity] += 1

        return {
            'total_advisories': feed.total_count,
            'critical_count': severity_counts['CRITICAL'],
            'high_count': severity_counts['HIGH'],
            'medium_count': severity_counts['MEDIUM'],
            'low_count': severity_counts['LOW'],
            'last_updated': feed.last_updated.isoformat() if feed.last_updated else None,
            'feed_version': feed.feed_version,
            'is_stale': not self.is_cache_valid()
        }
