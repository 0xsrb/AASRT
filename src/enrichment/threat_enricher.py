"""Threat Intelligence Enrichment for AASRT."""

from typing import Any, Dict, List, Optional, Tuple

from src.engines import SearchResult
from src.utils.logger import get_logger
from .clawsec_feed import ClawSecAdvisory, ClawSecFeedManager

logger = get_logger(__name__)


class ThreatEnricher:
    """
    Enriches SearchResult objects with ClawSec threat intelligence.

    Responsibilities:
    - Match results against ClawSec advisories
    - Add CVE metadata to result.metadata
    - Inject ClawSec vulnerabilities into result.vulnerabilities
    """

    def __init__(self, feed_manager: ClawSecFeedManager, config=None):
        """
        Initialize ThreatEnricher.

        Args:
            feed_manager: ClawSecFeedManager instance
            config: Optional configuration object
        """
        self.feed_manager = feed_manager
        self.config = config

    def enrich(self, result: SearchResult) -> SearchResult:
        """
        Enrich a single result with threat intelligence.

        Args:
            result: SearchResult to enrich

        Returns:
            Enriched SearchResult with ClawSec metadata
        """
        # Extract product info from result
        product, version = self._extract_product_info(result)
        banner = result.banner or ''

        # Get HTTP title if available
        http_info = result.metadata.get('http', {}) or {}
        title = http_info.get('title') or ''
        if title:
            banner = f"{banner} {title}"

        # Match against ClawSec advisories
        advisories = self.feed_manager.match_advisories(
            product=product,
            version=version,
            banner=banner
        )

        if advisories:
            result = self._add_cve_context(result, advisories)
            logger.debug(f"Enriched {result.ip}:{result.port} with {len(advisories)} ClawSec advisories")

        return result

    def enrich_batch(self, results: List[SearchResult]) -> List[SearchResult]:
        """
        Enrich multiple results efficiently.

        Args:
            results: List of SearchResults to enrich

        Returns:
            List of enriched SearchResults
        """
        enriched = []
        for result in results:
            enriched.append(self.enrich(result))
        return enriched

    def _extract_product_info(self, result: SearchResult) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract product name and version from result metadata.

        Args:
            result: SearchResult to analyze

        Returns:
            Tuple of (product_name, version) or (None, None)
        """
        product = None
        version = None

        # Check metadata for product info
        metadata = result.metadata if isinstance(result.metadata, dict) else {}

        # Try product field directly
        if 'product' in metadata:
            product = metadata['product']

        # Try version field
        if 'version' in metadata:
            version = metadata['version']

        # Check HTTP info
        http_info = metadata.get('http') or {}
        if http_info:
            title = http_info.get('title') or ''
            # Look for AI agent keywords in title
            ai_products = {
                'clawdbot': 'ClawdBot',
                'moltbot': 'MoltBot',
                'autogpt': 'AutoGPT',
                'langchain': 'LangChain',
                'openclaw': 'OpenClaw'
            }
            for keyword, name in ai_products.items():
                if title and keyword in title.lower():
                    product = name
                    break

        # Check service name
        if not product and result.service:
            service_lower = result.service.lower()
            for keyword in ['clawdbot', 'moltbot', 'autogpt', 'langchain']:
                if keyword in service_lower:
                    product = result.service
                    break

        # Check banner for version patterns
        if result.banner and not version:
            import re
            version_patterns = [
                r'v?(\d+\.\d+(?:\.\d+)?)',  # v1.2.3 or 1.2.3
                r'version[:\s]+(\d+\.\d+(?:\.\d+)?)',  # version: 1.2.3
            ]
            for pattern in version_patterns:
                match = re.search(pattern, result.banner, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    break

        return product, version

    def _add_cve_context(
        self,
        result: SearchResult,
        advisories: List[ClawSecAdvisory]
    ) -> SearchResult:
        """
        Add CVE information to result metadata and vulnerabilities.

        Args:
            result: SearchResult to update
            advisories: List of matched ClawSecAdvisory objects

        Returns:
            Updated SearchResult
        """
        # Add ClawSec advisories to metadata
        clawsec_data = []
        for advisory in advisories:
            clawsec_data.append({
                'cve_id': advisory.cve_id,
                'severity': advisory.severity,
                'cvss_score': advisory.cvss_score,
                'title': advisory.title,
                'vuln_type': advisory.vuln_type,
                'action': advisory.action,
                'nvd_url': advisory.nvd_url,
                'cwe_id': advisory.cwe_id
            })

        result.metadata['clawsec_advisories'] = clawsec_data

        # Track highest severity for quick access
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        highest_severity = max(
            (a.severity for a in advisories),
            key=lambda s: severity_order.get(s, 0),
            default='LOW'
        )
        result.metadata['clawsec_severity'] = highest_severity

        # Add CVE IDs to vulnerabilities list
        for advisory in advisories:
            vuln_id = f"clawsec_{advisory.cve_id}"
            if vuln_id not in result.vulnerabilities:
                result.vulnerabilities.append(vuln_id)

        return result

    def get_enrichment_stats(self, results: List[SearchResult]) -> Dict[str, Any]:
        """
        Get statistics about enrichment for a set of results.

        Args:
            results: List of enriched SearchResults

        Returns:
            Dictionary with enrichment statistics
        """
        enriched_count = 0
        total_cves = 0
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        cve_list = set()

        for result in results:
            advisories = result.metadata.get('clawsec_advisories', [])
            if advisories:
                enriched_count += 1
                total_cves += len(advisories)

                for advisory in advisories:
                    cve_list.add(advisory['cve_id'])
                    severity = advisory.get('severity', 'LOW')
                    if severity in severity_counts:
                        severity_counts[severity] += 1

        return {
            'enriched_results': enriched_count,
            'total_results': len(results),
            'enrichment_rate': (enriched_count / len(results) * 100) if results else 0,
            'unique_cves': len(cve_list),
            'total_cve_matches': total_cves,
            'severity_breakdown': severity_counts,
            'cve_ids': list(cve_list)
        }
