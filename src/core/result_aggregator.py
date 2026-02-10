"""Result aggregation and deduplication for AASRT."""

from typing import Any, Dict, List, Optional, Set
from datetime import datetime
from collections import defaultdict

from src.engines import SearchResult
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ResultAggregator:
    """Aggregates and deduplicates search results from multiple engines."""

    def __init__(
        self,
        dedupe_by: str = "ip_port",
        merge_metadata: bool = True,
        prefer_engine: Optional[str] = None
    ):
        """
        Initialize ResultAggregator.

        Args:
            dedupe_by: Deduplication key ("ip_port", "ip", or "hostname")
            merge_metadata: Whether to merge metadata from duplicate results
            prefer_engine: Preferred engine when resolving conflicts
        """
        self.dedupe_by = dedupe_by
        self.merge_metadata = merge_metadata
        self.prefer_engine = prefer_engine

    def aggregate(
        self,
        results: Dict[str, List[SearchResult]]
    ) -> List[SearchResult]:
        """
        Aggregate results from multiple engines.

        Args:
            results: Dictionary mapping engine names to result lists

        Returns:
            Deduplicated and merged list of results
        """
        all_results = []

        # Flatten results
        for engine_name, engine_results in results.items():
            for result in engine_results:
                result.source_engine = engine_name
                all_results.append(result)

        logger.info(f"Aggregating {len(all_results)} total results")

        # Deduplicate
        deduplicated = self._deduplicate(all_results)

        logger.info(f"After deduplication: {len(deduplicated)} unique results")

        return deduplicated

    def _get_dedupe_key(self, result: SearchResult) -> str:
        """Get deduplication key for a result."""
        if self.dedupe_by == "ip_port":
            return f"{result.ip}:{result.port}"
        elif self.dedupe_by == "ip":
            return result.ip
        elif self.dedupe_by == "hostname":
            return result.hostname or result.ip
        else:
            return f"{result.ip}:{result.port}"

    def _deduplicate(self, results: List[SearchResult]) -> List[SearchResult]:
        """Deduplicate results based on configured key."""
        seen: Dict[str, SearchResult] = {}

        for result in results:
            key = self._get_dedupe_key(result)

            if key not in seen:
                seen[key] = result
            else:
                # Merge with existing result
                existing = seen[key]
                seen[key] = self._merge_results(existing, result)

        return list(seen.values())

    def _merge_results(
        self,
        existing: SearchResult,
        new: SearchResult
    ) -> SearchResult:
        """
        Merge two results for the same target.

        Args:
            existing: Existing result
            new: New result to merge

        Returns:
            Merged result
        """
        # Prefer result from preferred engine
        if self.prefer_engine:
            if new.source_engine == self.prefer_engine:
                base = new
                other = existing
            else:
                base = existing
                other = new
        else:
            # Default: prefer result with more information
            if len(new.metadata) > len(existing.metadata):
                base = new
                other = existing
            else:
                base = existing
                other = new

        # Merge vulnerabilities (union)
        merged_vulns = list(set(base.vulnerabilities + other.vulnerabilities))

        # Merge metadata if enabled
        if self.merge_metadata:
            merged_metadata = {**other.metadata, **base.metadata}
            # Track source engines
            engines = set()
            if base.metadata.get('source_engines'):
                engines.update(base.metadata['source_engines'])
            if other.metadata.get('source_engines'):
                engines.update(other.metadata['source_engines'])
            engines.add(base.source_engine)
            engines.add(other.source_engine)
            merged_metadata['source_engines'] = list(engines)
        else:
            merged_metadata = base.metadata

        # Take highest risk score
        risk_score = max(base.risk_score, other.risk_score)

        # Take highest confidence
        confidence = max(base.confidence, other.confidence)

        return SearchResult(
            ip=base.ip,
            port=base.port,
            hostname=base.hostname or other.hostname,
            service=base.service or other.service,
            banner=base.banner or other.banner,
            vulnerabilities=merged_vulns,
            metadata=merged_metadata,
            source_engine=base.source_engine,
            timestamp=base.timestamp,
            risk_score=risk_score,
            confidence=confidence
        )

    def filter_by_confidence(
        self,
        results: List[SearchResult],
        min_confidence: int = 70
    ) -> List[SearchResult]:
        """Filter results by minimum confidence score."""
        filtered = [r for r in results if r.confidence >= min_confidence]
        logger.info(f"Filtered by confidence >= {min_confidence}: {len(filtered)} results")
        return filtered

    def filter_by_risk_score(
        self,
        results: List[SearchResult],
        min_score: float = 0.0
    ) -> List[SearchResult]:
        """Filter results by minimum risk score."""
        filtered = [r for r in results if r.risk_score >= min_score]
        logger.info(f"Filtered by risk >= {min_score}: {len(filtered)} results")
        return filtered

    def filter_whitelist(
        self,
        results: List[SearchResult],
        whitelist_ips: Optional[List[str]] = None,
        whitelist_domains: Optional[List[str]] = None
    ) -> List[SearchResult]:
        """Filter out whitelisted IPs and domains."""
        if not whitelist_ips and not whitelist_domains:
            return results

        whitelist_ips = set(whitelist_ips or [])
        whitelist_domains = set(whitelist_domains or [])

        filtered = []
        for result in results:
            if result.ip in whitelist_ips:
                continue
            if result.hostname and result.hostname in whitelist_domains:
                continue
            # Check if hostname ends with any whitelisted domain
            if result.hostname:
                skip = False
                for domain in whitelist_domains:
                    if result.hostname.endswith(f".{domain}") or result.hostname == domain:
                        skip = True
                        break
                if skip:
                    continue
            filtered.append(result)

        excluded = len(results) - len(filtered)
        if excluded > 0:
            logger.info(f"Excluded {excluded} whitelisted results")

        return filtered

    def group_by_ip(
        self,
        results: List[SearchResult]
    ) -> Dict[str, List[SearchResult]]:
        """Group results by IP address."""
        grouped = defaultdict(list)
        for result in results:
            grouped[result.ip].append(result)
        return dict(grouped)

    def group_by_service(
        self,
        results: List[SearchResult]
    ) -> Dict[str, List[SearchResult]]:
        """Group results by service type."""
        grouped = defaultdict(list)
        for result in results:
            service = result.service or "unknown"
            grouped[service].append(result)
        return dict(grouped)

    def get_statistics(self, results: List[SearchResult]) -> Dict[str, Any]:
        """
        Get aggregate statistics for results.

        Args:
            results: List of search results

        Returns:
            Statistics dictionary
        """
        if not results:
            return {
                'total_results': 0,
                'unique_ips': 0,
                'unique_hostnames': 0,
                'engines_used': [],
                'vulnerability_counts': {},
                'risk_distribution': {},
                'top_services': []
            }

        # Count unique IPs and hostnames
        unique_ips = set(r.ip for r in results)
        unique_hostnames = set(r.hostname for r in results if r.hostname)

        # Count engines
        engines = set()
        for r in results:
            if r.metadata.get('source_engines'):
                engines.update(r.metadata['source_engines'])
            else:
                engines.add(r.source_engine)

        # Count vulnerabilities
        vuln_counts = defaultdict(int)
        for r in results:
            for vuln in r.vulnerabilities:
                vuln_counts[vuln] += 1

        # Risk distribution
        risk_dist = {
            'critical': len([r for r in results if r.risk_score >= 9.0]),
            'high': len([r for r in results if 7.0 <= r.risk_score < 9.0]),
            'medium': len([r for r in results if 4.0 <= r.risk_score < 7.0]),
            'low': len([r for r in results if r.risk_score < 4.0])
        }

        # Top services
        service_counts = defaultdict(int)
        for r in results:
            service_counts[r.service or "unknown"] += 1
        top_services = sorted(
            service_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        return {
            'total_results': len(results),
            'unique_ips': len(unique_ips),
            'unique_hostnames': len(unique_hostnames),
            'engines_used': list(engines),
            'vulnerability_counts': dict(vuln_counts),
            'risk_distribution': risk_dist,
            'top_services': top_services,
            'average_risk_score': sum(r.risk_score for r in results) / len(results)
        }
