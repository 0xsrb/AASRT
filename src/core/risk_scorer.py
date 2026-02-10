"""Risk scoring engine for AASRT."""

from typing import Any, Dict, List

from .vulnerability_assessor import Vulnerability
from src.engines import SearchResult
from src.utils.logger import get_logger

logger = get_logger(__name__)


class RiskScorer:
    """Calculates risk scores for targets based on vulnerabilities."""

    # Severity weights for scoring
    SEVERITY_WEIGHTS = {
        'CRITICAL': 1.5,
        'HIGH': 1.2,
        'MEDIUM': 1.0,
        'LOW': 0.5,
        'INFO': 0.1
    }

    # Context multipliers
    CONTEXT_MULTIPLIERS = {
        'public_internet': 1.2,
        'no_waf': 1.1,
        'known_vulnerable_version': 1.3,
        'ai_agent': 1.2,  # AI agents may have additional risk
        'clawsec_cve': 1.4,  # Known ClawSec CVE vulnerability
        'clawsec_critical': 1.5,  # Critical ClawSec CVE
    }

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize RiskScorer.

        Args:
            config: Configuration options
        """
        self.config = config or {}

    def calculate_score(
        self,
        vulnerabilities: List[Vulnerability],
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Calculate risk score based on vulnerabilities.

        Formula:
        - Base score: Highest CVSS score found
        - Adjusted: base * (1 + 0.1 * critical_count)
        - Context multipliers applied
        - Capped at 10.0

        Args:
            vulnerabilities: List of discovered vulnerabilities
            context: Additional context (public_internet, etc.)

        Returns:
            Risk assessment dictionary
        """
        if not vulnerabilities:
            return {
                'overall_score': 0.0,
                'severity_breakdown': {
                    'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0
                },
                'exploitability': 'NONE',
                'impact': 'NONE',
                'confidence': 100
            }

        context = context or {}

        # Get base score (highest CVSS)
        base_score = max(v.cvss_score for v in vulnerabilities)

        # Count by severity
        severity_counts = self._count_severities(vulnerabilities)

        # Apply vulnerability count multiplier
        critical_count = severity_counts['critical']
        high_count = severity_counts['high']

        # Increase score based on multiple vulnerabilities
        adjusted_score = base_score * (1.0 + (0.1 * critical_count) + (0.05 * high_count))

        # Apply context multipliers
        for ctx_key, multiplier in self.CONTEXT_MULTIPLIERS.items():
            if context.get(ctx_key, False):
                adjusted_score *= multiplier

        # Cap at 10.0
        final_score = min(adjusted_score, 10.0)

        # Determine exploitability
        exploitability = self._calculate_exploitability(vulnerabilities, critical_count)

        # Determine impact
        impact = self._calculate_impact(vulnerabilities)

        return {
            'overall_score': round(final_score, 1),
            'severity_breakdown': severity_counts,
            'exploitability': exploitability,
            'impact': impact,
            'confidence': self._calculate_confidence(vulnerabilities),
            'contributing_factors': self._get_contributing_factors(vulnerabilities)
        }

    def _count_severities(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        """Count vulnerabilities by severity level."""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for v in vulnerabilities:
            severity_key = v.severity.lower()
            if severity_key in counts:
                counts[severity_key] += 1
        return counts

    def _calculate_exploitability(
        self,
        vulnerabilities: List[Vulnerability],
        critical_count: int
    ) -> str:
        """Determine overall exploitability level."""
        if critical_count >= 2:
            return 'CRITICAL'
        elif critical_count >= 1:
            return 'HIGH'

        # Check for easily exploitable vulnerabilities
        easy_exploit = ['api_key_exposure', 'no_authentication', 'shell_access']
        for v in vulnerabilities:
            if any(indicator in v.check_name for indicator in easy_exploit):
                return 'HIGH'

        high_count = len([v for v in vulnerabilities if v.severity == 'HIGH'])
        if high_count >= 2:
            return 'MEDIUM'

        return 'LOW'

    def _calculate_impact(self, vulnerabilities: List[Vulnerability]) -> str:
        """Determine potential impact level."""
        # Check for high-impact vulnerabilities
        high_impact_indicators = [
            'api_key_exposure',
            'shell_access',
            'database_exposed',
            'admin_panel'
        ]

        for v in vulnerabilities:
            if any(indicator in v.check_name for indicator in high_impact_indicators):
                return 'HIGH'

        if any(v.cvss_score >= 7.0 for v in vulnerabilities):
            return 'MEDIUM'

        return 'LOW'

    def _calculate_confidence(self, vulnerabilities: List[Vulnerability]) -> int:
        """Calculate confidence in the assessment."""
        if not vulnerabilities:
            return 100

        # Start with high confidence
        confidence = 100

        # Reduce confidence for potential false positives
        for v in vulnerabilities:
            if 'potential' in v.check_name or 'possible' in v.description.lower():
                confidence -= 10

        return max(confidence, 0)

    def _get_contributing_factors(self, vulnerabilities: List[Vulnerability]) -> List[str]:
        """Get list of main contributing factors to the risk score."""
        factors = []

        for v in vulnerabilities:
            if v.severity in ['CRITICAL', 'HIGH']:
                factors.append(f"{v.severity}: {v.description}")

        return factors[:5]  # Top 5 factors

    def score_result(self, result: SearchResult, vulnerabilities: List[Vulnerability]) -> SearchResult:
        """
        Apply risk score to a SearchResult.

        Args:
            result: SearchResult to score
            vulnerabilities: Assessed vulnerabilities

        Returns:
            Updated SearchResult with risk score
        """
        # Build context from result metadata
        context = {
            'public_internet': True,  # Assume public if found via search
            'ai_agent': self._is_ai_agent(result),
            'clawsec_cve': self._has_clawsec_cve(result),
            'clawsec_critical': self._has_critical_clawsec_cve(result)
        }

        # Check for WAF
        http_info = result.metadata.get('http') or {}
        http_headers = http_info.get('headers', {})
        if not any(waf in str(http_headers).lower() for waf in ['cloudflare', 'akamai', 'fastly']):
            context['no_waf'] = True

        # Calculate score
        risk_data = self.calculate_score(vulnerabilities, context)

        # Update result
        result.risk_score = risk_data['overall_score']
        result.metadata['risk_assessment'] = risk_data
        result.vulnerabilities = [v.check_name for v in vulnerabilities]

        return result

    def _has_clawsec_cve(self, result: SearchResult) -> bool:
        """Check if result has any ClawSec CVE associations."""
        return bool(result.metadata.get('clawsec_advisories'))

    def _has_critical_clawsec_cve(self, result: SearchResult) -> bool:
        """Check if result has a critical ClawSec CVE."""
        advisories = result.metadata.get('clawsec_advisories', [])
        return any(a.get('severity') == 'CRITICAL' for a in advisories)

    def _is_ai_agent(self, result: SearchResult) -> bool:
        """Check if result appears to be an AI agent."""
        ai_indicators = [
            'clawdbot', 'autogpt', 'langchain', 'openai',
            'anthropic', 'claude', 'gpt', 'agent'
        ]

        http_info = result.metadata.get('http') or {}
        http_title = http_info.get('title') or ''
        text = (
            (result.banner or '') +
            (result.service or '') +
            str(http_title)
        ).lower()

        return any(indicator in text for indicator in ai_indicators)

    def categorize_results(
        self,
        results: List[SearchResult]
    ) -> Dict[str, List[SearchResult]]:
        """
        Categorize results by risk level.

        Args:
            results: List of scored results

        Returns:
            Dictionary with risk level categories
        """
        categories = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }

        for result in results:
            if result.risk_score >= 9.0:
                categories['critical'].append(result)
            elif result.risk_score >= 7.0:
                categories['high'].append(result)
            elif result.risk_score >= 4.0:
                categories['medium'].append(result)
            else:
                categories['low'].append(result)

        return categories

    def get_summary(self, results: List[SearchResult]) -> Dict[str, Any]:
        """
        Get risk summary for a set of results.

        Args:
            results: List of scored results

        Returns:
            Summary statistics
        """
        if not results:
            return {
                'total': 0,
                'average_score': 0.0,
                'max_score': 0.0,
                'distribution': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            }

        categories = self.categorize_results(results)
        scores = [r.risk_score for r in results]

        return {
            'total': len(results),
            'average_score': round(sum(scores) / len(scores), 1),
            'max_score': max(scores),
            'distribution': {
                'critical': len(categories['critical']),
                'high': len(categories['high']),
                'medium': len(categories['medium']),
                'low': len(categories['low'])
            }
        }
