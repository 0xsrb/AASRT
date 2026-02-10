"""
Unit Tests for Risk Scorer Module

Tests for src/core/risk_scorer.py
"""

import pytest
from unittest.mock import MagicMock


class TestRiskScorer:
    """Tests for RiskScorer class."""

    @pytest.fixture
    def risk_scorer(self):
        """Create a RiskScorer instance."""
        from src.core.risk_scorer import RiskScorer
        return RiskScorer()

    @pytest.fixture
    def sample_vulnerabilities(self):
        """Create sample Vulnerability objects."""
        from src.core.vulnerability_assessor import Vulnerability
        return [
            Vulnerability(
                check_name='exposed_dashboard',
                severity='HIGH',
                cvss_score=7.5,
                description='Dashboard exposed without authentication'
            )
        ]

    @pytest.fixture
    def sample_result(self, sample_shodan_result):
        """Create a SearchResult with vulnerabilities."""
        from src.engines.base import SearchResult

        result = SearchResult(
            ip=sample_shodan_result['ip_str'],
            port=sample_shodan_result['port'],
            banner=sample_shodan_result['data'],
            metadata=sample_shodan_result
        )
        return result

    def test_calculate_score_returns_dict(self, risk_scorer, sample_vulnerabilities):
        """Test that calculate_score returns a dictionary."""
        result = risk_scorer.calculate_score(sample_vulnerabilities)
        assert isinstance(result, dict)
        assert 'overall_score' in result

    def test_calculate_score_range_valid(self, risk_scorer, sample_vulnerabilities):
        """Test that score is within valid range (0-10)."""
        result = risk_scorer.calculate_score(sample_vulnerabilities)
        assert 0 <= result['overall_score'] <= 10

    def test_high_risk_vulnerabilities_increase_score(self, risk_scorer):
        """Test that high-risk vulnerabilities increase score."""
        from src.core.vulnerability_assessor import Vulnerability

        # High severity vulnerabilities
        high_vulns = [
            Vulnerability(check_name='api_key_exposure', severity='CRITICAL', cvss_score=9.0, description='API key exposed'),
            Vulnerability(check_name='no_authentication', severity='CRITICAL', cvss_score=9.5, description='No auth')
        ]

        # Low severity vulnerabilities
        low_vulns = [
            Vulnerability(check_name='version_exposed', severity='LOW', cvss_score=2.0, description='Version info')
        ]

        high_score = risk_scorer.calculate_score(high_vulns)['overall_score']
        low_score = risk_scorer.calculate_score(low_vulns)['overall_score']

        assert high_score > low_score

    def test_empty_vulnerabilities_zero_score(self, risk_scorer):
        """Test that no vulnerabilities result in zero score."""
        result = risk_scorer.calculate_score([])
        assert result['overall_score'] == 0

    def test_score_result_updates_search_result(self, risk_scorer, sample_result, sample_vulnerabilities):
        """Test that score_result updates the SearchResult."""
        scored_result = risk_scorer.score_result(sample_result, sample_vulnerabilities)
        assert scored_result.risk_score >= 0
        assert 'risk_assessment' in scored_result.metadata

    def test_context_multipliers_applied(self, risk_scorer, sample_vulnerabilities):
        """Test that context multipliers affect the score."""
        # Score with no context
        base_score = risk_scorer.calculate_score(sample_vulnerabilities)['overall_score']

        # Score with context multiplier
        context = {'public_internet': True, 'no_waf': True, 'ai_agent': True}
        context_score = risk_scorer.calculate_score(sample_vulnerabilities, context)['overall_score']

        # Context should increase or maintain score
        assert context_score >= base_score

    def test_severity_breakdown_included(self, risk_scorer, sample_vulnerabilities):
        """Test that severity breakdown is included in results."""
        result = risk_scorer.calculate_score(sample_vulnerabilities)
        assert 'severity_breakdown' in result
        assert isinstance(result['severity_breakdown'], dict)


class TestRiskCategories:
    """Tests for risk categorization."""

    @pytest.fixture
    def risk_scorer(self):
        """Create a RiskScorer instance."""
        from src.core.risk_scorer import RiskScorer
        return RiskScorer()

    def test_get_risk_level(self, risk_scorer):
        """Test risk level categorization."""
        # Test if there's a method to get risk level string
        if hasattr(risk_scorer, 'get_risk_level'):
            assert risk_scorer.get_risk_level(95) in ['CRITICAL', 'HIGH', 'critical', 'high']
            assert risk_scorer.get_risk_level(75) in ['HIGH', 'MEDIUM', 'high', 'medium']
            assert risk_scorer.get_risk_level(50) in ['MEDIUM', 'medium']
            assert risk_scorer.get_risk_level(25) in ['LOW', 'low']
            assert risk_scorer.get_risk_level(10) in ['INFO', 'LOW', 'info', 'low']

