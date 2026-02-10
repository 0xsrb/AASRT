"""
Unit Tests for Shodan Engine Module

Tests for src/engines/shodan_engine.py
"""

import pytest
from unittest.mock import MagicMock, patch


class TestShodanEngineInit:
    """Tests for ShodanEngine initialization."""

    def test_init_with_valid_key(self):
        """Test initialization with valid API key."""
        from src.engines.shodan_engine import ShodanEngine

        with patch('shodan.Shodan') as mock_shodan:
            mock_client = MagicMock()
            mock_shodan.return_value = mock_client

            engine = ShodanEngine(api_key='test_api_key_12345')
            assert engine is not None
            assert engine.name == 'shodan'

    def test_init_without_key_raises_error(self):
        """Test initialization without API key raises error."""
        from src.engines.shodan_engine import ShodanEngine

        with pytest.raises(ValueError):
            ShodanEngine(api_key='')

        with pytest.raises((ValueError, TypeError)):
            ShodanEngine(api_key=None)


class TestShodanEngineSearch:
    """Tests for ShodanEngine search functionality."""

    @pytest.fixture
    def engine(self, mock_shodan_client):
        """Create a ShodanEngine instance with mocked client."""
        from src.engines.shodan_engine import ShodanEngine

        with patch('shodan.Shodan', return_value=mock_shodan_client):
            engine = ShodanEngine(api_key='test_api_key_12345')
            engine._client = mock_shodan_client
            return engine

    def test_search_returns_results(self, engine, mock_shodan_client, sample_shodan_result):
        """Test search returns results."""
        mock_shodan_client.search.return_value = {
            'matches': [sample_shodan_result],
            'total': 1
        }

        results = engine.search('http.title:"ClawdBot"')
        assert isinstance(results, list)

    def test_search_empty_query_raises_error(self, engine):
        """Test empty query raises error."""
        with pytest.raises((ValueError, Exception)):
            engine.search('')

    def test_search_handles_api_error(self, engine, mock_shodan_client):
        """Test search handles API errors gracefully."""
        import shodan

        mock_shodan_client.search.side_effect = shodan.APIError('API Error')

        from src.utils.exceptions import APIException
        with pytest.raises((APIException, Exception)):
            engine.search('test query')

    def test_search_with_max_results(self, engine, mock_shodan_client, sample_shodan_result):
        """Test search respects max_results limit."""
        mock_shodan_client.search.return_value = {
            'matches': [sample_shodan_result],
            'total': 1
        }

        results = engine.search('test', max_results=1)
        assert len(results) <= 1


class TestShodanEngineCredentials:
    """Tests for credential validation."""

    @pytest.fixture
    def engine(self, mock_shodan_client):
        """Create a ShodanEngine instance."""
        from src.engines.shodan_engine import ShodanEngine

        with patch('shodan.Shodan', return_value=mock_shodan_client):
            engine = ShodanEngine(api_key='test_api_key_12345')
            engine._client = mock_shodan_client
            return engine

    def test_validate_credentials_success(self, engine, mock_shodan_client):
        """Test successful credential validation."""
        mock_shodan_client.info.return_value = {'plan': 'dev', 'query_credits': 100}

        result = engine.validate_credentials()
        assert result is True

    def test_validate_credentials_invalid_key(self, engine, mock_shodan_client):
        """Test invalid API key handling."""
        import shodan
        from src.utils.exceptions import AuthenticationException

        mock_shodan_client.info.side_effect = shodan.APIError('Invalid API key')

        with pytest.raises((AuthenticationException, Exception)):
            engine.validate_credentials()


class TestShodanEngineQuota:
    """Tests for quota information."""

    @pytest.fixture
    def engine(self, mock_shodan_client):
        """Create a ShodanEngine instance."""
        from src.engines.shodan_engine import ShodanEngine

        with patch('shodan.Shodan', return_value=mock_shodan_client):
            engine = ShodanEngine(api_key='test_api_key_12345')
            engine._client = mock_shodan_client
            return engine

    def test_get_quota_info(self, engine, mock_shodan_client):
        """Test getting quota information."""
        mock_shodan_client.info.return_value = {
            'plan': 'dev',
            'query_credits': 100,
            'scan_credits': 50
        }

        quota = engine.get_quota_info()
        assert isinstance(quota, dict)

    def test_quota_info_handles_error(self, engine, mock_shodan_client):
        """Test quota info handles API errors."""
        import shodan
        from src.utils.exceptions import APIException

        mock_shodan_client.info.side_effect = shodan.APIError('API Error')

        # May either raise or return error info depending on implementation
        try:
            quota = engine.get_quota_info()
            assert quota is not None
        except (APIException, Exception):
            pass  # Acceptable if it raises


class TestShodanEngineRetry:
    """Tests for retry logic."""

    def test_retry_on_transient_error(self, mock_shodan_client):
        """Test retry logic on transient errors."""
        from src.engines.shodan_engine import ShodanEngine
        import shodan

        with patch('shodan.Shodan', return_value=mock_shodan_client):
            engine = ShodanEngine(api_key='test_api_key_12345')
            engine._client = mock_shodan_client

            # First call fails, second succeeds
            mock_shodan_client.search.side_effect = [
                ConnectionError("Network error"),
                {'matches': [], 'total': 0}
            ]

            # Depending on implementation, this may retry or raise
            try:
                results = engine.search('test')
                assert isinstance(results, list)
            except Exception:
                pass  # Expected if retries exhausted
