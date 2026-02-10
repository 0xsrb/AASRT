"""
Pytest Configuration and Shared Fixtures

This module provides shared fixtures and configuration for all tests.
"""

import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Generator, List
from unittest.mock import MagicMock, patch

import pytest

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


# =============================================================================
# Environment Fixtures
# =============================================================================

@pytest.fixture(scope="session")
def test_env():
    """Set up test environment variables."""
    original_env = os.environ.copy()
    
    os.environ.update({
        'SHODAN_API_KEY': 'test_api_key_12345',
        'AASRT_ENVIRONMENT': 'testing',
        'AASRT_LOG_LEVEL': 'DEBUG',
        'AASRT_DEBUG': 'true',
    })
    
    yield os.environ
    
    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def temp_db(temp_dir):
    """Create a temporary database path."""
    return temp_dir / "test_scanner.db"


# =============================================================================
# Mock Data Fixtures
# =============================================================================

@pytest.fixture
def sample_shodan_result() -> Dict[str, Any]:
    """Sample Shodan API response."""
    return {
        'ip_str': '192.0.2.1',
        'port': 8080,
        'transport': 'tcp',
        'hostnames': ['test.example.com'],
        'org': 'Test Organization',
        'asn': 'AS12345',
        'isp': 'Test ISP',
        'data': 'HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nClawdBot Dashboard',
        'location': {
            'country_code': 'US',
            'country_name': 'United States',
            'city': 'Test City',
            'latitude': 37.7749,
            'longitude': -122.4194
        },
        'http': {
            'status': 200,
            'title': 'ClawdBot Dashboard',
            'server': 'nginx/1.18.0',
            'html': '<html><body>ClawdBot Dashboard</body></html>'
        },
        'vulns': ['CVE-2021-44228'],
        'timestamp': '2024-01-15T10:30:00.000000'
    }


@pytest.fixture
def sample_search_results(sample_shodan_result) -> List[Dict[str, Any]]:
    """Multiple sample Shodan results."""
    results = [sample_shodan_result]
    
    # Add more varied results
    results.append({
        **sample_shodan_result,
        'ip_str': '192.0.2.2',
        'port': 3000,
        'http': {
            'status': 200,
            'title': 'AutoGPT Interface',
            'server': 'Python/3.11'
        }
    })
    
    results.append({
        **sample_shodan_result,
        'ip_str': '192.0.2.3',
        'port': 443,
        'http': {
            'status': 401,
            'title': 'Login Required'
        }
    })
    
    return results


@pytest.fixture
def sample_vulnerability() -> Dict[str, Any]:
    """Sample vulnerability data."""
    return {
        'check_name': 'exposed_dashboard',
        'severity': 'HIGH',
        'cvss_score': 7.5,
        'description': 'Dashboard accessible without authentication',
        'evidence': {'http_title': 'ClawdBot Dashboard'},
        'remediation': 'Implement authentication',
        'cwe_id': 'CWE-306'
    }


# =============================================================================
# Mock Service Fixtures
# =============================================================================

@pytest.fixture
def mock_shodan_client():
    """Mock Shodan API client."""
    with patch('shodan.Shodan') as mock:
        client = MagicMock()
        client.info.return_value = {
            'plan': 'dev',
            'query_credits': 100,
            'scan_credits': 50
        }
        mock.return_value = client
        yield client


@pytest.fixture
def mock_config(temp_dir, temp_db):
    """Mock configuration object."""
    config = MagicMock()
    config.get_shodan_key.return_value = 'test_api_key'
    config.get.side_effect = lambda *args, default=None: {
        ('database', 'type'): 'sqlite',
        ('database', 'sqlite', 'path'): str(temp_db),
        ('logging', 'level'): 'DEBUG',
        ('reporting', 'output_dir'): str(temp_dir / 'reports'),
        ('vulnerability_checks',): {'passive_only': True},
    }.get(args, default)
    return config


# =============================================================================
# Database Fixtures
# =============================================================================

@pytest.fixture
def test_database(mock_config, temp_db):
    """Create a test database instance."""
    from src.storage.database import Database
    
    # Patch config to use temp database
    with patch('src.storage.database.Config', return_value=mock_config):
        db = Database(mock_config)
        yield db
        db.close()

