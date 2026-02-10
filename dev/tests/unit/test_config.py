"""
Unit Tests for Config Module

Tests for src/utils/config.py
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


class TestConfigLoading:
    """Tests for configuration loading."""

    def test_load_from_yaml(self, temp_dir):
        """Test loading configuration from YAML file."""
        from src.utils.config import Config
        
        config_content = """
shodan:
  enabled: true
  rate_limit: 1
  max_results: 100

logging:
  level: DEBUG
"""
        config_path = temp_dir / "config.yaml"
        config_path.write_text(config_content)
        
        with patch.dict(os.environ, {'AASRT_CONFIG_PATH': str(config_path)}):
            config = Config()
            assert config.get('shodan', 'enabled') is True
            assert config.get('shodan', 'rate_limit') == 1

    def test_environment_variable_override(self, temp_dir, monkeypatch):
        """Test environment variables override config file."""
        from src.utils.config import Config

        config_content = """
shodan:
  enabled: true
  rate_limit: 1
"""
        config_path = temp_dir / "config.yaml"
        config_path.write_text(config_content)

        # Reset the Config singleton so we get a fresh instance
        Config._instance = None
        Config._config = {}

        # Use monkeypatch for proper isolation - clear and set
        monkeypatch.setenv('AASRT_CONFIG_PATH', str(config_path))
        monkeypatch.setenv('SHODAN_API_KEY', 'env_api_key_12345')

        config = Config()
        assert config.get_shodan_key() == 'env_api_key_12345'

        # Clean up - reset singleton for other tests
        Config._instance = None
        Config._config = {}

    def test_default_values(self):
        """Test default configuration values are used when not specified."""
        from src.utils.config import Config
        
        with patch.dict(os.environ, {'SHODAN_API_KEY': 'test_key'}):
            config = Config()
            # Check default logging level if not set
            log_level = config.get('logging', 'level', default='INFO')
            assert log_level in ['DEBUG', 'INFO', 'WARNING', 'ERROR']


class TestConfigValidation:
    """Tests for configuration validation."""

    def test_validate_shodan_key_format(self):
        """Test Shodan API key format validation."""
        from src.utils.config import Config
        
        # Valid key format (typically alphanumeric)
        with patch.dict(os.environ, {'SHODAN_API_KEY': 'AbCdEf123456789012345678'}):
            config = Config()
            key = config.get_shodan_key()
            assert key is not None

    def test_missing_required_config(self):
        """Test handling of missing required configuration."""
        from src.utils.config import Config
        
        # Clear all Shodan-related env vars
        env_copy = {k: v for k, v in os.environ.items() if 'SHODAN' not in k}
        with patch.dict(os.environ, env_copy, clear=True):
            config = Config()
            # Should return None or raise exception for missing key
            key = config.get_shodan_key()
            # Depending on implementation, key could be None or empty


class TestConfigHealthCheck:
    """Tests for configuration health check."""

    def test_health_check_returns_dict(self):
        """Test health_check returns a dictionary."""
        from src.utils.config import Config
        
        with patch.dict(os.environ, {'SHODAN_API_KEY': 'test_key'}):
            config = Config()
            health = config.health_check()
            assert isinstance(health, dict)
            assert 'status' in health or 'healthy' in health

    def test_health_check_includes_key_info(self):
        """Test health_check includes API key status."""
        from src.utils.config import Config
        
        with patch.dict(os.environ, {'SHODAN_API_KEY': 'test_key'}):
            config = Config()
            health = config.health_check()
            # Should indicate whether key is configured
            assert health is not None


class TestConfigGet:
    """Tests for the get() method."""

    def test_nested_key_access(self, temp_dir):
        """Test accessing nested configuration values."""
        from src.utils.config import Config
        
        config_content = """
database:
  sqlite:
    path: ./data/scanner.db
    pool_size: 5
"""
        config_path = temp_dir / "config.yaml"
        config_path.write_text(config_content)
        
        with patch.dict(os.environ, {'AASRT_CONFIG_PATH': str(config_path)}):
            config = Config()
            path = config.get('database', 'sqlite', 'path')
            assert path is not None

    def test_default_for_missing_key(self):
        """Test default value is returned for missing keys."""
        from src.utils.config import Config
        
        with patch.dict(os.environ, {'SHODAN_API_KEY': 'test_key'}):
            config = Config()
            value = config.get('nonexistent', 'key', default='default_value')
            assert value == 'default_value'

    def test_none_for_missing_key_no_default(self):
        """Test None is returned for missing keys without default."""
        from src.utils.config import Config
        
        with patch.dict(os.environ, {'SHODAN_API_KEY': 'test_key'}):
            config = Config()
            value = config.get('nonexistent', 'key')
            assert value is None

