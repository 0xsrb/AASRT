"""
Configuration management for AASRT.

This module provides a production-ready configuration management system with:
- Singleton pattern for global configuration access
- YAML file loading with deep merging
- Environment variable overrides
- Validation of required settings
- Support for structured logging configuration
- Health check capabilities

Configuration priority (highest to lowest):
1. Environment variables
2. YAML configuration file
3. Default values

Example:
    >>> from src.utils.config import Config
    >>> config = Config()
    >>> shodan_key = config.get_shodan_key()
    >>> log_level = config.get('logging', 'level', default='INFO')

Environment Variables:
    SHODAN_API_KEY: Required Shodan API key
    AASRT_LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    AASRT_ENVIRONMENT: Deployment environment (development, staging, production)
    AASRT_DEBUG: Enable debug mode (true/false)
    DB_TYPE: Database type (sqlite, postgresql)
    DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD: PostgreSQL settings
"""

import os
import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml
from dotenv import load_dotenv

from .exceptions import ConfigurationException
from .logger import get_logger

logger = get_logger(__name__)

# =============================================================================
# Validation Constants
# =============================================================================

VALID_LOG_LEVELS: Set[str] = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
VALID_ENVIRONMENTS: Set[str] = {"development", "staging", "production"}
VALID_DB_TYPES: Set[str] = {"sqlite", "postgresql", "mysql"}
REQUIRED_SETTINGS: List[str] = []  # API key is optional until scan is run


class Config:
    """
    Configuration manager for AASRT with singleton pattern.

    This class provides centralized configuration management with:
    - Thread-safe singleton access
    - YAML file configuration
    - Environment variable overrides
    - Validation of critical settings
    - Health check for configuration state

    Attributes:
        _instance: Singleton instance.
        _config: Configuration dictionary.
        _initialized: Flag indicating initialization status.
        _config_path: Path to loaded configuration file.
        _environment: Current deployment environment.

    Example:
        >>> config = Config()
        >>> api_key = config.get_shodan_key()
        >>> if not api_key:
        ...     print("Warning: Shodan API key not configured")
    """

    _instance: Optional['Config'] = None
    _config: Dict[str, Any] = {}

    def __new__(cls, config_path: Optional[str] = None):
        """
        Singleton pattern implementation.

        Args:
            config_path: Optional path to YAML configuration file.

        Returns:
            Singleton Config instance.
        """
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, config_path: Optional[str] = None) -> None:
        """
        Initialize configuration from multiple sources.

        Configuration is loaded in order of priority:
        1. Default values
        2. YAML configuration file
        3. Environment variables (highest priority)

        Args:
            config_path: Path to YAML configuration file.
                        If not provided, searches common locations.

        Raises:
            ConfigurationException: If YAML file is malformed.
        """
        if self._initialized:
            return

        # Load environment variables from .env file
        load_dotenv()

        # Store metadata
        self._config_path: Optional[str] = None
        self._environment: str = os.getenv('AASRT_ENVIRONMENT', 'development')
        self._validation_errors: List[str] = []

        # Default configuration
        self._config = self._get_defaults()

        # Load from file if provided
        if config_path:
            self._load_from_file(config_path)
        else:
            # Try to find config file in common locations
            for path in ['config.yaml', 'config.yml', './config/config.yaml']:
                if os.path.exists(path):
                    self._load_from_file(path)
                    break

        # Override with environment variables
        self._load_from_env()

        # Validate configuration
        self._validate_config()

        self._initialized = True
        logger.info(f"Configuration initialized (environment: {self._environment})")

    def _get_defaults(self) -> Dict[str, Any]:
        """Get default configuration values."""
        return {
            'shodan': {
                'enabled': True,
                'rate_limit': 1,
                'max_results': 100,
                'timeout': 30
            },
            'vulnerability_checks': {
                'enabled': True,
                'passive_only': True,
                'timeout_per_check': 10
            },
            'reporting': {
                'formats': ['json', 'csv'],
                'output_dir': './reports',
                'anonymize_by_default': False
            },
            'filtering': {
                'whitelist_ips': [],
                'whitelist_domains': [],
                'min_confidence_score': 70,
                'exclude_honeypots': True
            },
            'logging': {
                'level': 'INFO',
                'file': './logs/scanner.log',
                'max_size_mb': 100,
                'backup_count': 5
            },
            'database': {
                'type': 'sqlite',
                'sqlite': {
                    'path': './data/scanner.db'
                }
            },
            'api_keys': {},
            'clawsec': {
                'enabled': True,
                'feed_url': 'https://clawsec.prompt.security/advisories/feed.json',
                'cache_ttl_seconds': 86400,  # 24 hours
                'cache_file': './data/clawsec_cache.json',
                'offline_mode': False,
                'timeout': 30,
                'auto_refresh': True
            }
        }

    def _load_from_file(self, path: str) -> None:
        """
        Load configuration from YAML file.

        Args:
            path: Path to YAML configuration file.

        Raises:
            ConfigurationException: If YAML is malformed.
        """
        try:
            with open(path, 'r') as f:
                file_config = yaml.safe_load(f)
                if file_config:
                    self._deep_merge(self._config, file_config)
                    self._config_path = path
                    logger.info(f"Loaded configuration from {path}")
        except FileNotFoundError:
            logger.warning(f"Configuration file not found: {path}")
        except yaml.YAMLError as e:
            raise ConfigurationException(f"Invalid YAML in configuration file: {e}")

    def _load_from_env(self) -> None:
        """
        Load settings from environment variables.

        Environment variables override file-based configuration.
        This method handles all supported environment variables.
        """
        # Load Shodan API key
        shodan_key = os.getenv('SHODAN_API_KEY')
        if shodan_key:
            self._set_nested(('api_keys', 'shodan'), shodan_key)

        # Load log level if set
        log_level = os.getenv('AASRT_LOG_LEVEL', '').upper()
        if log_level and log_level in VALID_LOG_LEVELS:
            self._set_nested(('logging', 'level'), log_level)
        elif log_level:
            logger.warning(f"Invalid log level '{log_level}', using default")

        # Load environment setting
        env = os.getenv('AASRT_ENVIRONMENT', '').lower()
        if env and env in VALID_ENVIRONMENTS:
            self._environment = env

        # Load debug flag
        debug = os.getenv('AASRT_DEBUG', '').lower()
        if debug in ('true', '1', 'yes'):
            self._set_nested(('logging', 'level'), 'DEBUG')

        # Load database settings from environment
        db_type = os.getenv('DB_TYPE', '').lower()
        if db_type and db_type in VALID_DB_TYPES:
            self._set_nested(('database', 'type'), db_type)

        # PostgreSQL settings from environment
        if os.getenv('DB_HOST'):
            self._set_nested(('database', 'postgresql', 'host'), os.getenv('DB_HOST'))
        if os.getenv('DB_PORT'):
            try:
                port = int(os.getenv('DB_PORT'))
                self._set_nested(('database', 'postgresql', 'port'), port)
            except ValueError:
                logger.warning("Invalid DB_PORT, using default")
        if os.getenv('DB_NAME'):
            self._set_nested(('database', 'postgresql', 'database'), os.getenv('DB_NAME'))
        if os.getenv('DB_USER'):
            self._set_nested(('database', 'postgresql', 'user'), os.getenv('DB_USER'))
        if os.getenv('DB_PASSWORD'):
            self._set_nested(('database', 'postgresql', 'password'), os.getenv('DB_PASSWORD'))
        if os.getenv('DB_SSL_MODE'):
            self._set_nested(('database', 'postgresql', 'ssl_mode'), os.getenv('DB_SSL_MODE'))

        # Max results limit
        max_results = os.getenv('AASRT_MAX_RESULTS')
        if max_results:
            try:
                self._set_nested(('shodan', 'max_results'), int(max_results))
            except ValueError:
                logger.warning("Invalid AASRT_MAX_RESULTS, using default")

    def _validate_config(self) -> None:
        """
        Validate configuration settings.

        Checks for valid values and logs warnings for potential issues.
        Does not raise exceptions to allow graceful degradation.
        """
        self._validation_errors = []

        # Validate log level
        log_level = self.get('logging', 'level', default='INFO')
        if log_level.upper() not in VALID_LOG_LEVELS:
            self._validation_errors.append(f"Invalid log level: {log_level}")

        # Validate database type
        db_type = self.get('database', 'type', default='sqlite')
        if db_type.lower() not in VALID_DB_TYPES:
            self._validation_errors.append(f"Invalid database type: {db_type}")

        # Validate max results is positive
        max_results = self.get('shodan', 'max_results', default=100)
        if not isinstance(max_results, int) or max_results < 1:
            self._validation_errors.append(f"Invalid max_results: {max_results}")

        # Check for Shodan API key (warning, not error)
        if not self.get_shodan_key():
            logger.debug("Shodan API key not configured - scans will require it")

        # Log validation errors
        for error in self._validation_errors:
            logger.warning(f"Configuration validation: {error}")

    def _deep_merge(self, base: Dict, overlay: Dict) -> None:
        """
        Deep merge overlay dictionary into base dictionary.

        Args:
            base: Base dictionary to merge into (modified in place).
            overlay: Overlay dictionary to merge from.
        """
        for key, value in overlay.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def _set_nested(self, path: tuple, value: Any) -> None:
        """
        Set a nested configuration value by key path.

        Args:
            path: Tuple of keys representing the path.
            value: Value to set at the path.
        """
        current = self._config
        for key in path[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        current[path[-1]] = value

    def get(self, *keys: str, default: Any = None) -> Any:
        """
        Get a configuration value by nested keys.

        Args:
            *keys: Nested keys to traverse (e.g., 'database', 'type').
            default: Default value if path not found.

        Returns:
            Configuration value or default.

        Example:
            >>> config.get('shodan', 'max_results', default=100)
            100
        """
        current = self._config
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        return current

    def get_shodan_key(self) -> Optional[str]:
        """
        Get Shodan API key.

        Returns:
            Shodan API key string, or None if not configured.
        """
        return self.get('api_keys', 'shodan')

    def get_shodan_config(self) -> Dict[str, Any]:
        """
        Get Shodan configuration dictionary.

        Returns:
            Dictionary with Shodan settings (enabled, rate_limit, max_results, timeout).
        """
        return self.get('shodan', default={})

    def get_clawsec_config(self) -> Dict[str, Any]:
        """
        Get ClawSec configuration dictionary.

        Returns:
            Dictionary with ClawSec settings.
        """
        return self.get('clawsec', default={})

    def is_clawsec_enabled(self) -> bool:
        """
        Check if ClawSec integration is enabled.

        Returns:
            True if ClawSec vulnerability lookup is enabled.
        """
        return self.get('clawsec', 'enabled', default=True)

    def get_database_config(self) -> Dict[str, Any]:
        """
        Get database configuration.

        Returns:
            Dictionary with database settings.
        """
        return self.get('database', default={})

    def get_logging_config(self) -> Dict[str, Any]:
        """
        Get logging configuration.

        Returns:
            Dictionary with logging settings (level, file, max_size_mb, backup_count).
        """
        return self.get('logging', default={})

    @property
    def environment(self) -> str:
        """
        Get current deployment environment.

        Returns:
            Environment string (development, staging, production).
        """
        return self._environment

    @property
    def is_production(self) -> bool:
        """
        Check if running in production environment.

        Returns:
            True if environment is 'production'.
        """
        return self._environment == 'production'

    @property
    def is_debug(self) -> bool:
        """
        Check if debug mode is enabled.

        Returns:
            True if log level is DEBUG.
        """
        return self.get('logging', 'level', default='INFO').upper() == 'DEBUG'

    @property
    def all(self) -> Dict[str, Any]:
        """
        Get all configuration as dictionary.

        Returns:
            Copy of complete configuration dictionary.
        """
        return self._config.copy()

    def reload(self, config_path: Optional[str] = None) -> None:
        """
        Reload configuration from file and environment.

        Use this to refresh configuration without restarting the application.

        Args:
            config_path: Optional path to configuration file.
                        If None, uses previously loaded file path.
        """
        logger.info("Reloading configuration...")
        self._initialized = False
        self._config = self._get_defaults()

        # Use new path or fall back to previously loaded path
        path_to_load = config_path or self._config_path
        if path_to_load:
            self._load_from_file(path_to_load)

        self._load_from_env()
        self._validate_config()
        self._initialized = True
        logger.info("Configuration reloaded successfully")

    def health_check(self) -> Dict[str, Any]:
        """
        Perform a health check on configuration.

        Returns:
            Dictionary with health status:
                - healthy: bool indicating if configuration is valid
                - environment: Current deployment environment
                - config_file: Path to loaded config file (if any)
                - validation_errors: List of validation errors
                - shodan_configured: Whether Shodan API key is set
                - clawsec_enabled: Whether ClawSec is enabled
        """
        return {
            "healthy": len(self._validation_errors) == 0,
            "environment": self._environment,
            "config_file": self._config_path,
            "validation_errors": self._validation_errors.copy(),
            "shodan_configured": bool(self.get_shodan_key()),
            "clawsec_enabled": self.is_clawsec_enabled(),
            "log_level": self.get('logging', 'level', default='INFO'),
            "database_type": self.get('database', 'type', default='sqlite')
        }

    @staticmethod
    def reset_instance() -> None:
        """
        Reset the singleton instance (for testing).

        Warning:
            This should only be used in tests. It will cause any
            existing references to the old instance to be stale.
        """
        Config._instance = None
