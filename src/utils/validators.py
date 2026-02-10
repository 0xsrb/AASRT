"""
Input validation utilities for AASRT.

This module provides comprehensive input validation and sanitization functions
for security-sensitive operations including:
- IP address and domain validation
- Port number and query string validation
- File path sanitization (directory traversal prevention)
- API key format validation
- Template name whitelist validation
- Configuration value validation

All validators raise ValidationException on invalid input with descriptive
error messages for debugging.

Example:
    >>> from src.utils.validators import validate_ip, validate_file_path
    >>> validate_ip("192.168.1.1")  # Returns True
    >>> validate_file_path("../../../etc/passwd")  # Raises ValidationException
"""

import re
import os
import ipaddress
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

import validators

from .exceptions import ValidationException


# =============================================================================
# Constants
# =============================================================================

# Valid log levels for configuration
VALID_LOG_LEVELS: Set[str] = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

# Valid environment names
VALID_ENVIRONMENTS: Set[str] = {"development", "staging", "production"}

# Valid database types
VALID_DB_TYPES: Set[str] = {"sqlite", "postgresql", "mysql"}

# Valid report formats
VALID_REPORT_FORMATS: Set[str] = {"json", "csv", "html", "pdf"}

# Valid query template names (whitelist)
VALID_TEMPLATES: Set[str] = {
    "clawdbot_instances",
    "autogpt_instances",
    "langchain_agents",
    "openai_agents",
    "anthropic_agents",
    "ai_agent_general",
    "agent_gpt",
    "babyagi_instances",
    "crewai_instances",
    "autogen_instances",
    "superagi_instances",
    "flowise_instances",
    "dify_instances",
}

# Maximum limits for various inputs
MAX_QUERY_LENGTH: int = 2000
MAX_RESULTS_LIMIT: int = 10000
MIN_RESULTS_LIMIT: int = 1
MAX_PORT: int = 65535
MIN_PORT: int = 1
MAX_FILE_PATH_LENGTH: int = 4096
MAX_API_KEY_LENGTH: int = 256


# =============================================================================
# IP and Network Validators
# =============================================================================

def validate_ip(ip: str) -> bool:
    """
    Validate an IP address (IPv4 or IPv6).

    Args:
        ip: IP address string to validate.

    Returns:
        True if the IP address is valid.

    Raises:
        ValidationException: If IP is None, empty, or invalid format.

    Example:
        >>> validate_ip("192.168.1.1")
        True
        >>> validate_ip("2001:db8::1")
        True
        >>> validate_ip("invalid")
        ValidationException: Invalid IP address: invalid
    """
    if ip is None:
        raise ValidationException("IP address cannot be None")

    if not isinstance(ip, str):
        raise ValidationException(f"IP address must be a string, got {type(ip).__name__}")

    ip = ip.strip()
    if not ip:
        raise ValidationException("IP address cannot be empty")

    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        raise ValidationException(f"Invalid IP address: {ip}")


def validate_domain(domain: str) -> bool:
    """
    Validate a domain name.

    Args:
        domain: Domain name string

    Returns:
        True if valid

    Raises:
        ValidationException: If domain is invalid
    """
    if validators.domain(domain):
        return True
    raise ValidationException(f"Invalid domain: {domain}")


def validate_query(query: str, engine: str) -> bool:
    """
    Validate a search query for a specific engine.

    Args:
        query: Search query string
        engine: Search engine name

    Returns:
        True if valid

    Raises:
        ValidationException: If query is invalid
    """
    if not query or not query.strip():
        raise ValidationException("Query cannot be empty")

    # Check for potentially dangerous characters
    dangerous_patterns = [
        r'[<>]',  # Script injection attempts
        r'\x00',  # Null bytes
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, query):
            raise ValidationException(f"Query contains invalid characters: {pattern}")

    # Engine-specific validation
    if engine == "shodan":
        # Shodan queries should be reasonable length
        if len(query) > 1000:
            raise ValidationException("Shodan query too long (max 1000 chars)")

    elif engine == "censys":
        # Censys queries should be reasonable length
        if len(query) > 2000:
            raise ValidationException("Censys query too long (max 2000 chars)")

    return True


def validate_port(port: int) -> bool:
    """
    Validate a port number.

    Args:
        port: Port number

    Returns:
        True if valid

    Raises:
        ValidationException: If port is invalid
    """
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise ValidationException(f"Invalid port number: {port}")
    return True


def validate_api_key(api_key: str, engine: str) -> bool:
    """
    Validate API key format for a specific engine.

    Args:
        api_key: API key string
        engine: Search engine name

    Returns:
        True if valid

    Raises:
        ValidationException: If API key format is invalid
    """
    if not api_key or not api_key.strip():
        raise ValidationException(f"API key for {engine} cannot be empty")

    # Basic format validation (not checking actual validity)
    if engine == "shodan":
        # Shodan API keys are typically 32 characters
        if len(api_key) < 20:
            raise ValidationException("Shodan API key appears too short")

    return True


def sanitize_output(text: str) -> str:
    """
    Sanitize text for safe output (remove potential secrets).

    This function redacts sensitive patterns like API keys, passwords, and
    authentication tokens to prevent accidental exposure in logs or output.

    Args:
        text: Text to sanitize.

    Returns:
        Sanitized text with sensitive data replaced by REDACTED markers.

    Example:
        >>> sanitize_output("key: sk-ant-abc123...")
        'key: sk-ant-***REDACTED***'
    """
    if text is None:
        return ""

    if not isinstance(text, str):
        text = str(text)

    # Patterns for sensitive data (order matters - more specific first)
    patterns = [
        # Anthropic API keys
        (r'sk-ant-[a-zA-Z0-9-_]{20,}', 'sk-ant-***REDACTED***'),
        # OpenAI API keys
        (r'sk-[a-zA-Z0-9]{40,}', 'sk-***REDACTED***'),
        # AWS Access Key
        (r'AKIA[0-9A-Z]{16}', 'AKIA***REDACTED***'),
        # AWS Secret Key
        (r'(?i)aws_secret_access_key["\s:=]+["\']?[A-Za-z0-9/+=]{40}', 'aws_secret_access_key=***REDACTED***'),
        # GitHub tokens
        (r'ghp_[a-zA-Z0-9]{36}', 'ghp_***REDACTED***'),
        (r'gho_[a-zA-Z0-9]{36}', 'gho_***REDACTED***'),
        # Google API keys
        (r'AIza[0-9A-Za-z-_]{35}', 'AIza***REDACTED***'),
        # Stripe keys
        (r'sk_live_[a-zA-Z0-9]{24,}', 'sk_live_***REDACTED***'),
        (r'sk_test_[a-zA-Z0-9]{24,}', 'sk_test_***REDACTED***'),
        # Shodan API key (32 hex chars)
        (r'[a-fA-F0-9]{32}', '***REDACTED_KEY***'),
        # Generic password patterns
        (r'password["\s:=]+["\']?[\w@#$%^&*!?]+', 'password=***REDACTED***'),
        (r'passwd["\s:=]+["\']?[\w@#$%^&*!?]+', 'passwd=***REDACTED***'),
        (r'secret["\s:=]+["\']?[\w@#$%^&*!?]+', 'secret=***REDACTED***'),
        # Bearer tokens
        (r'Bearer\s+[a-zA-Z0-9._-]+', 'Bearer ***REDACTED***'),
        # Basic auth
        (r'Basic\s+[a-zA-Z0-9+/=]+', 'Basic ***REDACTED***'),
    ]

    result = text
    for pattern, replacement in patterns:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)

    return result


# =============================================================================
# File Path Validators
# =============================================================================

def validate_file_path(
    path: str,
    must_exist: bool = False,
    allow_absolute: bool = True,
    base_dir: Optional[str] = None
) -> str:
    """
    Validate and sanitize a file path to prevent directory traversal attacks.

    Args:
        path: File path to validate.
        must_exist: If True, the file must exist.
        allow_absolute: If True, allow absolute paths.
        base_dir: If provided, ensure path is within this directory.

    Returns:
        Sanitized, normalized file path.

    Raises:
        ValidationException: If path is invalid or potentially dangerous.

    Example:
        >>> validate_file_path("reports/scan.json")
        'reports/scan.json'
        >>> validate_file_path("../../../etc/passwd")
        ValidationException: Path traversal detected
    """
    if path is None:
        raise ValidationException("File path cannot be None")

    if not isinstance(path, str):
        raise ValidationException(f"File path must be a string, got {type(path).__name__}")

    path = path.strip()
    if not path:
        raise ValidationException("File path cannot be empty")

    if len(path) > MAX_FILE_PATH_LENGTH:
        raise ValidationException(f"File path too long (max {MAX_FILE_PATH_LENGTH} chars)")

    # Check for null bytes (security risk)
    if '\x00' in path:
        raise ValidationException("File path contains null bytes")

    # Normalize the path
    try:
        normalized = os.path.normpath(path)
    except Exception as e:
        raise ValidationException(f"Invalid file path: {e}")

    # Check for directory traversal
    if '..' in normalized.split(os.sep):
        raise ValidationException("Path traversal detected: '..' not allowed")

    # Check absolute path restriction
    if not allow_absolute and os.path.isabs(normalized):
        raise ValidationException("Absolute paths not allowed")

    # Check if within base directory
    if base_dir:
        base_dir = os.path.abspath(base_dir)
        full_path = os.path.abspath(os.path.join(base_dir, normalized))
        if not full_path.startswith(base_dir):
            raise ValidationException("Path escapes base directory")

    # Check existence if required
    if must_exist and not os.path.exists(path):
        raise ValidationException(f"File does not exist: {path}")

    return normalized


# =============================================================================
# Template and Configuration Validators
# =============================================================================

def validate_template_name(template: str) -> bool:
    """
    Validate a query template name against the whitelist.

    Args:
        template: Template name to validate.

    Returns:
        True if template is valid.

    Raises:
        ValidationException: If template is not in the allowed list.

    Example:
        >>> validate_template_name("clawdbot_instances")
        True
        >>> validate_template_name("malicious_query")
        ValidationException: Invalid template name
    """
    if template is None:
        raise ValidationException("Template name cannot be None")

    template = template.strip().lower()
    if not template:
        raise ValidationException("Template name cannot be empty")

    if template not in VALID_TEMPLATES:
        valid_list = ", ".join(sorted(VALID_TEMPLATES))
        raise ValidationException(
            f"Invalid template name: '{template}'. Valid templates: {valid_list}"
        )

    return True


def validate_max_results(max_results: Union[int, str]) -> int:
    """
    Validate and normalize max_results parameter.

    Args:
        max_results: Maximum number of results (int or string).

    Returns:
        Validated integer value.

    Raises:
        ValidationException: If value is invalid or out of range.

    Example:
        >>> validate_max_results(100)
        100
        >>> validate_max_results("50")
        50
        >>> validate_max_results(-1)
        ValidationException: max_results must be positive
    """
    if max_results is None:
        raise ValidationException("max_results cannot be None")

    # Convert string to int if needed
    if isinstance(max_results, str):
        try:
            max_results = int(max_results.strip())
        except ValueError:
            raise ValidationException(f"max_results must be a number, got: '{max_results}'")

    if not isinstance(max_results, int):
        raise ValidationException(f"max_results must be an integer, got {type(max_results).__name__}")

    if max_results < MIN_RESULTS_LIMIT:
        raise ValidationException(f"max_results must be at least {MIN_RESULTS_LIMIT}")

    if max_results > MAX_RESULTS_LIMIT:
        raise ValidationException(f"max_results cannot exceed {MAX_RESULTS_LIMIT}")

    return max_results


def validate_log_level(level: str) -> str:
    """
    Validate a log level string.

    Args:
        level: Log level string.

    Returns:
        Normalized uppercase log level.

    Raises:
        ValidationException: If log level is invalid.
    """
    if level is None:
        raise ValidationException("Log level cannot be None")

    level = str(level).strip().upper()

    if level not in VALID_LOG_LEVELS:
        valid_list = ", ".join(sorted(VALID_LOG_LEVELS))
        raise ValidationException(f"Invalid log level: '{level}'. Valid levels: {valid_list}")

    return level


def validate_environment(env: str) -> str:
    """
    Validate an environment name.

    Args:
        env: Environment name string.

    Returns:
        Normalized lowercase environment name.

    Raises:
        ValidationException: If environment is invalid.
    """
    if env is None:
        raise ValidationException("Environment cannot be None")

    env = str(env).strip().lower()

    if env not in VALID_ENVIRONMENTS:
        valid_list = ", ".join(sorted(VALID_ENVIRONMENTS))
        raise ValidationException(f"Invalid environment: '{env}'. Valid environments: {valid_list}")

    return env


def validate_db_type(db_type: str) -> str:
    """
    Validate a database type.

    Args:
        db_type: Database type string.

    Returns:
        Normalized lowercase database type.

    Raises:
        ValidationException: If database type is invalid.
    """
    if db_type is None:
        raise ValidationException("Database type cannot be None")

    db_type = str(db_type).strip().lower()

    if db_type not in VALID_DB_TYPES:
        valid_list = ", ".join(sorted(VALID_DB_TYPES))
        raise ValidationException(f"Invalid database type: '{db_type}'. Valid types: {valid_list}")

    return db_type


# =============================================================================
# Batch Validation Helpers
# =============================================================================

def validate_config_dict(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate a configuration dictionary.

    Args:
        config: Configuration dictionary to validate.

    Returns:
        Validated configuration dictionary.

    Raises:
        ValidationException: If any configuration value is invalid.
    """
    validated = {}

    # Validate log level if present
    if 'logging' in config and 'level' in config['logging']:
        config['logging']['level'] = validate_log_level(config['logging']['level'])

    # Validate database type if present
    if 'database' in config and 'type' in config['database']:
        config['database']['type'] = validate_db_type(config['database']['type'])

    # Validate max_results if present
    if 'shodan' in config and 'max_results' in config['shodan']:
        config['shodan']['max_results'] = validate_max_results(config['shodan']['max_results'])

    return config


def is_safe_string(text: str, max_length: int = 1000) -> bool:
    """
    Check if a string is safe (no injection attempts).

    Args:
        text: Text to check.
        max_length: Maximum allowed length.

    Returns:
        True if string appears safe, False otherwise.
    """
    if text is None:
        return False

    if len(text) > max_length:
        return False

    # Check for null bytes
    if '\x00' in text:
        return False

    # Check for common injection patterns
    dangerous_patterns = [
        r'<script',
        r'javascript:',
        r'on\w+\s*=',
        r'\x00',
        r'<!--',
        r'--\s*>',
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return False

    return True
