"""
Utility helper functions for Permission Storage Manager.
"""

import re
import hashlib
import secrets
import time
from typing import List, Dict, Any, Optional, Union
from datetime import datetime, timezone, timedelta
import logging

logger = logging.getLogger(__name__)


# Session ID generation and validation
def generate_session_id(prefix: str = "session", length: int = 32) -> str:
    """
    Generate a secure session ID.

    Args:
        prefix: Prefix for the session ID
        length: Length of the random part (default: 32)

    Returns:
        Generated session ID

    Example:
        >>> session_id = generate_session_id("app", 16)
        >>> print(session_id)
        "app_a1b2c3d4e5f6..."
    """
    random_part = secrets.token_urlsafe(length)[:length]
    timestamp = int(time.time())
    return f"{prefix}_{timestamp}_{random_part}"


def is_valid_session_id(session_id: str) -> bool:
    """
    Check if session ID format is valid.

    Args:
        session_id: Session ID to validate

    Returns:
        True if valid format

    Example:
        >>> is_valid_session_id("session_1234567890_abc123")
        True
        >>> is_valid_session_id("")
        False
    """
    if not session_id or not isinstance(session_id, str):
        return False

    if len(session_id) > 255:
        return False

    # Allow alphanumeric, hyphens, underscores, dots
    pattern = r"^[a-zA-Z0-9\-_.]+$"
    return bool(re.match(pattern, session_id))


def normalize_session_id(session_id: str) -> str:
    """
    Normalize session ID by removing invalid characters.

    Args:
        session_id: Session ID to normalize

    Returns:
        Normalized session ID

    Example:
        >>> normalize_session_id("session/with\\invalid:chars")
        "session_with_invalid_chars"
    """
    # Replace invalid characters with underscores
    normalized = re.sub(r"[^a-zA-Z0-9\-_.]", "_", session_id)

    # Remove multiple consecutive underscores
    normalized = re.sub(r"_+", "_", normalized)

    # Remove leading/trailing underscores
    normalized = normalized.strip("_")

    return normalized[:255]  # Ensure max length


# Permission management utilities
def normalize_permissions(permissions: List[str]) -> List[str]:
    """
    Normalize permission list by removing duplicates and empty values.

    Args:
        permissions: List of permission strings

    Returns:
        Normalized permission list

    Example:
        >>> normalize_permissions(["read", "write", "read", "", "admin"])
        ["admin", "read", "write"]
    """
    if not permissions:
        return []

    # Remove empty strings and normalize
    normalized = [perm.strip() for perm in permissions if perm and perm.strip()]

    # Remove duplicates and sort for consistency
    return sorted(list(set(normalized)))


def merge_permissions(
    current: List[str], new: List[str], mode: str = "replace"
) -> List[str]:
    """
    Merge permission lists according to specified mode.

    Args:
        current: Current permission list
        new: New permission list
        mode: Merge mode ("replace", "add", "remove")

    Returns:
        Merged permission list

    Example:
        >>> merge_permissions(["read"], ["write", "admin"], "add")
        ["admin", "read", "write"]
        >>> merge_permissions(["read", "write"], ["read"], "remove")
        ["write"]
    """
    current_set = set(normalize_permissions(current))
    new_set = set(normalize_permissions(new))

    if mode == "replace":
        result = new_set
    elif mode == "add":
        result = current_set | new_set
    elif mode == "remove":
        result = current_set - new_set
    else:
        raise ValueError(
            f"Invalid merge mode: {mode}. Use 'replace', 'add', or 'remove'"
        )

    return sorted(list(result))


def has_any_permission(
    user_permissions: List[str], required_permissions: List[str]
) -> bool:
    """
    Check if user has any of the required permissions.

    Args:
        user_permissions: User's current permissions
        required_permissions: Required permissions (any one is sufficient)

    Returns:
        True if user has at least one required permission

    Example:
        >>> has_any_permission(["read", "write"], ["admin", "write"])
        True
        >>> has_any_permission(["read"], ["admin", "super_admin"])
        False
    """
    user_set = set(normalize_permissions(user_permissions))
    required_set = set(normalize_permissions(required_permissions))
    return bool(user_set & required_set)


def has_all_permissions(
    user_permissions: List[str], required_permissions: List[str]
) -> bool:
    """
    Check if user has all required permissions.

    Args:
        user_permissions: User's current permissions
        required_permissions: Required permissions (all are required)

    Returns:
        True if user has all required permissions

    Example:
        >>> has_all_permissions(["read", "write", "admin"], ["read", "write"])
        True
        >>> has_all_permissions(["read"], ["read", "admin"])
        False
    """
    user_set = set(normalize_permissions(user_permissions))
    required_set = set(normalize_permissions(required_permissions))
    return required_set.issubset(user_set)


# Permission pattern matching
def match_permission_pattern(permission: str, pattern: str) -> bool:
    """
    Check if permission matches a pattern with wildcards.

    Args:
        permission: Permission to check
        pattern: Pattern with wildcards (* and ?)

    Returns:
        True if permission matches pattern

    Example:
        >>> match_permission_pattern("user:read:profile", "user:*")
        True
        >>> match_permission_pattern("admin:write", "user:*")
        False
    """
    import fnmatch

    return fnmatch.fnmatch(permission, pattern)


def filter_permissions_by_pattern(permissions: List[str], pattern: str) -> List[str]:
    """
    Filter permissions by pattern.

    Args:
        permissions: List of permissions
        pattern: Pattern with wildcards

    Returns:
        Filtered permission list

    Example:
        >>> filter_permissions_by_pattern(["user:read", "user:write", "admin:read"], "user:*")
        ["user:read", "user:write"]
    """
    return [perm for perm in permissions if match_permission_pattern(perm, pattern)]


# Time and TTL utilities
def parse_ttl_string(ttl_str: str) -> int:
    """
    Parse TTL string to seconds.

    Args:
        ttl_str: TTL string (e.g., "1h", "30m", "3600s", "1d")

    Returns:
        TTL in seconds

    Example:
        >>> parse_ttl_string("1h")
        3600
        >>> parse_ttl_string("30m")
        1800
        >>> parse_ttl_string("1d")
        86400
    """
    if not ttl_str:
        raise ValueError("TTL string cannot be empty")

    ttl_str = ttl_str.strip().lower()

    # If already a number, return as-is
    if ttl_str.isdigit():
        return int(ttl_str)

    # Parse with units
    units = {
        "s": 1,
        "m": 60,
        "h": 3600,
        "d": 86400,
        "w": 604800,  # week
    }

    for unit, multiplier in units.items():
        if ttl_str.endswith(unit):
            try:
                value = float(ttl_str[:-1])
                return int(value * multiplier)
            except ValueError:
                break

    raise ValueError(
        f"Invalid TTL format: {ttl_str}. Use formats like '1h', '30m', '3600s'"
    )


def format_ttl_remaining(seconds: int) -> str:
    """
    Format remaining TTL seconds to human-readable string.

    Args:
        seconds: Remaining seconds

    Returns:
        Human-readable TTL string

    Example:
        >>> format_ttl_remaining(3661)
        "1h 1m 1s"
        >>> format_ttl_remaining(90)
        "1m 30s"
    """
    if seconds <= 0:
        return "expired"

    units = [("d", 86400), ("h", 3600), ("m", 60), ("s", 1)]

    parts = []
    for unit, duration in units:
        if seconds >= duration:
            count = seconds // duration
            parts.append(f"{count}{unit}")
            seconds -= count * duration

    return " ".join(parts) if parts else "0s"


def calculate_expiry_time(ttl: int) -> datetime:
    """
    Calculate expiry datetime from TTL.

    Args:
        ttl: TTL in seconds

    Returns:
        Expiry datetime in UTC

    Example:
        >>> expiry = calculate_expiry_time(3600)
        >>> # Returns datetime 1 hour from now
    """
    return datetime.now(timezone.utc) + timedelta(seconds=ttl)


def is_expired(expires_at: Union[str, datetime]) -> bool:
    """
    Check if given expiry time has passed.

    Args:
        expires_at: Expiry time as datetime or ISO string

    Returns:
        True if expired

    Example:
        >>> is_expired("2024-01-01T00:00:00Z")
        True
        >>> future_time = datetime.now(timezone.utc) + timedelta(hours=1)
        >>> is_expired(future_time)
        False
    """
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))

    return datetime.now(timezone.utc) > expires_at


# Data serialization helpers
def hash_data(data: Any, algorithm: str = "sha256") -> str:
    """
    Generate hash of data for integrity checking.

    Args:
        data: Data to hash
        algorithm: Hash algorithm (md5, sha1, sha256, sha512)

    Returns:
        Hex digest of hash

    Example:
        >>> hash_data({"user": "test", "permissions": ["read"]})
        "a1b2c3d4e5f6..."
    """
    import json

    # Convert data to consistent string representation
    if isinstance(data, (dict, list)):
        json_str = json.dumps(data, sort_keys=True, separators=(",", ":"))
    else:
        json_str = str(data)

    # Generate hash
    hasher = hashlib.new(algorithm)
    hasher.update(json_str.encode("utf-8"))
    return hasher.hexdigest()


def sanitize_metadata(metadata: Dict[str, Any], max_depth: int = 5) -> Dict[str, Any]:
    """
    Sanitize metadata to prevent serialization issues.

    Args:
        metadata: Metadata dictionary
        max_depth: Maximum nesting depth allowed

    Returns:
        Sanitized metadata

    Example:
        >>> sanitize_metadata({"nested": {"deep": {"too": {"deep": "value"}}}}, 3)
        {"nested": {"deep": {"too": "[TRUNCATED]"}}}
    """

    def _sanitize_recursive(obj, current_depth=0):
        if current_depth >= max_depth:
            return "[TRUNCATED]"

        if isinstance(obj, dict):
            return {
                str(k): _sanitize_recursive(v, current_depth + 1)
                for k, v in obj.items()
                if isinstance(k, (str, int, float))
            }
        elif isinstance(obj, list):
            return [
                _sanitize_recursive(item, current_depth + 1)
                for item in obj[:100]  # Limit list size
            ]
        elif isinstance(obj, (str, int, float, bool)) or obj is None:
            return obj
        else:
            # Convert other types to string
            return str(obj)

    if not isinstance(metadata, dict):
        return {}

    return _sanitize_recursive(metadata)


# Configuration helpers
def parse_provider_url(url: str) -> Dict[str, Any]:
    """
    Parse provider URL to configuration dictionary.

    Args:
        url: Provider URL (e.g., "redis://localhost:6379/0")

    Returns:
        Configuration dictionary

    Example:
        >>> parse_provider_url("redis://user:pass@localhost:6379/0")
        {"host": "localhost", "port": 6379, "db": 0, "username": "user", "password": "pass"}
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)
    config = {}

    if parsed.scheme:
        config["scheme"] = parsed.scheme

    if parsed.hostname:
        config["host"] = parsed.hostname

    if parsed.port:
        config["port"] = parsed.port

    if parsed.username:
        config["username"] = parsed.username

    if parsed.password:
        config["password"] = parsed.password

    if parsed.path and len(parsed.path) > 1:
        # Remove leading slash and try to parse as database number
        path = parsed.path[1:]
        if path.isdigit():
            config["db"] = int(path)
        else:
            config["path"] = path

    # Parse query parameters
    if parsed.query:
        from urllib.parse import parse_qs

        query_params = parse_qs(parsed.query)
        for key, values in query_params.items():
            if values:
                # Take first value if multiple
                value = values[0]
                # Try to convert to appropriate type
                if value.lower() in ("true", "false"):
                    config[key] = value.lower() == "true"
                elif value.isdigit():
                    config[key] = int(value)
                else:
                    try:
                        config[key] = float(value)
                    except ValueError:
                        config[key] = value

    return config


def merge_configs(
    base_config: Dict[str, Any], override_config: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Merge configuration dictionaries with deep merge for nested dicts.

    Args:
        base_config: Base configuration
        override_config: Override configuration

    Returns:
        Merged configuration

    Example:
        >>> base = {"redis": {"host": "localhost", "port": 6379}}
        >>> override = {"redis": {"port": 6380}, "debug": True}
        >>> merge_configs(base, override)
        {"redis": {"host": "localhost", "port": 6380}, "debug": True}
    """

    def _deep_merge(base_dict, override_dict):
        result = base_dict.copy()

        for key, value in override_dict.items():
            if (
                key in result
                and isinstance(result[key], dict)
                and isinstance(value, dict)
            ):
                result[key] = _deep_merge(result[key], value)
            else:
                result[key] = value

        return result

    return _deep_merge(base_config, override_config)


# Logging and debugging helpers
def setup_logger(
    name: str, level: str = "INFO", format_str: Optional[str] = None
) -> logging.Logger:
    """
    Setup logger with consistent formatting.

    Args:
        name: Logger name
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format_str: Custom format string

    Returns:
        Configured logger

    Example:
        >>> logger = setup_logger("permission_storage", "DEBUG")
        >>> logger.info("Test message")
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))

    # Remove existing handlers to avoid duplicates
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Create console handler
    handler = logging.StreamHandler()

    # Set format
    if format_str is None:
        format_str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    formatter = logging.Formatter(format_str)
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    return logger


def log_performance(
    func_name: str, duration: float, details: Optional[Dict[str, Any]] = None
):
    """
    Log performance metrics.

    Args:
        func_name: Function name
        duration: Execution duration in seconds
        details: Additional details to log

    Example:
        >>> log_performance("store_permissions", 0.025, {"session_count": 1})
    """
    details_str = ""
    if details:
        details_str = " - " + ", ".join(f"{k}={v}" for k, v in details.items())

    logger.info(f"Performance: {func_name} took {duration:.3f}s{details_str}")


# Version and compatibility utilities
def get_version_info() -> Dict[str, str]:
    """
    Get version information for debugging.

    Returns:
        Dictionary containing version information
    """
    import sys
    import platform

    return {
        "python_version": sys.version,
        "platform": platform.platform(),
        "psm_version": "1.0.2",  # This would be dynamic in real implementation
    }


def check_dependencies() -> Dict[str, bool]:
    """
    Check availability of optional dependencies.

    Returns:
        Dictionary showing which dependencies are available
    """
    dependencies = {}

    try:
        import redis

        dependencies["redis"] = True
    except ImportError:
        dependencies["redis"] = False

    # Add other optional dependencies as needed

    return dependencies


# Retry and resilience utilities
def retry_with_backoff(
    max_retries: int = 3, base_delay: float = 1.0, max_delay: float = 60.0
):
    """
    Decorator for retrying operations with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts
        base_delay: Base delay in seconds
        max_delay: Maximum delay in seconds

    Example:
        >>> @retry_with_backoff(max_retries=3)
        ... async def unreliable_operation():
        ...     # Some operation that might fail
        ...     pass
    """

    def decorator(func):
        async def wrapper(*args, **kwargs):
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e

                    if attempt == max_retries:
                        break

                    # Calculate delay with exponential backoff
                    delay = min(base_delay * (2**attempt), max_delay)
                    logger.warning(
                        f"Attempt {attempt + 1} failed, retrying in {delay}s: {e}"
                    )

                    import asyncio

                    await asyncio.sleep(delay)

            # All retries exhausted
            raise last_exception

        return wrapper

    return decorator
