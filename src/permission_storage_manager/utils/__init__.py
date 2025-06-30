"""
Utility functions for Permission Storage Manager.

This module provides helper functions for common tasks like:
- Session ID generation and validation
- Permission management and normalization
- Time and TTL utilities
- Configuration parsing
- Logging and debugging helpers
"""

from .helpers import (
    # Session ID utilities
    generate_session_id,
    is_valid_session_id,
    normalize_session_id,
    # Permission utilities
    normalize_permissions,
    merge_permissions,
    has_any_permission,
    has_all_permissions,
    match_permission_pattern,
    filter_permissions_by_pattern,
    # Time and TTL utilities
    parse_ttl_string,
    format_ttl_remaining,
    calculate_expiry_time,
    is_expired,
    # Data utilities
    hash_data,
    sanitize_metadata,
    # Configuration utilities
    parse_provider_url,
    merge_configs,
    # Logging utilities
    setup_logger,
    log_performance,
    # Version utilities
    get_version_info,
    check_dependencies,
    # Retry utilities
    retry_with_backoff,
)

# Version info
__version__ = "1.0.2"

# Public API
__all__ = [
    # Session ID utilities
    "generate_session_id",
    "is_valid_session_id",
    "normalize_session_id",
    # Permission utilities
    "normalize_permissions",
    "merge_permissions",
    "has_any_permission",
    "has_all_permissions",
    "match_permission_pattern",
    "filter_permissions_by_pattern",
    # Time and TTL utilities
    "parse_ttl_string",
    "format_ttl_remaining",
    "calculate_expiry_time",
    "is_expired",
    # Data utilities
    "hash_data",
    "sanitize_metadata",
    # Configuration utilities
    "parse_provider_url",
    "merge_configs",
    # Logging utilities
    "setup_logger",
    "log_performance",
    # Version utilities
    "get_version_info",
    "check_dependencies",
    # Retry utilities
    "retry_with_backoff",
    # Metadata
    "__version__",
]
