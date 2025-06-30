"""
Core module for Permission Storage Manager.

This module provides the main classes and interfaces for the permission storage system:
- BaseProvider: Abstract base class for all storage providers
- PermissionStorageManager: Main manager class
- Custom exceptions for error handling
"""

from .base import BaseProvider
from .manager import PermissionStorageManager
from .exceptions import (
    # Base exceptions
    PermissionStorageError,
    ProviderError,
    ProviderConnectionError,
    ProviderNotInitializedError,
    ProviderConfigurationError,
    ProviderNotSupportedError,
    # Session related exceptions
    SessionNotFoundError,
    SessionExpiredError,
    InvalidSessionIdError,
    # Permission related exceptions
    InvalidPermissionError,
    InvalidUserIdError,
    # Operation exceptions
    TTLError,
    OperationTimeoutError,
    ConcurrencyError,
    StorageQuotaExceededError,
    SerializationError,
    ValidationError,
    # Validation functions
    validate_session_id,
    validate_user_id,
    validate_permission,
    validate_permissions,
    validate_ttl,
)

# Version info
__version__ = "1.0.2"
__author__ = "Fatih Emre"
__email__ = "info@fatihemre.net"

# Public API
__all__ = [
    # Main classes
    "BaseProvider",
    "PermissionStorageManager",
    # Exceptions
    "PermissionStorageError",
    "ProviderError",
    "ProviderConnectionError",
    "ProviderNotInitializedError",
    "ProviderConfigurationError",
    "ProviderNotSupportedError",
    "SessionNotFoundError",
    "SessionExpiredError",
    "InvalidSessionIdError",
    "InvalidPermissionError",
    "InvalidUserIdError",
    "TTLError",
    "OperationTimeoutError",
    "ConcurrencyError",
    "StorageQuotaExceededError",
    "SerializationError",
    "ValidationError",
    # Validation functions
    "validate_session_id",
    "validate_user_id",
    "validate_permission",
    "validate_permissions",
    "validate_ttl",
    # Metadata
    "__version__",
    "__author__",
    "__email__",
]
