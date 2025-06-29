"""
Custom exceptions for Permission Storage Manager.
"""

from typing import Optional, Any


class PermissionStorageError(Exception):
    """Base exception for all permission storage related errors."""

    def __init__(self, message: str, details: Optional[dict] = None):
        self.message = message
        self.details = details or {}
        super().__init__(self.message)

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} - Details: {self.details}"
        return self.message


class ProviderError(PermissionStorageError):
    """Raised when a storage provider encounters an error."""

    pass


class ProviderConnectionError(ProviderError):
    """Raised when provider cannot establish or maintain connection."""

    pass


class ProviderNotInitializedError(ProviderError):
    """Raised when trying to use provider before initialization."""

    def __init__(self, provider_name: str):
        message = (
            f"Provider '{provider_name}' is not initialized. Call initialize() first."
        )
        super().__init__(message)


class ProviderConfigurationError(ProviderError):
    """Raised when provider configuration is invalid."""

    pass


class SessionNotFoundError(PermissionStorageError):
    """Raised when a session is not found."""

    def __init__(self, session_id: str):
        message = f"Session '{session_id}' not found"
        super().__init__(message, {"session_id": session_id})


class SessionExpiredError(PermissionStorageError):
    """Raised when a session has expired."""

    def __init__(self, session_id: str):
        message = f"Session '{session_id}' has expired"
        super().__init__(message, {"session_id": session_id})


class InvalidSessionIdError(PermissionStorageError):
    """Raised when session ID format is invalid."""

    def __init__(self, session_id: str, reason: str = "Invalid format"):
        message = f"Invalid session ID '{session_id}': {reason}"
        super().__init__(message, {"session_id": session_id, "reason": reason})


class InvalidPermissionError(PermissionStorageError):
    """Raised when permission format is invalid."""

    def __init__(self, permission: str, reason: str = "Invalid format"):
        message = f"Invalid permission '{permission}': {reason}"
        super().__init__(message, {"permission": permission, "reason": reason})


class InvalidUserIdError(PermissionStorageError):
    """Raised when user ID format is invalid."""

    def __init__(self, user_id: str, reason: str = "Invalid format"):
        message = f"Invalid user ID '{user_id}': {reason}"
        super().__init__(message, {"user_id": user_id, "reason": reason})


class TTLError(PermissionStorageError):
    """Raised when TTL value is invalid."""

    def __init__(self, ttl: Any, reason: str = "Invalid TTL value"):
        message = f"Invalid TTL '{ttl}': {reason}"
        super().__init__(message, {"ttl": ttl, "reason": reason})


class ProviderNotSupportedError(PermissionStorageError):
    """Raised when trying to use an unsupported provider."""

    def __init__(self, provider_name: str, available_providers: list = None):
        available = (
            f"Available providers: {', '.join(available_providers)}"
            if available_providers
            else ""
        )
        message = f"Provider '{provider_name}' is not supported. {available}"
        super().__init__(
            message,
            {
                "provider_name": provider_name,
                "available_providers": available_providers or [],
            },
        )


class OperationTimeoutError(ProviderError):
    """Raised when a provider operation times out."""

    def __init__(self, operation: str, timeout: float):
        message = f"Operation '{operation}' timed out after {timeout} seconds"
        super().__init__(message, {"operation": operation, "timeout": timeout})


class ConcurrencyError(ProviderError):
    """Raised when concurrent operations conflict."""

    def __init__(self, operation: str, session_id: str):
        message = (
            f"Concurrent operation '{operation}' conflict for session '{session_id}'"
        )
        super().__init__(message, {"operation": operation, "session_id": session_id})


class StorageQuotaExceededError(ProviderError):
    """Raised when storage quota is exceeded."""

    def __init__(self, provider_name: str, quota_type: str = "storage"):
        message = (
            f"Storage quota exceeded for provider '{provider_name}' ({quota_type})"
        )
        super().__init__(
            message, {"provider_name": provider_name, "quota_type": quota_type}
        )


class SerializationError(PermissionStorageError):
    """Raised when data serialization/deserialization fails."""

    def __init__(self, operation: str, data_type: str, reason: str = "Unknown"):
        message = f"Serialization error during {operation} for {data_type}: {reason}"
        super().__init__(
            message, {"operation": operation, "data_type": data_type, "reason": reason}
        )


class ValidationError(PermissionStorageError):
    """Raised when input validation fails."""

    def __init__(self, field: str, value: Any, reason: str):
        message = f"Validation error for field '{field}' with value '{value}': {reason}"
        super().__init__(message, {"field": field, "value": value, "reason": reason})


# Convenience functions for common validations
def validate_session_id(session_id: str) -> None:
    """Validate session ID format."""
    if not session_id or not isinstance(session_id, str):
        raise InvalidSessionIdError(session_id, "Session ID must be a non-empty string")

    if len(session_id) > 255:
        raise InvalidSessionIdError(
            session_id, "Session ID too long (max 255 characters)"
        )

    # Basic format validation - can be extended
    if not session_id.replace("-", "").replace("_", "").isalnum():
        raise InvalidSessionIdError(
            session_id, "Session ID contains invalid characters"
        )


def validate_user_id(user_id: str) -> None:
    """Validate user ID format."""
    if not user_id or not isinstance(user_id, str):
        raise InvalidUserIdError(user_id, "User ID must be a non-empty string")

    if len(user_id) > 255:
        raise InvalidUserIdError(user_id, "User ID too long (max 255 characters)")


def validate_permission(permission: str) -> None:
    """Validate permission format."""
    if not permission or not isinstance(permission, str):
        raise InvalidPermissionError(
            permission, "Permission must be a non-empty string"
        )

    if len(permission) > 255:
        raise InvalidPermissionError(
            permission, "Permission too long (max 255 characters)"
        )


def validate_permissions(permissions: list) -> None:
    """Validate permissions list."""
    if not isinstance(permissions, list):
        raise ValidationError("permissions", permissions, "Must be a list")

    if not permissions:
        raise ValidationError("permissions", permissions, "Cannot be empty")

    for perm in permissions:
        validate_permission(perm)


def validate_ttl(ttl: Optional[int]) -> None:
    """Validate TTL value."""
    if ttl is not None:
        if not isinstance(ttl, int):
            raise TTLError(ttl, "TTL must be an integer")

        if ttl <= 0:
            raise TTLError(ttl, "TTL must be positive")

        if ttl > 31536000:  # 1 year in seconds
            raise TTLError(ttl, "TTL too large (max 31536000 seconds / 1 year)")
