"""
Storage providers for Permission Storage Manager.

This module contains implementations of different storage backends:
- RedisProvider: High-performance Redis-based storage
- MemoryProvider: In-memory storage for development/testing
- FileProvider: File-based storage for simple deployments

Each provider implements the BaseProvider interface and can be used
interchangeably through the PermissionStorageManager class.
"""

from typing import Dict, Any

# Import available providers
from .redis_provider import RedisProvider
from .memory_provider import MemoryProvider
from .file_provider import FileProvider

# Provider registry information
AVAILABLE_PROVIDERS = {
    "redis": {
        "class": RedisProvider,
        "description": "High-performance Redis-based storage with native TTL support",
        "features": ["ttl", "clustering", "persistence", "high_performance"],
        "dependencies": ["redis"],
        "available": True,
    },
    "memory": {
        "class": MemoryProvider,
        "description": "In-memory storage for development and testing",
        "features": ["ttl", "fast", "no_persistence"],
        "dependencies": [],
        "available": True,
    },
    "file": {
        "class": FileProvider,
        "description": "File-based storage for simple deployments",
        "features": ["ttl", "persistence", "portable", "backup"],
        "dependencies": [],
        "available": True,
    },
}


def get_provider_info(provider_name: str = None) -> dict:
    """
    Get information about available providers.

    Args:
        provider_name: Specific provider name, or None for all providers

    Returns:
        Provider information dictionary

    Example:
        >>> info = get_provider_info("redis")
        >>> print(info["description"])
        "High-performance Redis-based storage with native TTL support"

        >>> all_info = get_provider_info()
        >>> print(list(all_info.keys()))
        ["redis", "memory", "file"]
    """
    if provider_name:
        return AVAILABLE_PROVIDERS.get(provider_name, {})
    return AVAILABLE_PROVIDERS


def list_available_providers() -> list:
    """
    Get list of available provider names.

    Returns:
        List of provider names that are available for use

    Example:
        >>> providers = list_available_providers()
        >>> print(providers)
        ["redis", "memory", "file"]
    """
    return [
        name
        for name, info in AVAILABLE_PROVIDERS.items()
        if info.get("available", False)
    ]


def get_provider_class(provider_name: str):
    """
    Get provider class by name.

    Args:
        provider_name: Name of the provider

    Returns:
        Provider class

    Raises:
        ValueError: If provider is not available

    Example:
        >>> ProviderClass = get_provider_class("redis")
        >>> provider = ProviderClass({"url": "redis://localhost:6379"})
    """
    if provider_name not in AVAILABLE_PROVIDERS:
        available = list_available_providers()
        raise ValueError(
            f"Provider '{provider_name}' not available. Available providers: {available}"
        )

    provider_info = AVAILABLE_PROVIDERS[provider_name]
    if not provider_info.get("available", False):
        raise ValueError(
            f"Provider '{provider_name}' is not available (missing dependencies)"
        )

    return provider_info["class"]


def compare_providers() -> Dict[str, Dict[str, Any]]:
    """
    Compare features and characteristics of all providers.

    Returns:
        Detailed comparison of provider features

    Example:
        >>> comparison = compare_providers()
        >>> for provider, info in comparison.items():
        ...     print(f"{provider}: {info['use_cases']}")
    """
    return {
        "redis": {
            "performance": "High",
            "persistence": "Yes (configurable)",
            "clustering": "Yes",
            "ttl_support": "Native",
            "dependencies": ["redis"],
            "use_cases": ["Production", "High-traffic", "Distributed systems"],
            "memory_usage": "External (Redis server)",
            "concurrency": "Excellent",
            "data_safety": "High (with persistence)",
        },
        "memory": {
            "performance": "Highest",
            "persistence": "No",
            "clustering": "No",
            "ttl_support": "Emulated",
            "dependencies": [],
            "use_cases": ["Development", "Testing", "Temporary storage"],
            "memory_usage": "In-process",
            "concurrency": "Good (single process)",
            "data_safety": "Low (in-memory only)",
        },
        "file": {
            "performance": "Medium",
            "persistence": "Yes",
            "clustering": "No",
            "ttl_support": "Emulated",
            "dependencies": [],
            "use_cases": ["Simple deployments", "Single server", "Backup storage"],
            "memory_usage": "Low (file-based)",
            "concurrency": "Good (file locking)",
            "data_safety": "High (with backups)",
        },
    }


def get_recommended_provider(use_case: str) -> str:
    """
    Get recommended provider for specific use case.

    Args:
        use_case: Use case scenario

    Returns:
        Recommended provider name

    Example:
        >>> provider = get_recommended_provider("production")
        >>> print(provider)  # "redis"

        >>> provider = get_recommended_provider("testing")
        >>> print(provider)  # "memory"
    """
    recommendations = {
        "production": "redis",
        "high_traffic": "redis",
        "distributed": "redis",
        "development": "memory",
        "testing": "memory",
        "debug": "memory",
        "simple": "file",
        "single_server": "file",
        "backup": "file",
        "portable": "file",
    }

    return recommendations.get(use_case.lower(), "memory")


# Public API
__all__ = [
    # Provider classes
    "RedisProvider",
    "MemoryProvider",
    "FileProvider",
    # Utility functions
    "get_provider_info",
    "list_available_providers",
    "get_provider_class",
    "compare_providers",
    "get_recommended_provider",
    # Constants
    "AVAILABLE_PROVIDERS",
]
