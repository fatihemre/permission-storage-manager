"""Test module for provider package init and exception coverage."""

import pytest
from permission_storage_manager.providers import (
    get_provider_class,
    list_available_providers,
    get_provider_info,
    compare_providers,
    get_recommended_provider,
)
from permission_storage_manager.providers.memory_provider import MemoryProvider


def test_get_provider_class():
    cls = get_provider_class("memory")
    assert cls is MemoryProvider
    with pytest.raises(ValueError):
        get_provider_class("nonexistent")


def test_list_available_providers():
    providers = list_available_providers()
    assert "memory" in providers
    assert "file" in providers
    assert "redis" in providers


def test_get_provider_info():
    info = get_provider_info("memory")
    assert info["class"].__name__ == "MemoryProvider"
    all_info = get_provider_info()
    assert "memory" in all_info
    assert "file" in all_info
    assert "redis" in all_info


def test_compare_providers():
    comparison = compare_providers()
    assert "memory" in comparison
    assert "file" in comparison
    assert "redis" in comparison


def test_get_recommended_provider():
    assert get_recommended_provider("production") == "redis"
    assert get_recommended_provider("testing") == "memory"
    assert get_recommended_provider("simple") == "file"
    assert get_recommended_provider("unknown") == "memory"
