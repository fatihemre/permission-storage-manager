import pytest

from permission_storage_manager.providers import (
    get_provider_class,
    list_available_providers,
    compare_providers,
    get_recommended_provider,
    get_provider_info,
)
from permission_storage_manager.providers.memory_provider import MemoryProvider
from permission_storage_manager.providers.file_provider import FileProvider
from permission_storage_manager.providers.redis_provider import RedisProvider


class TestProvidersInitExtended:
    """Extended tests for providers/__init__.py coverage."""

    def test_compare_providers(self):
        """Test provider comparison functionality."""
        comparison = compare_providers()
        assert isinstance(comparison, dict)
        for key in ["memory", "file", "redis"]:
            assert key in comparison

    def test_get_recommended_provider(self):
        """Test provider recommendation functionality."""
        recommendation = get_recommended_provider("development")
        assert isinstance(recommendation, str)
        assert recommendation in ["memory", "file", "redis"]
        recommendation = get_recommended_provider("production")
        assert isinstance(recommendation, str)

    def test_get_provider_info(self):
        """Test provider information retrieval."""
        info = get_provider_info("memory")
        assert isinstance(info, dict)
        assert "description" in info
        assert "features" in info
        info = get_provider_info("file")
        assert isinstance(info, dict)
        assert "description" in info
        info = get_provider_info("redis")
        assert isinstance(info, dict)
        assert "description" in info

    def test_get_provider_class_edge_cases(self):
        with pytest.raises(ValueError):
            get_provider_class(None)
        with pytest.raises(ValueError):
            get_provider_class("")
        with pytest.raises(ValueError):
            get_provider_class("   ")

    def test_list_available_providers_extended(self):
        providers = list_available_providers()
        assert isinstance(providers, list)
        assert len(providers) >= 3

    def test_provider_registration_workflow(self):
        providers = list_available_providers()
        expected_providers = ["memory", "file", "redis"]
        for provider_name in expected_providers:
            assert provider_name in providers
            provider_class = get_provider_class(provider_name)
            assert provider_class is not None
            info = get_provider_info(provider_name)
            assert info is not None

    def test_provider_comparison_matrix(self):
        comparison = compare_providers()
        for provider1 in ["memory", "file", "redis"]:
            for provider2 in ["memory", "file", "redis"]:
                if provider1 != provider2:
                    assert provider1 in comparison
                    assert provider2 in comparison

    def test_recommendation_scenarios(self):
        scenarios = [
            "development",
            "testing",
            "production",
            "high-performance",
            "persistent-storage",
        ]
        for scenario in scenarios:
            recommendation = get_recommended_provider(scenario)
            assert isinstance(recommendation, str)
            assert recommendation in ["memory", "file", "redis"]

    def test_provider_info_completeness(self):
        for provider_name in ["memory", "file", "redis"]:
            info = get_provider_info(provider_name)
            required_fields = ["description", "features"]
            for field in required_fields:
                assert field in info, f"Missing field '{field}' in {provider_name} info"
            assert isinstance(info["features"], list)


class TestProvidersInitCoverage:
    """Test providers init coverage edge cases."""

    def test_provider_registration_workflow(self):
        """Test complete provider registration workflow."""
        from permission_storage_manager.providers import (
            get_provider_class,
            list_available_providers,
        )

        # Test getting registered provider
        provider_class = get_provider_class("memory")
        assert provider_class is not None

        # Test listing available providers
        providers = list_available_providers()
        assert "memory" in providers
        assert "file" in providers

    def test_get_provider_class_edge_cases(self):
        """Test get_provider_class edge cases."""
        from permission_storage_manager.providers import get_provider_class

        # Test with non-existent provider
        with pytest.raises(ValueError, match="not available"):
            get_provider_class("nonexistent")

        # Test with None
        with pytest.raises(ValueError, match="not available"):
            get_provider_class(None)

    def test_compare_providers_edge_cases(self):
        """Test compare_providers edge cases."""
        from permission_storage_manager.providers import compare_providers

        # Test compare_providers returns dict
        result = compare_providers()
        assert isinstance(result, dict)
        assert "memory" in result
        assert "file" in result
        assert "redis" in result

    def test_get_recommended_provider_edge_cases(self):
        """Test get_recommended_provider edge cases."""
        from permission_storage_manager.providers import get_recommended_provider

        # Test with empty string
        result = get_recommended_provider("")
        assert result == "memory"  # Default fallback

        # Test with unknown use case
        result = get_recommended_provider("unknown")
        assert result == "memory"  # Default fallback

        # Test with known use cases
        assert get_recommended_provider("production") == "redis"
        assert get_recommended_provider("testing") == "memory"
        assert get_recommended_provider("simple") == "file"

    def test_get_provider_info_edge_cases(self):
        """Test get_provider_info with edge cases."""
        # Test with non-existent provider
        info = get_provider_info("non_existent_provider")
        assert info == {}  # Returns empty dict for non-existent providers

        # Test with None - should return all providers
        all_info = get_provider_info(None)
        assert isinstance(all_info, dict)
        assert "redis" in all_info
        assert "memory" in all_info
        assert "file" in all_info

    def test_provider_registration_and_retrieval(self):
        """Test provider registration and retrieval."""
        from permission_storage_manager.providers import get_provider_class

        # Test that all built-in providers are available
        redis_class = get_provider_class("redis")
        memory_class = get_provider_class("memory")
        file_class = get_provider_class("file")

        assert redis_class is not None
        assert memory_class is not None
        assert file_class is not None

        # Test that provider names match
        assert redis_class().provider_name == "redis"
        assert memory_class().provider_name == "memory"
        assert file_class().provider_name == "file"
