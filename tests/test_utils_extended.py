import pytest
from permission_storage_manager.utils.helpers import (
    generate_session_id,
    is_valid_session_id,
    normalize_session_id,
    normalize_permissions,
    merge_permissions,
    has_any_permission,
    has_all_permissions,
    parse_ttl_string,
    format_ttl_remaining,
    calculate_expiry_time,
    is_expired,
    hash_data,
    sanitize_metadata,
    parse_provider_url,
    merge_configs,
    setup_logger,
    log_performance,
    get_version_info,
    check_dependencies,
)
from datetime import datetime, timezone, timedelta
import logging


class TestSessionIdHelpers:
    """Test session ID generation and validation helpers."""

    def test_generate_session_id_default(self):
        session_id = generate_session_id()
        assert session_id.startswith("session_")
        assert len(session_id) > 20

    def test_generate_session_id_custom(self):
        session_id = generate_session_id("app", 16)
        assert session_id.startswith("app_")
        assert len(session_id) > 20

    def test_is_valid_session_id_valid(self):
        assert is_valid_session_id("session_123_abc") is True
        assert is_valid_session_id("app-123.456") is True
        assert is_valid_session_id("test_session") is True

    def test_is_valid_session_id_invalid(self):
        assert is_valid_session_id("") is False
        assert is_valid_session_id(None) is False
        assert is_valid_session_id("x" * 300) is False  # Too long
        assert is_valid_session_id("session with spaces") is False
        assert is_valid_session_id("session:with:colons") is False

    def test_normalize_session_id(self):
        assert (
            normalize_session_id("session/with:bad*chars") == "session_with_bad_chars"
        )
        assert normalize_session_id("__abc__") == "abc"
        assert len(normalize_session_id("x" * 300)) <= 255


class TestPermissionHelpers:
    """Test permission management helpers."""

    def test_normalize_permissions(self):
        perms = ["read", "write", "read", "", "admin"]
        result = normalize_permissions(perms)
        assert set(result) == {"read", "write", "admin"}
        assert normalize_permissions([]) == []
        assert normalize_permissions([""]) == []

    def test_merge_permissions(self):
        assert set(merge_permissions(["read"], ["write", "admin"], "add")) == {
            "read",
            "write",
            "admin",
        }
        assert set(merge_permissions(["read", "write"], ["read"], "remove")) == {
            "write"
        }
        assert set(merge_permissions(["read"], ["write"], "replace")) == {"write"}
        with pytest.raises(ValueError):
            merge_permissions(["read"], ["write"], "invalid")

    def test_has_any_permission(self):
        assert has_any_permission(["read", "write"], ["admin", "write"]) is True
        assert has_any_permission(["read"], ["admin", "super_admin"]) is False

    def test_has_all_permissions(self):
        assert (
            has_all_permissions(["read", "write", "admin"], ["read", "write"]) is True
        )
        assert has_all_permissions(["read"], ["read", "admin"]) is False


class TestTTLHelpers:
    """Test TTL and time-related helpers."""

    def test_parse_ttl_string(self):
        assert parse_ttl_string("1h") == 3600
        assert parse_ttl_string("30m") == 1800
        assert parse_ttl_string("2d") == 172800
        assert parse_ttl_string("3600") == 3600

    def test_parse_ttl_string_edge_cases(self):
        with pytest.raises(ValueError):
            parse_ttl_string("invalid")
        with pytest.raises(ValueError):
            parse_ttl_string("1x")  # Invalid unit

    def test_format_ttl_remaining(self):
        assert "1h" in format_ttl_remaining(3600)
        assert "30m" in format_ttl_remaining(1800)
        assert "expired" in format_ttl_remaining(-1)

    def test_calculate_expiry_time(self):
        ttl = 3600
        expiry = calculate_expiry_time(ttl)
        assert isinstance(expiry, datetime)
        assert expiry.tzinfo == timezone.utc

    def test_is_expired(self):
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        past = datetime.now(timezone.utc) - timedelta(hours=1)

        assert is_expired(future) is False
        assert is_expired(past) is True
        assert is_expired(future.isoformat()) is False
        assert is_expired(past.isoformat()) is True


class TestDataHelpers:
    """Test data processing helpers."""

    def test_hash_data(self):
        data = {"test": "data"}
        hash1 = hash_data(data)
        hash2 = hash_data(data)
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 length

    def test_hash_data_different_algorithms(self):
        data = "test"
        sha1_hash = hash_data(data, "sha1")
        md5_hash = hash_data(data, "md5")
        assert len(sha1_hash) == 40  # SHA1 length
        assert len(md5_hash) == 32  # MD5 length

    def test_sanitize_metadata_simple(self):
        metadata = {"key": "value", "number": 123}
        sanitized = sanitize_metadata(metadata)
        assert sanitized == metadata

    def test_sanitize_metadata_deep_nesting(self):
        metadata = {
            "level1": {"level2": {"level3": {"level4": {"level5": "too_deep"}}}}
        }
        sanitized = sanitize_metadata(metadata, max_depth=3)
        assert "level4" not in str(sanitized)

    def test_sanitize_metadata_complex_types(self):
        metadata = {
            "list": [1, 2, 3],
            "dict": {"a": 1},
            "set": {1, 2, 3},  # Set will be converted
            "tuple": (1, 2, 3),  # Tuple will be converted
        }
        sanitized = sanitize_metadata(metadata)
        assert isinstance(sanitized["list"], list)
        assert isinstance(sanitized["dict"], dict)
        assert isinstance(sanitized["set"], str)
        assert isinstance(sanitized["tuple"], str)


class TestConfigHelpers:
    """Test configuration helpers."""

    def test_parse_provider_url_simple(self):
        url = "redis://localhost:6379/0"
        config = parse_provider_url(url)
        assert config["host"] == "localhost"
        assert config["port"] == 6379
        assert config["db"] == 0

    def test_parse_provider_url_complex(self):
        url = "redis://user:pass@host:6380/1?ssl=true&timeout=5"
        config = parse_provider_url(url)
        assert config["host"] == "host"
        assert config["port"] == 6380
        assert config["db"] == 1
        assert config["username"] == "user"
        assert config["password"] == "pass"
        assert config["ssl"] is True
        assert config["timeout"] == 5

    def test_parse_provider_url_invalid(self):
        # Gerçek API invalid URL'de dict döndürüyor, None değil
        result = parse_provider_url("invalid-url")
        assert isinstance(result, dict)  # Gerçek davranış
        assert "path" in result

    def test_merge_configs(self):
        base = {"a": 1, "b": {"x": 1, "y": 2}}
        override = {"b": {"y": 3, "z": 4}, "c": 5}
        merged = merge_configs(base, override)
        assert merged["a"] == 1
        assert merged["b"]["x"] == 1
        assert merged["b"]["y"] == 3
        assert merged["b"]["z"] == 4
        assert merged["c"] == 5


class TestLoggingHelpers:
    """Test logging helpers."""

    def test_setup_logger(self):
        logger = setup_logger("test_logger", "DEBUG")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "test_logger"
        assert logger.level == logging.DEBUG

    def test_log_performance(self):
        # Should not raise any exceptions
        log_performance("test_func", 1.5, {"detail": "test"})
        log_performance("test_func", 0.5)


class TestSystemHelpers:
    """Test system information helpers."""

    def test_get_version_info(self):
        version_info = get_version_info()
        assert isinstance(version_info, dict)
        assert "psm_version" in version_info
        assert "python_version" in version_info

    def test_check_dependencies(self):
        deps = check_dependencies()
        assert isinstance(deps, dict)
        assert "redis" in deps
        assert isinstance(deps["redis"], bool)


class TestRetryDecorator:
    """Test retry_with_backoff decorator."""

    async def test_retry_success_on_first_attempt(self):
        """Test retry decorator when operation succeeds on first attempt."""
        from permission_storage_manager.utils.helpers import retry_with_backoff

        call_count = 0

        @retry_with_backoff(max_retries=3)
        async def successful_operation():
            nonlocal call_count
            call_count += 1
            return "success"

        result = await successful_operation()
        assert result == "success"
        assert call_count == 1

    async def test_retry_success_after_failures(self):
        """Test retry decorator when operation succeeds after some failures."""
        from permission_storage_manager.utils.helpers import retry_with_backoff

        call_count = 0

        @retry_with_backoff(max_retries=3, base_delay=0.01)
        async def eventually_successful_operation():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Temporary failure")
            return "success"

        result = await eventually_successful_operation()
        assert result == "success"
        assert call_count == 3

    async def test_retry_exhausted(self):
        """Test retry decorator when all retries are exhausted."""
        from permission_storage_manager.utils.helpers import retry_with_backoff

        call_count = 0

        @retry_with_backoff(max_retries=2, base_delay=0.01)
        async def always_failing_operation():
            nonlocal call_count
            call_count += 1
            raise ValueError("Persistent failure")

        with pytest.raises(ValueError, match="Persistent failure"):
            await always_failing_operation()

        assert call_count == 3  # Initial attempt + 2 retries

    async def test_retry_with_custom_delays(self):
        """Test retry decorator with custom delay parameters."""
        from permission_storage_manager.utils.helpers import retry_with_backoff
        import time

        call_count = 0
        start_time = time.time()

        @retry_with_backoff(max_retries=2, base_delay=0.1, max_delay=0.5)
        async def delayed_operation():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Temporary failure")
            return "success"

        result = await delayed_operation()
        end_time = time.time()

        assert result == "success"
        assert call_count == 3
        # Should have some delay between retries
        assert end_time - start_time > 0.1


class TestUtilsHelpersCoverage:
    """Test utils helpers coverage edge cases."""

    def test_filter_permissions_by_pattern(self):
        """Test filter_permissions_by_pattern function."""
        from permission_storage_manager.utils.helpers import (
            filter_permissions_by_pattern,
        )

        permissions = ["user:read", "user:write", "admin:read", "admin:write"]

        # Test wildcard pattern
        result = filter_permissions_by_pattern(permissions, "user:*")
        assert result == ["user:read", "user:write"]

        # Test exact match
        result = filter_permissions_by_pattern(permissions, "user:read")
        assert result == ["user:read"]

        # Test no match
        result = filter_permissions_by_pattern(permissions, "nonexistent:*")
        assert result == []

    def test_parse_ttl_string_edge_cases(self):
        """Test parse_ttl_string edge cases."""
        from permission_storage_manager.utils.helpers import parse_ttl_string

        # Test empty string
        with pytest.raises(ValueError, match="cannot be empty"):
            parse_ttl_string("")

        # Test whitespace only - should raise ValueError for invalid format
        with pytest.raises(ValueError, match="Invalid TTL format"):
            parse_ttl_string("   ")

        # Test invalid format
        with pytest.raises(ValueError, match="Invalid TTL format"):
            parse_ttl_string("1x")

        # Test invalid unit
        with pytest.raises(ValueError, match="Invalid TTL format"):
            parse_ttl_string("1z")

        # Test decimal values
        assert parse_ttl_string("1.5h") == 5400  # 1.5 * 3600
        assert parse_ttl_string("0.5m") == 30  # 0.5 * 60

    def test_format_ttl_remaining_edge_cases(self):
        """Test format_ttl_remaining edge cases."""
        from permission_storage_manager.utils.helpers import format_ttl_remaining

        # Test zero
        assert format_ttl_remaining(0) == "expired"

        # Test negative
        assert format_ttl_remaining(-1) == "expired"

        # Test very small values
        assert format_ttl_remaining(1) == "1s"
        assert format_ttl_remaining(30) == "30s"

        # Test exact minute
        assert format_ttl_remaining(60) == "1m"

        # Test exact hour
        assert format_ttl_remaining(3600) == "1h"

        # Test exact day
        assert format_ttl_remaining(86400) == "1d"

    def test_is_expired_edge_cases(self):
        """Test is_expired edge cases."""
        from permission_storage_manager.utils.helpers import is_expired
        from datetime import datetime, timezone, timedelta

        # Test expired datetime
        past_time = datetime.now(timezone.utc) - timedelta(hours=1)
        assert is_expired(past_time) is True

        # Test future datetime
        future_time = datetime.now(timezone.utc) + timedelta(hours=1)
        assert is_expired(future_time) is False

        # Test expired ISO string
        past_iso = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        assert is_expired(past_iso) is True

        # Test future ISO string
        future_iso = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        assert is_expired(future_iso) is False

        # Test ISO string with Z suffix
        past_iso_z = (
            (datetime.now(timezone.utc) - timedelta(hours=1))
            .isoformat()
            .replace("+00:00", "Z")
        )
        assert is_expired(past_iso_z) is True

    def test_hash_data_edge_cases(self):
        """Test hash_data edge cases."""
        from permission_storage_manager.utils.helpers import hash_data

        # Test with None
        hash_none = hash_data(None)
        assert isinstance(hash_none, str)
        assert len(hash_none) > 0

        # Test with empty dict
        hash_empty = hash_data({})
        assert isinstance(hash_empty, str)
        assert len(hash_empty) > 0

        # Test with empty list
        hash_list = hash_data([])
        assert isinstance(hash_list, str)
        assert len(hash_list) > 0

        # Test with different algorithms
        data = {"test": "data"}
        hash_md5 = hash_data(data, "md5")
        hash_sha1 = hash_data(data, "sha1")
        hash_sha256 = hash_data(data, "sha256")

        assert len(hash_md5) == 32  # MD5 hex digest length
        assert len(hash_sha1) == 40  # SHA1 hex digest length
        assert len(hash_sha256) == 64  # SHA256 hex digest length

        # Test that same data produces same hash
        assert hash_data(data) == hash_data(data)

    def test_sanitize_metadata_edge_cases(self):
        """Test sanitize_metadata edge cases."""
        from permission_storage_manager.utils.helpers import sanitize_metadata

        # Test with None
        result = sanitize_metadata(None)
        assert result == {}

        # Test with empty dict
        result = sanitize_metadata({})
        assert result == {}

        # Test with max_depth 0
        result = sanitize_metadata({"nested": {"data": "value"}}, max_depth=0)
        assert result == "[TRUNCATED]"

        # Test with max_depth 1
        result = sanitize_metadata({"nested": {"data": "value"}}, max_depth=1)
        assert result == {"nested": "[TRUNCATED]"}

        # Test with max_depth 2
        result = sanitize_metadata({"nested": {"data": "value"}}, max_depth=2)
        assert result == {"nested": {"data": "[TRUNCATED]"}}

        # Test with non-string keys
        result = sanitize_metadata({123: "value", None: "value2"})
        assert result == {"123": "value"}  # None key is filtered out

        # Test with complex nested structure
        complex_data = {
            "level1": {"level2": {"level3": {"level4": {"level5": "too_deep"}}}}
        }
        result = sanitize_metadata(complex_data, max_depth=3)
        assert result["level1"]["level2"]["level3"] == "[TRUNCATED]"


class TestHelpersEdgeCases:
    """Test edge cases and uncovered lines in helpers.py."""

    def test_parse_provider_url_with_query_params(self):
        """Test parse_provider_url with query parameters to cover lines 494-497."""
        from permission_storage_manager.utils.helpers import parse_provider_url

        # Test with boolean query params
        url = "redis://localhost:6379/0?ssl=true&timeout=5.0&retry=false"
        config = parse_provider_url(url)
        assert config["ssl"] is True
        assert config["timeout"] == 5.0
        assert config["retry"] is False

        # Test with numeric query params
        url = "redis://localhost:6379/0?max_connections=10&pool_size=5"
        config = parse_provider_url(url)
        assert config["max_connections"] == 10
        assert config["pool_size"] == 5

        # Test with string query params
        url = "redis://localhost:6379/0?password=secret&username=admin"
        config = parse_provider_url(url)
        assert config["password"] == "secret"
        assert config["username"] == "admin"

    def test_setup_logger_with_custom_format(self):
        """Test setup_logger with custom format string to cover line 564."""
        from permission_storage_manager.utils.helpers import setup_logger

        # Test with custom format
        custom_format = "%(levelname)s - %(message)s"
        logger = setup_logger("test_custom_format", "DEBUG", custom_format)
        
        # Verify logger is configured
        assert logger.name == "test_custom_format"
        assert logger.level == 10  # DEBUG level
        
        # Check that handler has custom format
        handler = logger.handlers[0]
        formatter = handler.formatter
        assert formatter._fmt == custom_format

    def test_check_dependencies_with_redis_import_error(self):
        """Test check_dependencies when redis import fails to cover lines 632-633."""
        from permission_storage_manager.utils.helpers import check_dependencies
        import sys
        from unittest.mock import patch

        # Mock import error for redis
        with patch.dict(sys.modules, {'redis': None}):
            dependencies = check_dependencies()
            assert dependencies["redis"] is False

        # Test with redis available
        try:
            import redis
            dependencies = check_dependencies()
            assert dependencies["redis"] is True
        except ImportError:
            # If redis is not installed, this is expected
            dependencies = check_dependencies()
            assert dependencies["redis"] is False
