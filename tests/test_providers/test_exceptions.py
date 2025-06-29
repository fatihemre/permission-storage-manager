from permission_storage_manager.core.exceptions import (
    ProviderError,
    SerializationError,
    ValidationError,
)


def test_serialization_error_str():
    err = SerializationError("write", "test.json", "fail")
    assert "Serialization error during write" in str(err)
    assert "test.json" in str(err)
    assert "fail" in str(err)


def test_provider_error_chaining():
    try:
        raise ValueError("inner")
    except ValueError as e:
        err = ProviderError("outer", details={"foo": "bar"})
        err.__cause__ = e
        assert "outer" in str(err)
        assert err.details["foo"] == "bar"


def test_validation_error_details():
    err = ValidationError("field_name", "invalid_value", "must be string")
    assert "field_name" in str(err)
    assert "invalid_value" in str(err)
    assert "must be string" in str(err)
