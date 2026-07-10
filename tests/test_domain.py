import pytest

from app.core.domain import DomainValidationError, ensure_authorized_scope, normalize_domain


def test_domain_normalization():
    assert normalize_domain(" ExAmPle.COM. ") == "example.com"


@pytest.mark.parametrize("value", ["", "https://example.com", "example.com/path", "127.0.0.1", "bad_label.example.com"])
def test_invalid_domains(value):
    with pytest.raises(DomainValidationError):
        normalize_domain(value)


def test_scope_accepts_subdomains():
    ensure_authorized_scope("api.example.com", ("example.com",), False)


def test_scope_rejects_unlisted_target():
    with pytest.raises(PermissionError):
        ensure_authorized_scope("example.org", ("example.com",), False)
