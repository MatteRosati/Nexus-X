import ipaddress
import re

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class DomainValidationError(ValueError):
    pass


def normalize_domain(value: str) -> str:
    if not isinstance(value, str):
        raise DomainValidationError("Domain must be a string")
    raw = value.strip().rstrip(".")
    if not raw:
        raise DomainValidationError("Domain cannot be empty")
    if len(raw) > 253:
        raise DomainValidationError("Domain is too long")
    if any(token in raw for token in ("://", "/", "?", "#", "@", "\\")):
        raise DomainValidationError("Provide only a domain name, without URL, path, port or credentials")
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        raise DomainValidationError("IP addresses are not accepted by this endpoint")

    try:
        ascii_domain = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise DomainValidationError("Invalid internationalized domain name") from exc

    labels = ascii_domain.split(".")
    if len(labels) < 2:
        raise DomainValidationError("A public-style domain with at least two labels is required")
    if any(not _LABEL.fullmatch(label) for label in labels):
        raise DomainValidationError("Domain contains an invalid label")
    return ascii_domain


def is_subdomain_or_equal(candidate: str, root: str) -> bool:
    return candidate == root or candidate.endswith("." + root)


def ensure_authorized_scope(domain: str, allowed_domains: tuple[str, ...], allow_arbitrary: bool) -> None:
    if allow_arbitrary:
        return
    if not allowed_domains:
        raise PermissionError("No authorized scope is configured. Set EASM_ALLOWED_DOMAINS.")
    if not any(is_subdomain_or_equal(domain, allowed) for allowed in allowed_domains):
        raise PermissionError("Target is outside the configured authorized scope")
