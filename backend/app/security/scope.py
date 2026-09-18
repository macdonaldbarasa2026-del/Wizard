from __future__ import annotations

import re
import urllib.parse
from app.models.schemas import TargetScope


class ScopeError(ValueError):
    """Raised when target scope verification fails or authorization is missing."""
    pass


DANGEROUS_TARGET_CHARS = re.compile(r"[`$;&|><\n\r\t]")


def validate_target_scope(scope: TargetScope | dict | None) -> TargetScope:
    """Validate that testing scope is authorized and within approved host/port boundaries.
    
    Never allows arbitrary internet targets or unauthorized scans.
    """
    if scope is None:
        raise ScopeError("Testing scope is required. Explicit authorization must be provided.")

    if isinstance(scope, dict):
        scope = TargetScope(**scope)

    if not scope.authorized:
        raise ScopeError(
            "Target is unauthorized. Security testing requires explicit user authorization (authorized=True)."
        )

    target_str = scope.target.strip()
    if not target_str:
        raise ScopeError("Target cannot be empty.")

    if DANGEROUS_TARGET_CHARS.search(target_str):
        raise ScopeError("Target contains invalid or dangerous characters.")

    # Parse hostname and port
    if "://" in target_str:
        parsed = urllib.parse.urlparse(target_str)
        host = parsed.hostname or ""
        port = parsed.port
    elif ":" in target_str and not target_str.startswith("["):
        parts = target_str.split(":", 1)
        host = parts[0]
        try:
            port = int(parts[1].split("/")[0])
        except ValueError:
            raise ScopeError(f"Invalid port in target: {parts[1]}")
    else:
        host = target_str.split("/")[0]
        port = None

    host = host.lower().strip("[]")

    if not host:
        raise ScopeError(f"Could not parse valid hostname from target: {target_str}")

    # Check host against allowed_hosts
    allowed_normalized = [h.lower().strip("[]") for h in scope.allowed_hosts]
    if host not in allowed_normalized:
        raise ScopeError(
            f"Target host '{host}' is not in approved allowed_hosts list: {scope.allowed_hosts}. "
            "Never scan arbitrary or unapproved external targets."
        )

    # Check against excluded_targets
    for excluded in scope.excluded_targets:
        ex_norm = excluded.lower().strip()
        if ex_norm and (ex_norm == host or ex_norm in target_str.lower()):
            raise ScopeError(
                f"Target '{target_str}' matches excluded target '{excluded}' and is blocked by scope policy."
            )

    # Check port if specified
    if port is not None and port not in scope.allowed_ports:
        raise ScopeError(
            f"Target port {port} is not in approved allowed_ports list: {scope.allowed_ports}."
        )

    return scope
