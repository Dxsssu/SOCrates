"""Canonical alert fingerprint contracts."""

from __future__ import annotations

import hashlib
import json
from typing import Protocol, runtime_checkable

from .event_tree import LAYER_ORDER, AlertPath


@runtime_checkable
class FingerprintCanonicalizer(Protocol):
    """Normalize dynamic fields and serialize stable fingerprints."""

    def canonicalize(self, path: AlertPath) -> str:
        """Return the collision-verifiable canonical fingerprint string."""
        ...

    def digest(self, canonical_fingerprint: str) -> str:
        """Return the lookup hash for a canonical fingerprint."""
        ...


class SHA256FingerprintCanonicalizer:
    """Canonical JSON serialization with SHA-256 lookup digests."""

    version = 1

    def canonicalize(self, path: AlertPath) -> str:
        payload = {
            "version": self.version,
            "layers": [
                {"name": layer.value, "value": value}
                for layer, value in zip(LAYER_ORDER, path.values, strict=True)
            ],
        }
        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    def digest(self, canonical_fingerprint: str) -> str:
        return hashlib.sha256(canonical_fingerprint.encode("utf-8")).hexdigest()
