"""Module-two aggregation compatibility contracts.

All supported burst aggregation now happens in module one.  Module two keeps
an identity aggregator protocol so alternative graph implementations can retain
the original dependency-injection surface without changing alert membership.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Protocol

from ...models import AlertObject, NormalizedAlert
from ..benign_fingerprint import brute_force_family


class BurstAlertAggregator(Protocol):
    """Compatibility protocol for pre-graph alert-object preparation."""

    def aggregate(self, alerts: Iterable[AlertObject]) -> tuple[AlertObject, ...]:
        """Return graph inputs without changing module-one membership."""
        ...


class IdentityBurstAlertAggregator:
    """Leave module-one alert objects unchanged before graph construction."""

    def aggregate(self, alerts: Iterable[AlertObject]) -> tuple[AlertObject, ...]:
        return tuple(alerts)


@dataclass(slots=True)
class SessionBurstAlertAggregator(IdentityBurstAlertAggregator):
    """Deprecated identity adapter retained for older dependency injection."""

    inactivity_threshold_seconds: int = 60

    def __post_init__(self) -> None:
        if self.inactivity_threshold_seconds <= 0:
            raise ValueError("inactivity_threshold_seconds must be positive")


def behavior_category(alert: NormalizedAlert) -> str | None:
    """Compatibility helper for the former module-two brute-force detector."""

    return "brute_force" if brute_force_family(alert) is not None else None
