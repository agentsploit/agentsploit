"""Base class for carriers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class CarrierOutput:
    """A carrier produces either text or bytes plus a content-type."""

    payload: str | bytes
    content_type: str


class Carrier(ABC):
    """Embeds a technique-produced injection string in a target format."""

    NAME: str = ""
    CONTENT_TYPE: str = "text/plain"

    @abstractmethod
    def wrap(self, injection: str, cover_text: str, canary: str) -> CarrierOutput:
        """Return the carrier output containing the injection."""
        ...
