"""Plain text carrier."""

from __future__ import annotations

from agentsploit.modules.injection.carriers.base import Carrier, CarrierOutput


class TextCarrier(Carrier):
    NAME = "text"
    CONTENT_TYPE = "text/plain"

    def wrap(self, injection: str, cover_text: str, canary: str) -> CarrierOutput:
        payload = f"{cover_text}\n\n{injection}\n"
        return CarrierOutput(payload=payload, content_type=self.CONTENT_TYPE)
