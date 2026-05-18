"""iCalendar carrier — .ics calendar invite with payload in DESCRIPTION/SUMMARY.

Agents that watch a user's calendar (assistants, scheduling bots) ingest
event descriptions as untrusted content. We craft a minimal valid VEVENT
and stuff the payload into the DESCRIPTION property.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from agentsploit.modules.injection.carriers.base import Carrier, CarrierOutput


def _ical_escape(text: str) -> str:
    """Escape per RFC 5545: backslash, semicolon, comma, newline."""
    return text.replace("\\", "\\\\").replace(";", r"\;").replace(",", r"\,").replace("\n", r"\n")


def _fold(line: str) -> str:
    """RFC 5545 line folding at 75 octets."""
    if len(line) <= 75:
        return line
    chunks = [line[:75]] + [line[i : i + 74] for i in range(75, len(line), 74)]
    return "\r\n ".join(chunks)


class ICalCarrier(Carrier):
    NAME = "ical"
    CONTENT_TYPE = "text/calendar"

    def wrap(self, injection: str, cover_text: str, canary: str) -> CarrierOutput:
        now = datetime.now(UTC)
        dtstart = (now + timedelta(days=1)).strftime("%Y%m%dT%H%M%SZ")
        dtend = (now + timedelta(days=1, hours=1)).strftime("%Y%m%dT%H%M%SZ")
        dtstamp = now.strftime("%Y%m%dT%H%M%SZ")
        uid = f"{uuid4().hex}@agentsploit"

        summary = _ical_escape((cover_text.splitlines()[0] if cover_text else "Meeting")[:80])
        description = _ical_escape(f"{cover_text}\n\n{injection}")

        lines = [
            "BEGIN:VCALENDAR",
            "VERSION:2.0",
            "PRODID:-//AgentSploit//EN",
            "METHOD:REQUEST",
            "BEGIN:VEVENT",
            f"UID:{uid}",
            f"DTSTAMP:{dtstamp}",
            f"DTSTART:{dtstart}",
            f"DTEND:{dtend}",
            _fold(f"SUMMARY:{summary}"),
            _fold(f"DESCRIPTION:{description}"),
            f"X-CANARY:{canary}",
            "STATUS:CONFIRMED",
            "END:VEVENT",
            "END:VCALENDAR",
        ]
        return CarrierOutput(payload="\r\n".join(lines) + "\r\n", content_type=self.CONTENT_TYPE)
