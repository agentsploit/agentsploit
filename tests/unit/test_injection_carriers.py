"""Injection carrier tests."""

from __future__ import annotations

import pytest

from agentsploit.modules.injection.carriers import ALL_CARRIERS


@pytest.mark.parametrize("name,cls", ALL_CARRIERS.items())
def test_carrier_produces_payload(name: str, cls: type) -> None:
    out = cls().wrap(injection="INJECT", cover_text="Cover.", canary="AS-CANARY01")
    assert out.payload, f"{name} produced empty payload"
    assert out.content_type, f"{name} missing content_type"


def test_pdf_is_bytes() -> None:
    from agentsploit.modules.injection.carriers.pdf import PDFCarrier

    out = PDFCarrier().wrap(injection="INJECT", cover_text="Cover", canary="AS-X")
    assert isinstance(out.payload, bytes)
    assert out.payload.startswith(b"%PDF-")


def test_text_carrier_contains_injection() -> None:
    from agentsploit.modules.injection.carriers.text import TextCarrier

    out = TextCarrier().wrap(injection="UNIQUE-INJECT", cover_text="Hi", canary="C")
    assert "UNIQUE-INJECT" in out.payload  # type: ignore[operator]


def test_html_carrier_escapes_cover_but_keeps_injection() -> None:
    from agentsploit.modules.injection.carriers.html import HTMLCarrier

    out = HTMLCarrier().wrap(
        injection="UNIQUE-INJECT",
        cover_text="<script>alert(1)</script>",
        canary="C",
    )
    assert "<script>alert(1)</script>" not in out.payload  # type: ignore[operator]
    assert "&lt;script&gt;" in out.payload  # type: ignore[operator]
    assert "UNIQUE-INJECT" in out.payload  # type: ignore[operator]


def test_ical_is_rfc5545_shaped() -> None:
    from agentsploit.modules.injection.carriers.ical import ICalCarrier

    out = ICalCarrier().wrap(injection="INJECT", cover_text="Cover", canary="C")
    text = out.payload
    assert isinstance(text, str)
    assert text.startswith("BEGIN:VCALENDAR\r\n")
    assert "BEGIN:VEVENT\r\n" in text
    assert "END:VCALENDAR\r\n" in text
