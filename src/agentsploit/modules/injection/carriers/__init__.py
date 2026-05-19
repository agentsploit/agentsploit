"""Carriers - embed a payload in a transport format (text, markdown, html, pdf, email, ical)."""

from agentsploit.modules.injection.carriers.base import Carrier, CarrierOutput
from agentsploit.modules.injection.carriers.email import EmailCarrier
from agentsploit.modules.injection.carriers.html import HTMLCarrier
from agentsploit.modules.injection.carriers.ical import ICalCarrier
from agentsploit.modules.injection.carriers.markdown import MarkdownCarrier
from agentsploit.modules.injection.carriers.pdf import PDFCarrier
from agentsploit.modules.injection.carriers.text import TextCarrier

ALL_CARRIERS: dict[str, type[Carrier]] = {
    "text": TextCarrier,
    "markdown": MarkdownCarrier,
    "html": HTMLCarrier,
    "pdf": PDFCarrier,
    "email": EmailCarrier,
    "ical": ICalCarrier,
}

__all__ = [
    "ALL_CARRIERS",
    "Carrier",
    "CarrierOutput",
    "EmailCarrier",
    "HTMLCarrier",
    "ICalCarrier",
    "MarkdownCarrier",
    "PDFCarrier",
    "TextCarrier",
]
