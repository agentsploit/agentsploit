"""Email carrier — RFC 5322 message with HTML body, hidden Subject preview, custom headers."""

from __future__ import annotations

from email.message import EmailMessage
from html import escape

from agentsploit.modules.injection.carriers.base import Carrier, CarrierOutput


class EmailCarrier(Carrier):
    NAME = "email"
    CONTENT_TYPE = "message/rfc822"

    def wrap(self, injection: str, cover_text: str, canary: str) -> CarrierOutput:
        msg = EmailMessage()
        msg["From"] = "Compliance <compliance@example.com>"
        msg["To"] = "recipient@example.com"
        msg["Subject"] = (cover_text.splitlines()[0] if cover_text else "Compliance Review")[:80]
        msg["X-Canary"] = canary
        # Email headers can't contain CR/LF; collapse them for the X-header slot.
        header_safe = " ".join(injection.split())[:240]
        msg["X-Internal-Note"] = header_safe

        msg.set_content(f"{cover_text}\n\n{injection}\n")
        html = f"""\
<html>
  <body>
    <p>{escape(cover_text)}</p>
    <p style="color:#ffffff;font-size:1px;">{escape(injection)}</p>
    <div style="display:none;mso-hide:all" data-canary="{escape(canary)}">
      {escape(injection)}
    </div>
  </body>
</html>
"""
        msg.add_alternative(html, subtype="html")
        return CarrierOutput(payload=msg.as_string(), content_type=self.CONTENT_TYPE)
