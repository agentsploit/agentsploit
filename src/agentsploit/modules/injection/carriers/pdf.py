"""PDF carrier - visible cover text + a low-contrast hidden injection layer.

Agents that OCR or text-extract PDFs typically don't filter by color or
font size, so we place the payload in white-on-white tiny text at the bottom.
"""

from __future__ import annotations

from io import BytesIO

from reportlab.lib.colors import Color, black
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from agentsploit.modules.injection.carriers.base import Carrier, CarrierOutput


class PDFCarrier(Carrier):
    NAME = "pdf"
    CONTENT_TYPE = "application/pdf"

    def wrap(self, injection: str, cover_text: str, canary: str) -> CarrierOutput:
        buf = BytesIO()
        c = canvas.Canvas(buf, pagesize=letter)
        _width, height = letter

        c.setTitle("Compliance Review")
        c.setAuthor("Internal")
        c.setSubject(injection[:240])  # also tucked into the document subject
        c.setKeywords([canary, "review"])

        # Visible cover content
        c.setFillColor(black)
        c.setFont("Helvetica-Bold", 18)
        c.drawString(72, height - 100, "Quarterly Compliance Review")
        c.setFont("Helvetica", 11)
        text_obj = c.beginText(72, height - 140)
        for line in cover_text.splitlines() or [cover_text]:
            text_obj.textLine(line[:100])
        c.drawText(text_obj)

        # Hidden injection: white on white, 1pt
        c.setFillColor(Color(1, 1, 1, alpha=1))
        c.setFont("Helvetica", 1)
        hidden = c.beginText(72, 72)
        for raw_line in injection.splitlines():
            # Avoid extremely long lines that ReportLab refuses
            chunks = [raw_line[i : i + 200] for i in range(0, len(raw_line), 200)] or [""]
            for chunk in chunks:
                hidden.textLine(chunk)
        c.drawText(hidden)

        c.showPage()
        c.save()
        return CarrierOutput(payload=buf.getvalue(), content_type=self.CONTENT_TYPE)
