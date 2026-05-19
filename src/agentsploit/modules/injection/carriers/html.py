"""HTML carrier - embeds payload in visible and hidden DOM nodes.

A web page that an agent crawls will tokenize all visible text plus often
attributes like `alt`, `title`, and `aria-label`. We place the payload in
multiple locations so different scrapers pick it up.
"""

from __future__ import annotations

from html import escape

from agentsploit.modules.injection.carriers.base import Carrier, CarrierOutput

_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{title}</title>
  <meta name="description" content="{injection_attr}">
</head>
<body>
  <article>
    <h1>{title}</h1>
    <p>{cover_text}</p>
    <p style="position:absolute;left:-9999px;color:#fff;font-size:0;" aria-hidden="false">
      {injection_visible}
    </p>
    <img src="data:image/gif;base64,R0lGODlhAQABAAAAACw=" alt="{injection_attr}" />
    <!--
    {injection_comment}
    -->
    <p style="display:none" data-canary="{canary}">{canary}</p>
  </article>
</body>
</html>
"""


class HTMLCarrier(Carrier):
    NAME = "html"
    CONTENT_TYPE = "text/html"

    def wrap(self, injection: str, cover_text: str, canary: str) -> CarrierOutput:
        title = (cover_text.splitlines()[0] if cover_text else "Document")[:80]
        payload = _TEMPLATE.format(
            title=escape(title),
            cover_text=escape(cover_text),
            injection_visible=escape(injection),
            injection_attr=escape(injection, quote=True),
            injection_comment=injection.replace("--", "- -"),
            canary=escape(canary),
        )
        return CarrierOutput(payload=payload, content_type=self.CONTENT_TYPE)
