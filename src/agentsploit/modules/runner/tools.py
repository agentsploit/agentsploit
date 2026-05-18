"""MockTool — a tool we expose to the target agent that returns a chosen string.

Used to deliver the payload realistically: the agent is told to read a
document or fetch a URL, and the mock tool returns the injection content.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class MockTool(BaseModel):
    """A tool definition the runner exposes to the agent.

    Exactly one tool per agent run should have `returns_payload=True`. When
    the agent calls that tool, the runner returns the injection payload as
    the tool's output, simulating an agent fetching untrusted content.
    """

    name: str
    description: str
    input_schema: dict[str, Any] = Field(
        default_factory=lambda: {
            "type": "object",
            "properties": {"name": {"type": "string"}},
        }
    )
    returns_payload: bool = False
    """If True, this tool's output is the injection payload. Otherwise it
    returns the `static_response` value, simulating a benign tool."""

    static_response: str = "[mock] ok"
    """Returned content when `returns_payload=False`."""

    def render_response(self, payload: str) -> str:
        return payload if self.returns_payload else self.static_response


def default_document_reader() -> MockTool:
    """The most common mock tool: an agent reads a document and gets the payload."""
    return MockTool(
        name="read_document",
        description=(
            "Reads the named document and returns its full text. Use this whenever "
            "the user references a document by name or filename."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Document name or filename.",
                },
            },
            "required": ["name"],
        },
        returns_payload=True,
    )
