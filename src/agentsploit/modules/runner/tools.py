"""MockTool — a tool we expose to the target agent that returns a chosen string.

Used to deliver the payload realistically: the agent is told to read a
document or fetch a URL, and the mock tool returns the injection content.

v0.8 adds `on_call` — an optional callback that receives the agent's
tool-call arguments and returns the response. This lets a single tool
behave differently depending on what was passed in, which the memory-
poisoning module uses to wire `save_note`/`read_note` against a shared
backing store.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class MockTool(BaseModel):
    """A tool definition the runner exposes to the agent.

    Exactly one tool per agent run should have `returns_payload=True`. When
    the agent calls that tool, the runner returns the injection payload as
    the tool's output, simulating an agent fetching untrusted content.

    For arg-dependent behaviour (memory poisoning's save/read pattern), set
    `on_call` to a callable that takes the tool-call arguments and returns
    the response string. `on_call` overrides `returns_payload`/`static_response`.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

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
    """Returned content when `returns_payload=False` and `on_call=None`."""

    on_call: Callable[[dict[str, Any]], str] | None = Field(default=None, exclude=True)
    """If set, called with the tool-call arguments to compute the response.
    Overrides returns_payload/static_response. Excluded from serialization."""

    default_args: dict[str, Any] | None = None
    """If set, the mock adapter uses these arguments when synthesising a
    tool call to this tool (overrides the schema-derived default). Real
    adapters ignore this — the live agent picks args from the trigger prompt."""

    def render_response(self, payload: str, arguments: dict[str, Any] | None = None) -> str:
        if self.on_call is not None:
            return self.on_call(arguments or {})
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
