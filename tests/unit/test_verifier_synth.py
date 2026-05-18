"""synth_runner_config unit tests."""

from __future__ import annotations

from agentsploit.modules.mapper.models import (
    Classification,
    Edge,
    Node,
    Path,
    Privilege,
)
from agentsploit.modules.verifier.synth_config import synth_runner_config


def _make_path() -> Path:
    source = Node(
        id="srv-a::read_email",
        server_uri="srv-a",
        name="read_email",
        description="Reads email body.",
        input_schema={"type": "object", "properties": {"id": {"type": "string"}}},
        classification=Classification.SOURCE,
        privilege=Privilege.READ,
    )
    sink = Node(
        id="srv-b::send_email",
        server_uri="srv-b",
        name="send_email",
        description="Sends email.",
        input_schema={
            "type": "object",
            "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
            "required": ["to", "body"],
        },
        classification=Classification.SINK,
        privilege=Privilege.EGRESS,
    )
    edge = Edge(src=source.id, dst=sink.id, weight=2.0)
    return Path(nodes=[source, sink], edges=[edge], total_weight=2.0)


def test_synth_registers_source_as_payload_tool() -> None:
    cfg = synth_runner_config(_make_path())
    payload_tools = [t for t in cfg.mock_tools if t.returns_payload]
    assert len(payload_tools) == 1
    assert payload_tools[0].name == "read_email"


def test_synth_registers_sink_as_passive_tool() -> None:
    cfg = synth_runner_config(_make_path())
    names = [t.name for t in cfg.mock_tools]
    assert "send_email" in names
    sink = next(t for t in cfg.mock_tools if t.name == "send_email")
    assert sink.returns_payload is False


def test_trigger_prompt_references_source_name() -> None:
    cfg = synth_runner_config(_make_path())
    assert "read_email" in cfg.trigger_prompt


def test_provider_passes_through() -> None:
    cfg = synth_runner_config(
        _make_path(),
        provider="anthropic",
        model="claude-sonnet-4-6",
        api_key_env="ANTHROPIC_API_KEY",
    )
    assert cfg.provider == "anthropic"
    assert cfg.model == "claude-sonnet-4-6"
    assert cfg.api_key_env == "ANTHROPIC_API_KEY"
