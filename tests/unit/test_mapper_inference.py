"""Edge inference unit tests."""

from __future__ import annotations

from agentsploit.modules.mapper.classifier import classify
from agentsploit.modules.mapper.inference import infer_edges
from agentsploit.modules.mapper.models import Node


def _classify(name: str, description: str = "", input_schema: dict | None = None) -> Node:
    return classify(
        Node(
            id=f"test::{name}",
            server_uri="test",
            name=name,
            description=description,
            input_schema=input_schema or {},
        )
    )


def test_source_to_sink_baseline_edge_exists() -> None:
    src = _classify("read_email", "Reads email content.")
    sink = _classify("send_email")
    edges = infer_edges([src, sink])
    assert any(e.src == src.id and e.dst == sink.id for e in edges)


def test_no_self_loops() -> None:
    n = _classify("read_email")
    edges = infer_edges([n])
    assert not any(e.src == e.dst for e in edges)


def test_no_edge_into_a_source() -> None:
    src = _classify("read_file")
    other = _classify("read_url")
    edges = infer_edges([src, other])
    # Sources should never appear as dst
    assert all(e.dst not in (src.id, other.id) for e in edges)


def test_no_edge_out_of_a_sink() -> None:
    sink_a = _classify("send_email")
    sink_b = _classify("git_push")
    pivot = _classify("frobnicate")
    edges = infer_edges([sink_a, sink_b, pivot])
    assert all(e.src not in (sink_a.id, sink_b.id) for e in edges)


def test_shared_arg_name_strengthens_edge() -> None:
    src = _classify(
        "fetch_data",
        description="Fetches content from the given URL and returns the body text.",
    )
    sink = _classify(
        "send_email",
        input_schema={
            "type": "object",
            "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
        },
    )
    edges = infer_edges([src, sink])
    chain = next(e for e in edges if e.src == src.id and e.dst == sink.id)
    # `body` is in the source description and is an arg of the sink → weight should be lowered
    assert any("body" in r for r in chain.reasons), chain.reasons
    assert chain.weight < 5.0
