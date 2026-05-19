"""FuzzPathVerifier unit tests."""

from __future__ import annotations

import pytest

from agentsploit.modules.mapper.models import (
    Classification,
    Edge,
    Node,
    Path,
    Privilege,
)
from agentsploit.modules.verifier.fuzzer import FuzzPathVerifier


def _path() -> Path:
    src = Node(
        id="srv-a::read_email",
        server_uri="srv-a",
        name="read_email",
        description="Reads email.",
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
    return Path(
        nodes=[src, sink],
        edges=[Edge(src=src.id, dst=sink.id, weight=1.0)],
        total_weight=1.0,
    )


def test_rejects_unknown_technique_in_list() -> None:
    with pytest.raises(ValueError, match="Unknown technique"):
        FuzzPathVerifier(path=_path(), techniques=["role_confusion", "nope"])


def test_defaults_to_full_fuzz_order_when_none_given() -> None:
    fuzzer = FuzzPathVerifier(path=_path())
    assert len(fuzzer.techniques) >= 4
    assert "role_confusion" in fuzzer.techniques


def test_accepts_custom_subset() -> None:
    fuzzer = FuzzPathVerifier(path=_path(), techniques=["direct", "delimiter"])
    assert fuzzer.techniques == ["direct", "delimiter"]
