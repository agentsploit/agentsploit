"""Classifier unit tests."""

from __future__ import annotations

from agentsploit.modules.mapper.classifier import classify
from agentsploit.modules.mapper.models import Classification, Node, Privilege


def _node(name: str, description: str = "", input_schema: dict | None = None) -> Node:
    return Node(
        id=f"test::{name}",
        server_uri="test",
        name=name,
        description=description,
        input_schema=input_schema or {},
    )


def test_classifies_read_prefix_as_source() -> None:
    classified = classify(_node("read_email"))
    assert classified.classification == Classification.SOURCE
    assert classified.privilege == Privilege.READ


def test_classifies_fetch_prefix_as_source() -> None:
    classified = classify(_node("fetch_url"))
    assert classified.classification == Classification.SOURCE


def test_classifies_send_email_as_egress_sink() -> None:
    classified = classify(_node("send_email"))
    assert classified.classification == Classification.SINK
    assert classified.privilege == Privilege.EGRESS


def test_classifies_run_command_as_execution_sink() -> None:
    classified = classify(_node("run_command"))
    assert classified.classification == Classification.SINK
    assert classified.privilege == Privilege.EXECUTION


def test_classifies_git_push_as_mutation() -> None:
    classified = classify(_node("git_push"))
    assert classified.classification == Classification.SINK
    assert classified.privilege == Privilege.MUTATION


def test_classifies_pure_unknown_as_pivot() -> None:
    classified = classify(_node("frobnicate"))
    assert classified.classification == Classification.PIVOT


def test_command_arg_promotes_to_execution_sink() -> None:
    classified = classify(
        _node(
            "exec_thing",
            input_schema={
                "type": "object",
                "properties": {"command": {"type": "string"}},
            },
        )
    )
    assert classified.classification == Classification.SINK
    assert classified.privilege == Privilege.EXECUTION


def test_description_phrase_marks_sink() -> None:
    classified = classify(
        _node("relay", description="Delivers a message to the configured webhook.")
    )
    assert classified.classification == Classification.SINK


def test_highest_privilege_wins_when_multiple_match() -> None:
    # name says "run_command" (execution) and arg says "to" (egress)
    classified = classify(
        _node(
            "run_command",
            input_schema={
                "type": "object",
                "properties": {"to": {"type": "string"}},
            },
        )
    )
    assert classified.privilege == Privilege.EXECUTION
