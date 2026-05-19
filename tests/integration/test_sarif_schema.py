"""SARIF 2.1.0 schema-conformance tests.

For v1.0 we guarantee that AgentSploit's SARIF output is interoperable
with industry tooling (GitHub Code Scanning, Defender for Cloud, etc.).
The test runs a real scan, emits SARIF, and validates the result against
the official SARIF 2.1.0 JSON Schema.
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path as FsPath

import pytest

from agentsploit.core import SARIFReporter, Session, Target
from agentsploit.modules.mcp.scanner import MCPScanner

pytestmark = pytest.mark.integration


SARIF_SCHEMA_URL = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)


@pytest.fixture(scope="module")
def sarif_schema(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Fetch the official SARIF 2.1.0 schema once per test session.

    Cached on disk to avoid hammering the network and to keep CI offline-
    capable after the first run.
    """
    cache = FsPath(__file__).parent.parent / ".sarif_schema_cache.json"
    if cache.exists():
        return json.loads(cache.read_text())
    try:
        with urllib.request.urlopen(SARIF_SCHEMA_URL, timeout=15) as resp:
            data = resp.read().decode()
    except Exception as e:
        pytest.skip(f"could not fetch SARIF schema: {e}")
    cache.write_text(data)
    return json.loads(data)


def _vulnerable_uri() -> str:
    p = FsPath(__file__).parent.parent / "fixtures" / "vulnerable_mcp" / "server.py"
    return f"stdio://{p}"


def _benign_uri() -> str:
    p = FsPath(__file__).parent.parent / "fixtures" / "benign_mcp" / "server.py"
    return f"stdio://{p}"


async def _scan_to_sarif(session: Session, target_uri: str, out: FsPath) -> dict:
    target = Target.parse(target_uri)
    scanner = MCPScanner()
    async for f in scanner.run(target, session):
        session.add(f)
    SARIFReporter(out).emit(session)
    return json.loads(out.read_text())


async def test_sarif_against_vulnerable_fixture_validates(
    session: Session, sarif_schema: dict, tmp_path: FsPath
) -> None:
    sarif = await _scan_to_sarif(session, _vulnerable_uri(), tmp_path / "vuln.sarif")
    _validate_sarif_basics(sarif)


async def test_sarif_against_benign_fixture_validates(
    session: Session, sarif_schema: dict, tmp_path: FsPath
) -> None:
    sarif = await _scan_to_sarif(session, _benign_uri(), tmp_path / "benign.sarif")
    _validate_sarif_basics(sarif)


async def test_sarif_passes_jsonschema(
    session: Session, sarif_schema: dict, tmp_path: FsPath
) -> None:
    """Validate the SARIF output against the official JSON Schema. This is
    the gate that gives us GitHub Code Scanning compatibility."""
    jsonschema = pytest.importorskip("jsonschema")

    sarif = await _scan_to_sarif(session, _vulnerable_uri(), tmp_path / "vuln.sarif")

    validator = jsonschema.Draft202012Validator(sarif_schema)
    errors = sorted(validator.iter_errors(sarif), key=lambda e: list(e.absolute_path))
    if errors:
        msgs = [f"  - {list(e.absolute_path) or '<root>'}: {e.message}" for e in errors[:10]]
        pytest.fail("SARIF schema violations:\n" + "\n".join(msgs))


# -------------------------------------------------------- structural sanity


def _validate_sarif_basics(sarif: dict) -> None:
    """Light structural checks that don't need the schema package installed."""
    assert sarif.get("version") == "2.1.0"
    assert sarif.get("$schema", "").endswith("sarif-schema-2.1.0.json")

    runs = sarif.get("runs") or []
    assert len(runs) == 1, f"expected exactly one run, got {len(runs)}"
    run = runs[0]

    tool = run.get("tool") or {}
    driver = tool.get("driver") or {}
    assert driver.get("name") == "agentsploit"
    assert driver.get("informationUri", "").startswith("https://")
    assert isinstance(driver.get("rules"), list)

    for rule in driver["rules"]:
        assert isinstance(rule.get("id"), str) and rule["id"], "rule missing id"
        assert isinstance(rule.get("name"), str), "rule missing name"
        # SARIF requires shortDescription on rules
        sd = rule.get("shortDescription") or {}
        assert isinstance(sd.get("text"), str), (
            f"rule {rule.get('id')} missing shortDescription.text"
        )
        config = rule.get("defaultConfiguration") or {}
        assert config.get("level") in {"none", "note", "warning", "error"}, (
            f"rule {rule.get('id')} has invalid level {config.get('level')!r}"
        )

    results = run.get("results") or []
    for r in results:
        assert isinstance(r.get("ruleId"), str)
        assert r.get("level") in {"none", "note", "warning", "error"}
        msg = r.get("message") or {}
        assert isinstance(msg.get("text"), str)
