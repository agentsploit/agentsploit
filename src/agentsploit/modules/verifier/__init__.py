"""Path verifier — turn a mapper-inferred path into a confirmed exploit.

Pipeline:

    Graph + (source, sink) tool names
            │
            ▼
    paths.shortest_path()  →  Path
            │
            ▼
    PathVerifyTechnique.craft()  →  injection string aimed at the sink
            │
            ▼
    synth_runner_config()  →  RunnerConfig with auto-built MockTools
            │
            ▼
    InjectionRunner.run()  →  RunTrace
            │
            ▼
    Detector (scoped to the sink tool)  →  Finding
"""

from agentsploit.modules.verifier.batch import BatchPathVerifier
from agentsploit.modules.verifier.synth_config import synth_runner_config
from agentsploit.modules.verifier.techniques import PathVerifyTechnique
from agentsploit.modules.verifier.verifier import PathVerifier, VerifierOutcome

__all__ = [
    "BatchPathVerifier",
    "PathVerifier",
    "PathVerifyTechnique",
    "VerifierOutcome",
    "synth_runner_config",
]
