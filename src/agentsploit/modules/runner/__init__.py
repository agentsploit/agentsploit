"""Live agent runner - drives generated payloads through real LLM agents and
detects canary surface to confirm exploitation.

Pipeline:

    InjectionArtifact (canary, technique, carrier)
            │
            ▼
    InjectionRunner.run(payload, agent_config)
            │
            ├──► AgentAdapter (anthropic / openai / mock / http)
            │       ├── exposes MockTools to the agent
            │       └── returns a RunTrace
            │
            └──► CanaryDetector.scan(trace, canary)
                    │
                    ▼
                Finding (CRITICAL if canary surfaces, INFO otherwise)
"""

from agentsploit.modules.runner.detector import CanaryDetector, CanarySurface
from agentsploit.modules.runner.runner import InjectionRunner
from agentsploit.modules.runner.tools import MockTool
from agentsploit.modules.runner.trace import (
    AssistantMessage,
    Message,
    RunTrace,
    ToolCall,
    ToolResult,
    UserMessage,
)

__all__ = [
    "AssistantMessage",
    "CanaryDetector",
    "CanarySurface",
    "InjectionRunner",
    "Message",
    "MockTool",
    "RunTrace",
    "ToolCall",
    "ToolResult",
    "UserMessage",
]
