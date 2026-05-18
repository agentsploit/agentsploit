"""Core abstractions for AgentSploit modules."""

from agentsploit.core.authorization import Authorization, AuthorizationError, TrainingAuth
from agentsploit.core.finding import Evidence, Finding, Severity
from agentsploit.core.module import Category, Module, ModuleMeta
from agentsploit.core.registry import Registry, registry
from agentsploit.core.reporter import JSONReporter, RichReporter, SARIFReporter
from agentsploit.core.session import Session
from agentsploit.core.target import Target, TargetType

__all__ = [
    "Authorization",
    "AuthorizationError",
    "Category",
    "Evidence",
    "Finding",
    "JSONReporter",
    "Module",
    "ModuleMeta",
    "Registry",
    "RichReporter",
    "SARIFReporter",
    "Session",
    "Severity",
    "Target",
    "TargetType",
    "TrainingAuth",
    "registry",
]
