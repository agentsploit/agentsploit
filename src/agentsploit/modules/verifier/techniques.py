"""Path-targeted injection techniques — back-compat shim.

The v0.5 module exposed a single `PathVerifyTechnique`. v0.7 broke that out
into a catalog of variants under `targeted_techniques.py`. This file re-exports
the role-confusion variant under its old name for back-compat.

New code should import from `verifier.targeted_techniques`.
"""

from __future__ import annotations

from agentsploit.modules.verifier.targeted_techniques import (
    RoleConfusionPathVerify as PathVerifyTechnique,
)
from agentsploit.modules.verifier.targeted_techniques import (
    _filler_for,
    _scaffold_required_args,
)

__all__ = ["PathVerifyTechnique", "_filler_for", "_scaffold_required_args"]
