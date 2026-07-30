"""Detection rules.

Two algorithm classes cover every shipped detection:

* ``PatternSignatureRule`` — stateless per-line regex matching (SQLi, traversal),
  aggregated per IP into one finding.
* ``ThresholdRule`` — stateful per-IP sliding window (brute force, scanning).

Behavior lives in these classes; parameters (thresholds, patterns, severities)
are data supplied via config specs. A registry + ``build_rules`` factory turns
structured specs into rule instances.

See docs/engine-plan.md §6.
"""

from __future__ import annotations

from engine.rules.base import Rule
from engine.rules.factory import build_rules
from engine.rules.registry import RULE_TYPES, register
from engine.rules.signature import PatternSignatureRule
from engine.rules.threshold import ThresholdRule

__all__ = [
    "Rule",
    "PatternSignatureRule",
    "ThresholdRule",
    "RULE_TYPES",
    "register",
    "build_rules",
]
