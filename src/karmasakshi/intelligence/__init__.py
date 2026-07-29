"""The deterministic Effect Intelligence Engine (extreme-v2 Phase 1).

Assesses a proposed ``EffectManifest`` against a versioned
``IntelligencePolicy`` and explicit ``AssessmentFacts``, producing a
structured ``EffectAssessment``. See docs/effect-intelligence.md.
"""

from __future__ import annotations

from karmasakshi.intelligence.engine import EffectIntelligenceEngine
from karmasakshi.intelligence.facts import AssessmentFacts, derive_facts_from_audit
from karmasakshi.intelligence.model import (
    EffectAssessment,
    Recommendation,
    RiskLevel,
    RiskSignal,
    VerificationStrength,
)
from karmasakshi.intelligence.policy import DEFAULT_INTELLIGENCE_POLICY, IntelligencePolicy

__all__ = [
    "DEFAULT_INTELLIGENCE_POLICY",
    "AssessmentFacts",
    "EffectAssessment",
    "EffectIntelligenceEngine",
    "IntelligencePolicy",
    "Recommendation",
    "RiskLevel",
    "RiskSignal",
    "VerificationStrength",
    "derive_facts_from_audit",
]
