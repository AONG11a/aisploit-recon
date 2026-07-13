"""Payload schema.

A payload is a declarative test case: what to send, how to decide if it
worked, and how bad it is if it did. Keeping payloads as data (YAML) rather
than code means the library can be extended, reviewed, and version-controlled
without touching the engine — and lets you pull vetted payloads from public
research (Garak, PyRIT, disclosed reports) into the same schema.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, model_validator


class PayloadCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    DATA_LEAKAGE = "data_leakage"
    INDIRECT_INJECTION = "indirect_injection"


class DetectionStrategy(str, Enum):
    SIGNATURE = "signature"
    CANARY = "canary"
    REFUSAL_CLASSIFIER = "refusal"
    LLM_JUDGE = "llm_judge"


class Payload(BaseModel):
    id: str = Field(..., description="Stable ID, e.g. 'PI-001'")
    category: PayloadCategory
    name: str
    description: str = ""
    template: str = Field(..., description="Body to send; may contain a {canary} placeholder")
    detection: DetectionStrategy

    success_indicators: list[str] = Field(default_factory=list)
    refusal_indicators: list[str] = Field(default_factory=list)

    severity_base: float = Field(default=5.0, ge=0.0, le=10.0)
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    enabled: bool = True

    # Mutators to apply (base64/rot13/leetspeak/homoglyph/zero_width).
    # Cannot be used together with canary detection — mutating a canary payload
    # would corrupt the token the detector looks for.
    mutators: list[str] = Field(default_factory=list)

    @property
    def requires_canary(self) -> bool:
        return "{canary}" in self.template

    @model_validator(mode="after")
    def _check_canary_mutator_conflict(self) -> Payload:
        if self.mutators and self.requires_canary:
            raise ValueError(
                f"Payload {self.id!r} uses both mutators and a {{canary}} "
                "placeholder — mutating would corrupt the canary token. "
                "Use one or the other."
            )
        return self
