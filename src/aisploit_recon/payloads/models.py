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
    # Single-shot: ``template`` is the one message to send. May contain a
    # ``{canary}`` placeholder.
    template: str | None = Field(default=None, description="Single-shot body to send")
    # Multi-turn (D2): a sequence of messages. The canary placeholder may
    # appear in any turn; detection runs against the final turn's response.
    turns: list[str] | None = Field(default=None, description="Multi-turn message sequence")
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
    def is_multi_turn(self) -> bool:
        """True if this payload is a multi-turn conversation (``turns`` set)."""
        return self.turns is not None

    @property
    def requires_canary(self) -> bool:
        """True if a ``{canary}`` placeholder appears anywhere in the payload."""
        if self.template is not None:
            return "{canary}" in self.template
        if self.turns is not None:
            return any("{canary}" in t for t in self.turns)
        return False

    @property
    def body_text(self) -> str:
        """The displayable body of the payload (template for single-shot, or
        a joined summary of turns for multi-turn). Used for logging and reports."""
        if self.template is not None:
            return self.template
        if self.turns is not None:
            return " | ".join(self.turns)
        return ""

    @model_validator(mode="after")
    def _validate_payload_shape(self) -> Payload:
        # Exactly one of template / turns must be set.
        has_template = self.template is not None
        has_turns = self.turns is not None
        if has_template and has_turns:
            raise ValueError(
                f"Payload {self.id!r} sets both 'template' and 'turns' — "
                "use exactly one."
            )
        if not has_template and not has_turns:
            raise ValueError(
                f"Payload {self.id!r} has neither 'template' nor 'turns' — "
                "one is required."
            )
        # Multi-turn: must have at least 2 turns (1 turn = single-shot).
        if has_turns and self.turns is not None and len(self.turns) < 2:
            raise ValueError(
                f"Payload {self.id!r} 'turns' must have at least 2 messages "
                "(use 'template' for single-shot payloads)."
            )
        # Mutator / canary conflict applies to multi-turn too.
        if self.mutators and self.requires_canary:
            raise ValueError(
                f"Payload {self.id!r} uses both mutators and a {{canary}} "
                "placeholder — mutating would corrupt the canary token. "
                "Use one or the other."
            )
        return self
