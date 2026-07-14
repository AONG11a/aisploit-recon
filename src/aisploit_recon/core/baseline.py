"""Baseline characterisation for false-positive suppression (DESIGN D1).

A target that indiscriminately echoes user input (RAG UIs, "you said: ..."
confirmations) will reflect a canary token even though the injected
*instructions* were never followed — a false positive.

``Baseline`` captures whether the target reflects input: we send a benign
control message carrying a ``CONTROL_<hex>`` token. If the control token
appears in the response, the target reflects input and canary hits are
penalised (downgraded to INCONCLUSIVE at reduced confidence) rather than
trusted.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from aisploit_recon.utils.crypto import content_digest


@dataclass(frozen=True)
class Baseline:
    """Result of a single control probe against the target.

    ``reflects_input`` is True when the control canary was echoed verbatim,
    signalling that the target indiscriminately reflects user input.
    """

    reflects_input: bool
    control_digest: str
    control_excerpt: str = ""


def generate_control_token() -> str:
    """A token distinct from the canary namespace, used only for baseline."""
    return f"CONTROL_{secrets.token_hex(8)}_END"


def build_baseline(control_response: str, control_token: str) -> Baseline:
    """Construct a Baseline from the control probe's response text."""
    found = control_token in control_response
    if found:
        idx = control_response.find(control_token)
        start = max(0, idx - 30)
        end = idx + len(control_token) + 30
        excerpt = control_response[start:end]
    else:
        excerpt = ""
    return Baseline(
        reflects_input=found,
        control_digest=content_digest(control_response),
        control_excerpt=excerpt,
    )
