"""Inbound shape validation for the write path (P4).

The ledger validates-and-stores already-structured typed facts; it performs no
NLP. ``FactInput`` is the wire shape an AI client (Murray, Claude, ChatGPT)
sends to ``remember_facts`` / ``supersede_fact``. The enums mirror the
``facts.type`` and ``facts.source`` CHECK constraints in 0001 exactly — pydantic
gives a clear client-facing error before the row ever reaches Postgres, and the
DB CHECK remains the backstop.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# Mirrors facts.type CHECK (0001).
FactType = Literal[
    "identity",
    "preference",
    "state",
    "episodic",
    "relationship",
    "style",
    "behavioral",
]

# Mirrors facts.source CHECK (0001) — every accepted value, not just Murray's.
FactSource = Literal[
    "import_chatgpt",
    "import_claude",
    "dump_prompt",
    "mcp_writeback",
    "save_session",
    "refresh_diff",
    "murray_app",
    "murray_clip",
    "user_manual",
]


class FactInput(BaseModel):
    """One inbound fact. Extra keys are rejected so a malformed payload fails
    loudly rather than silently dropping a misspelled field."""

    model_config = ConfigDict(extra="forbid")

    type: FactType
    content: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    scope_tags: list[str] = Field(default_factory=lambda: ["account"])
    source: FactSource = "mcp_writeback"
    source_ref: str | None = None
    dedupe_key: str | None = None
