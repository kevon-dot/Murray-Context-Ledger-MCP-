# Murray → Ledger Wire Contract (v1)

This is the **authoritative contract** for what the Murray app sends to the
Context Ledger's `remember_facts` MCP tool. It is the integration source of
truth: a Murray engineer builds against this document, and the Ledger enforces
exactly the shape described here (`server/app/schemas.py`,
`server/app/mcp_server.py`). It contains **no Murray-side code** — the Ledger
owns and validates the shape; Murray conforms to it.

---

## 1. Scope — what lives where

Murray performs **speech → intent → structured typed facts**. The Ledger does
**validate-and-store only**.

- The Ledger **never** receives raw audio or transcripts. There is no NLP,
  transcription, or LLM call anywhere in the Ledger repo, and none should ever
  be added — that boundary is the whole point of the split.
- Murray decides *what is true* (extraction, typing, confidence). The Ledger
  decides *whether the payload is well-formed and who may store it*, then keeps
  it isolated per org and audited per person.

## 2. Transport

- Murray authenticates as a registered, **per-org** OAuth client. Its ledger
  `clients` row carries `connector_source = 'murray_app'`, so every fact it
  writes is attributable to Murray in the audit trail
  (`audit_log.client_id → clients.connector_source`).
- Murray calls the MCP tool **`remember_facts`** with a single argument,
  `facts`: a JSON array. Each element conforms to **`FactInput`**
  (`server/app/schemas.py`).
- Isolation is resolved in Postgres from the caller's membership; the token
  carries only the Auth0 `sub`. Murray never sends an `org_id` — the Ledger
  stamps it from the authenticated membership. A user who is not a member of
  exactly one org is rejected (see §7).

## 3. Field-by-field spec (`FactInput`)

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | enum | **yes** | — | One of `identity`, `preference`, `state`, `episodic`, `relationship`, `style`, `behavioral`. |
| `content` | string | **yes** | — | Non-empty. The human-readable fact. |
| `confidence` | number | no | `0.5` | `0.0`–`1.0`. Drives auto-promotion (§5). |
| `scope_tags` | string[] | no | `["account"]` | Visibility tags. For field sales the default `account` scope is correct; the row is shared across the org. |
| `source` | enum | no | `mcp_writeback` | Murray sends `murray_app`. Full set: `import_chatgpt`, `import_claude`, `dump_prompt`, `mcp_writeback`, `save_session`, `refresh_diff`, `murray_app`, `murray_clip`, `user_manual`. |
| `source_ref` | string | no | `null` | External ref, e.g. an account/job id (`job:henderson`). |
| `dedupe_key` | string | no | `null` | Idempotency key (§4). Omit and the fact is always inserted. |

Unknown fields are **rejected** (`extra="forbid"`) so a misspelled key fails
loudly instead of being silently dropped. `org_id`, `user_id`, and `status` are
**not** client-settable — the Ledger stamps them.

## 4. `dedupe_key` derivation (normative)

A `dedupe_key` makes a re-sent fact a **no-op**: the Ledger holds a partial
unique index on `(org_id, dedupe_key)`, so the same key in the same org is
stored once. The key is **org-scoped** — the same key in a different org is a
distinct fact.

To make re-sends stable, derive the key as a SHA-256 hex digest of
**`normalized(content) | source_ref | source`**, where `normalized` is, in order:

1. lowercase;
2. remove punctuation — every character that is **not** a letter, digit, or
   whitespace is deleted (not replaced with a space);
3. collapse every run of whitespace to a single space;
4. strip leading/trailing whitespace.

The three parts are joined with a single `|` (U+007C). Reference implementation
(any writer that produces this exact string derives identical keys):

```python
import hashlib, re

def dedupe_key(content: str, source_ref: str, source: str) -> str:
    normalized = re.sub(r"\s+", " ", re.sub(r"[^\w\s]", "", content.lower())).strip()
    basis = f"{normalized}|{source_ref}|{source}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()
```

**Worked keys** (the canonical example in §6, `source_ref="job:henderson"`,
`source="murray_app"`):

| `content` | `normalized(content)` | `dedupe_key` |
|---|---|---|
| `Insurance claim is open on the roof` | `insurance claim is open on the roof` | `459424b5b5390ae144cf316471b71a72c82be7fb302c95f37c398b56468322ec` |
| `Spouse is the decision-maker` | `spouse is the decisionmaker` | `2816eda7a8d432401b82b1c96f11387f9a7dc699c38a90763118be96b47e7619` |
| `Soft decking on the north slope` | `soft decking on the north slope` | `a6f5759edccc2cd39e328ffce402ae6c4ea44876b3a97339c2a909f403d09449` |

`dedupe_key` is optional: omit it (or send `null`) and the fact is never
deduped. Use it whenever a spoken fact might be re-sent (retries, re-opens of
the same note).

## 5. Status semantics

Facts land **`pending_review`** unless `confidence >= 0.9`, in which case they
auto-promote to **`active`** and become **team-visible immediately**. Murray
should set realistic confidences: high confidence is instant org-wide
visibility, so reserve it for facts a rep stated plainly. The threshold is a
tunable Ledger constant (`AUTO_PROMOTE_CONFIDENCE`), not part of the wire shape.

## 6. Worked example — the canonical field note

Input utterance (handled entirely in Murray, shown only for context):

> "insurance claim open, spouse makes the decision, soft decking on the north slope."

The **exact** JSON Murray sends to `remember_facts`:

```json
{
  "facts": [
    { "type": "state",        "content": "Insurance claim is open on the roof", "confidence": 0.95, "scope_tags": ["account"], "source": "murray_app", "source_ref": "job:henderson", "dedupe_key": "459424b5b5390ae144cf316471b71a72c82be7fb302c95f37c398b56468322ec" },
    { "type": "relationship", "content": "Spouse is the decision-maker",         "confidence": 0.9,  "scope_tags": ["account"], "source": "murray_app", "source_ref": "job:henderson", "dedupe_key": "2816eda7a8d432401b82b1c96f11387f9a7dc699c38a90763118be96b47e7619" },
    { "type": "state",        "content": "Soft decking on the north slope",      "confidence": 0.85, "scope_tags": ["account"], "source": "murray_app", "source_ref": "job:henderson", "dedupe_key": "a6f5759edccc2cd39e328ffce402ae6c4ea44876b3a97339c2a909f403d09449" }
  ]
}
```

Outcome for this payload: facts 1 and 2 (`>= 0.9`) land `active`; fact 3
(`0.85`) lands `pending_review`. Re-sending the identical payload no-ops all
three (each reported as `deduped`).

## 7. Error contract

`remember_facts` is **per-item**: one malformed fact never drops the rest of a
voice note. It returns a structured summary (never a hard error for a bad fact):

```json
{
  "created":  ["<fact id>", "..."],
  "deduped":  ["<existing fact id>", "..."],
  "invalid":  [ { "index": 2, "errors": [ { "field": "confidence", "message": "..." } ] } ],
  "counts":   { "created": 1, "deduped": 1, "invalid": 1 },
  "connector_source": "murray_app"
}
```

- **created** — newly stored facts (their ids).
- **deduped** — a `dedupe_key` collision; the existing fact's id is returned, no
  new row, no error.
- **invalid** — per-item validation failures, each with the 0-based `index` into
  the request `facts` array and the offending `field`(s). Valid facts in the same
  call are unaffected. A single fact never partially commits.

`supersede_fact(old_fact_id, new_fact)` returns one of:

- success: `{ "superseded": "<old id>", "created": "<new id>", "new_status": "active"|"pending_review", "deduped": false }`
- invalid `new_fact`: `{ "superseded": null, "created": null, "invalid": [ … ] }` — nothing is written.
- `old_fact_id` not in your org: `{ "superseded": null, "created": null, "message": "No fact with that id exists in your org." }` — nothing is written (no orphan replacement).
- `old_fact_id` not a UUID: a tool error, `"'<id>' is not a valid fact id."`

Request-level rejections (returned as MCP tool errors, before any write):

| Condition | Message |
|---|---|
| Caller has no membership | "This account is not a member of any ledger org yet. …" |
| Caller is in >1 org | "This account belongs to more than one org, which is not supported in v1. …" |
| Connector revoked | "This client's access to the ledger has been revoked. …" |

Every outcome — created, deduped, superseded, and rejected writes — is appended
to `audit_log`, attributable to Murray via the connector.

## 8. Versioning

This is **Contract v1**. v1 assumes **one org per user** (a caller in zero or
multiple orgs is rejected, §7). The multi-org seam is intentionally unbuilt;
when it lands, the transport gains an explicit org selector and this document
moves to v2. The fact shape (§3) and `dedupe_key` derivation (§4) are stable
within v1.
