# Batch Contract

## Contents

- [Complete a full pass](#complete-a-full-pass)
- [Manifest envelope](#manifest-envelope)
- [Legacy item representation](#legacy-item-representation)
- [Discovery traces and success evidence](#discovery-traces-and-success-evidence)
- [Bounded artifact validation](#bounded-artifact-validation)
- [Actual v2 bridge](#actual-v2-bridge)
- [Honest review queue](#honest-review-queue)
- [Completion invariant](#completion-invariant)

## Complete a full pass

- Preserve every accepted, trimmed input title and its order, including
  duplicates.
- Initialize the full batch before discovery and continue after ambiguity, access
  failure, retrieval failure, and verification failure.
- Do not interrupt the first pass for per-item choices. Present all review actions
  together, apply the submitted set in the active Codex process, and repeat.
- Before adding an item to that review set, exhaust its applicable bounded
  identifier-location and public transfer routes and record their outcomes.
- Treat a single title as a one-item batch.

## Manifest envelope

`scripts/paper_finder_batch.py` initializes manifest-envelope schema version `2`
and accepts historical envelope schema version `1`. Both versions require these
root fields:

```text
schema_version: 1 or 2
revision
created_at
updated_at
review_state
done
items
```

`revision` is a nonnegative integer; timestamps include a timezone;
`review_state` is `processing`, `review_ready`, `submitted`, or `done`; and `done`
is a boolean consistent with that state. `schema_version` must be a non-boolean
integer `1` or `2`. `save_manifest` validates the JSON tree and secret patterns,
increments `revision`, updates `updated_at`, and atomically replaces the file.

New manifests use root `schema_version: 2` and must contain `operations_v2`, whose
own closed root also has `schema_version: 2`. A root-schema-2 manifest without that
field is invalid. The envelope itself is not closed and permits additional root
fields.

A historical root-schema-1 manifest without `operations_v2` remains readable by
validation and produces a legacy warning, but it is migration-only: serving
review, saving review decisions, submitting actions, finishing, reopening, and
export all refuse it until v2 is embedded. Root schema 1 with a valid embedded v2
remains supported; once the field is present, the closed-state and bridge checks
are enforced exactly as they are for root schema 2.

Treat every manifest value as untrusted. Never store credentials, cookies,
authorization headers, one-time codes, private keys, browser/session state,
signed URLs, raw headers, or secret-bearing comments or provenance.

## Legacy item representation

Every item requires:

```text
id
requested_title
status
match_type
comment
candidates
selected_candidate_id
selected_version_id
pending_action
decision_history
```

Item status is `pending`, `processing`, `retrieved_verified`, `ambiguous_exact`,
`relevance_fallback`, `authentication_required`, `failed_retryable`, `not_found`,
or `failed_final`. Match type is `exact`, `relevance`, or `none`.

`selected_version_id` is nullable and, when present, names a version on
`selected_candidate_id`. It remains available after a selection is applied even
when retrieval later fails; a successful result repeats the same selected version.

Candidates require a nonempty `id`, `title`, and safe public HTTPS `source_url`.
When present, `relationship` is `title_match`, `version_of_title_match`,
`related_publication`, or `relevance_fallback`; `title_match_type` is `verbatim`,
`normalized`, `expanded`, or `different`. A candidate may contain a bounded
`versions` array. Each version requires a unique nonempty `id`; a present
`source_url` must be safe HTTPS. `candidate_review`, when present, contains
`id`/`candidate_id`/`version_id` triples: each field is nonempty, and the candidate
and version pair resolves to the item's candidate metadata.

The legacy validator intentionally permits candidate metadata beyond those
validated fields. Do not imply that candidate objects are closed or duplicated in
v2; v2 stores only opaque selected candidate IDs and work-owned version IDs.

`pending_action` is null or an object with a nonempty `type` and `recorded_at`,
plus optional `candidate_id`, `version_id`, and `comment`. The review server queues
only `select_candidate`, `accept_fallback`, `retry`, `retry_authenticated`,
`retry_public`, `skip`, and `stop_retrying`. The validator warns, rather than
fails, for an unknown future action type in a pre-v2 legacy manifest. Once v2 is
present, its closed projected request action still makes an unsupported type an
error. Candidate/version references must resolve when present.

`decision_history` is a bounded legacy array. The batch validator does not impose
one closed schema on every historical entry, except where a rule such as relevance
fallback acceptance needs specific fields.

## Discovery traces and success evidence

`artifact_discovery` and `route_metrics` may appear on an item and may also be
copied into its result for display. For `retrieved_verified`, the item-level
records are canonical and required; result-level copies do not replace them. An
artifact-discovery object requires:

- `method`: `registry_metadata`, `html_metadata`, `structured_data`,
  `embedded_document`, `download_link`, `repository_metadata`,
`collection_index`, `user_supplied`, or `other`;
- safe HTTPS `discovered_from` and `artifact_url`; and
- nonempty `evidence`.

`other` preserves an uncovered long-tail observation for review but is not an
eligible discovery method for `retrieved_verified`. Search snippets, search
indexes/caches, generated summaries, and third-party reconstructions cannot supply
the bytes or complete text of a successful local artifact.

After resolving a work/version with a verified strong identifier, record a
separate bounded identifier-driven OA/artifact-location pass in working evidence
and the applicable discovery route metrics. It does not count toward the
four-query/40-hit title-discovery ceiling. Run at most four location queries and
inspect at most 10 raw records or hits per query: broad OA/repository metadata by
identifier, canonical-source metadata, native web search for exact title plus an
artifact term, then—only if still needed—native web search for identifier plus the
artifact term. Do not combine title and identifier into a mandatory all-terms
query, substitute a scraped/feed endpoint for available native search, broaden to
topical relevance, or spend the budget on registries that repeat the same absence.
A structured artifact URL that later fails every applicable transfer rung does not
suppress the remaining web query. Nonresponsive unrelated hits do not prove
absence.
The single item-level `artifact_discovery` object remains the canonical declaration
for the artifact ultimately retrieved; do not invent extra manifest fields for the
discarded leads.

Each route metric requires `phase` (`discovery`, `retrieval`, or `verification`),
nonempty `method`, and nonempty `outcome`. Optional measured fields are
`access_mode`, safe HTTPS `url`, nonnegative `request_count`, `redirect_count`,
`bytes`, or `elapsed_ms`, and HTTP status 100–599. Record phases separately, never
estimate values, and do not count a `user_supplied` link as autonomous discovery.

A `retrieved_verified` item requires a `result` whose
`selected_candidate_id` matches the item selection. It also requires:

```text
format
verified_url
retrieval_url
local_path
verification_summary
provenance
```

`format` is `pdf` or `html`. `verified_url` matches the selected candidate source
URL, or the selected version source URL when `selected_version_id` is present.
`retrieval_url` matches `artifact_discovery.artifact_url`. Direct discovery uses
the actual safe HTTPS declaration source as `discovered_from`.
`registry_metadata`, `structured_data`, `embedded_document`, `download_link`,
`collection_index`, and `repository_metadata` may therefore declare a URL that
differs from the verified canonical work URL. This does not relax the selected
work/version identity, provenance, or artifact/retrieval URL checks. For
`html_metadata` and `user_supplied`, `discovered_from` remains the verified
canonical URL; `other` is not eligible for retrieved success.

The verification summary requires positive `bytes`, lowercase `sha256`,
`observed_title`, nonempty `verification_method`, `identity_evidence`, and
`full_text_evidence`, timezone-aware `verified_at`, and
`identity_verified`, `full_text_verified`, and `artifact_integrity_verified` all
true. PDF additionally requires positive `page_count`; HTML requires
`sanitized_inert_snapshot: true`. Provenance requires nonempty `method` and
`source_role`, where the role is `publisher`, `issuing_organization`,
`official_repository`, `official_collection`, `trusted_registry`,
`author_repository`, or `other_legitimate_source`.

An author upload or professional-organization archive may use the existing
`author_repository`, `issuing_organization`, or `other_legitimate_source` role as
the evidence supports. Verify account/domain control or uploader identity, work
identity, and completeness. A subscriber watermark alone does not make the
artifact ineligible. Download a plausible public copy into quarantine before the
final role/ranking decision; quarantine does not satisfy provenance or success.

Before a manual-download handoff, record concrete outcomes for each applicable
public transfer rung: `paper_finder_fetch.py download` for bounded credential-free
HTTPS transfer to quarantine, trusted managed-browser save/capture, and
`paper_finder_fetch.py sanitize-html` for a complete rendered-DOM inert HTML
capture. Use existing route metrics, access observations, attempts, and working
evidence; this contract adds no transfer-ladder collection. A client-specific
transfer failure is not proof that a publicly rendered artifact is unavailable.

Both public helper operations refuse an existing destination and expose no
overwrite mode. Every attempt uses a new deterministic collision-safe relative
quarantine path so prior evidence remains intact.

At least one verification route metric has `outcome: passed` and a measured byte
count equal to the local artifact. Any verification URL matches the verified or
retrieval source. The local artifact is a nonsymlink relative path under
`papers/` with portable components (no device names, alternate-stream colon,
control characters, or trailing dot/space); validation recomputes its size and
digest and applies the format rules in [retrieval-policy.md](retrieval-policy.md).

Exact success selects a title-family relationship, requires `verbatim`,
`normalized`, or `expanded` title evidence, and requires the requested title to be
an ordered normalized subsequence of the effective selected title. Relevance
success selects `relevance_fallback` and requires an applied decision-history
entry for `accept_fallback` that binds the selected candidate/version, has
`outcome: accepted`, and has timezone-aware `applied_at`.

`failed_retryable` and `failed_final` require a `failure` with nonempty `code` and
`message` plus a boolean `retryable` matching the status. A standalone
`sign_in_url` is rejected; use the verified selected source hostname.

## Bounded artifact validation

PDF success uses bounded `pdfinfo` and `pdftotext`, requires a positive declared
and independently observed page count, enough extractable text containing the
effective selected title, matching size and SHA-256, and a structurally valid
terminal cross-reference.

The implemented bounded terminal rule must accept the complete terminal/revision
chain, every cross-reference table or stream, and the referenced object offsets,
with no unexplained bytes outside the chain. Structure bytes and cumulative decoded
cross-reference entries have independent limits. Do not reject a PDF solely
because it uses a common valid xref stream or incremental update: it is eligible
when the implemented validator supports and accepts that complete bounded
structure. Unsupported, appended, forged, overlapping, cyclic, truncated,
malformed, or inconsistent structures fail closed. Encryption/scanning that
prevents sufficient title-bearing text and OCR-dependent files do not pass
automated validation; the MVP does not auto-ingest OCR output.

HTML success is a newly sanitized strict-UTF-8 document with exactly one doctype
and one `html`/`head`/`body`, exact UTF-8 meta first, and
`default-src 'none'; base-uri 'none'; form-action 'none'` as the second head
element. It stays within node, attribute, depth, text, and byte limits; contains no
active/remote content, comments, duplicate attributes, or external link targets;
and has enough body text containing the effective title.

An official complete abstract is sufficient only when the selected source is a
meeting abstract. An abstract page is not full text for a selected article.

## Actual v2 bridge

For manifests that contain `operations_v2`, that object is authoritative for the
operational entities it represents. The current bridge validates a limited overlap
with legacy items; it does not fully generate, overwrite, or synchronize the item
array.

The implemented checks are exactly:

1. validate the closed v2 state;
2. map legacy `review_state` to v2 `status`:
   `processing` → `active`, `review_ready` → `review`, `submitted` → `review`
   or `active`, and `done` → `done`;
3. require one v2 request per item and match it by `input_index`;
4. require `request.title == item.requested_title`;
5. require request `comment` and `selected_candidate_id` to equal the legacy item;
6. require request `selected_version_id` to equal item `selected_version_id`; for
   historical items without that field, fall back to `item.result.selected_version_id`
   or null when there is no result;
7. require request `pending_action` and `decision_history` to equal their closed v2
   projections from the legacy records: candidate/version IDs are retained, a
   decision comment falls back to the item comment, legacy `type` becomes v2
   `action`, a pending outcome becomes `queued`, and historical `accepted` becomes
   `succeeded`;
8. require compatible statuses:
   - legacy `pending`/`processing` → v2 `pending`;
   - `retrieved_verified` → `retrieved`;
   - the four attention statuses → `attention`;
   - `not_found`/`failed_final` → `failed` or `skipped`;
9. for `retrieved_verified`, compare the referenced v2 artifact's `format`,
   `verified_url`, `local_relpath`, `bytes`, and `sha256` with the legacy result;
   and
10. when the legacy result has `selected_version_id`, require the v2 artifact to
   use it.

The bridge does not compare or copy candidate objects, candidate-review options,
artifact-discovery evidence, route metrics, retrieval URL, detailed verification
summary, provenance, or other legacy-only metadata. Apart from initialization and
the review-server update described below, it validates rather than regenerates or
repairs either representation. The active Codex process must apply queued
decisions and update both representations atomically wherever their implemented
overlap requires agreement. Do not claim that item regeneration or full
bidirectional synchronization exists.

## Honest review queue

Open review only at `review_ready` with v2 `status: review`. Saving an item decision
records a legacy pending action against the current manifest revision and mirrors
the item comment plus the closed queued-action projection into the matching v2
request. It does not change the v2 selection, decision history, status, or
handoffs. **Submit queued actions to Codex** requires at least one pending action,
changes legacy `review_state` to `submitted`, and shuts down the short-lived
server. At that queued boundary v2 may remain `review`; it may be changed to
`active` while the agent applies the round. The button does not search, retry,
browse, download, ingest, create a handoff, or apply the decision.

The active Codex process consumes the complete submitted set, performs affected
work, updates legacy and v2 records, clears or archives pending actions, validates,
and reopens review. Every control must use queue language; the localhost page has
no retrieval backend.

The review server binds to `127.0.0.1`, uses an in-memory route token, rejects
non-loopback Host headers and stale or externally changed revisions, and stops
after a batch action.

## Completion invariant

The legacy **Finish batch** action first requires:

- no legacy pending action; and
- every item in `retrieved_verified`, `not_found`, or `failed_final`.

When v2 exists, completion sets its `status` to `done` and validates the exact
done-state invariant in [operations-v2.md](operations-v2.md): all handoffs closed,
requests and works terminal, no pending request action, no active attempt, no
pending provider prompt or next action, every resolved retry request backed by a
matching terminal attempt, no artifact left in candidate status, and consistent
verified-artifact and shared-work outcomes. Only then may the manifest set
`review_state: done` and `done: true`.

The v2 validator—not a separate requirement for a suppression per retry—defines
whether attempt history is terminal. Export requires a valid done manifest and no
unfinished v2 handoff. Reopening explicitly returns legacy review state and v2
status to review; completion otherwise remains terminal.
