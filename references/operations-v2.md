# Operational State v2

New root-schema-2 batch manifests embed a closed schema-v2 operational object at
`manifest.json.operations_v2`. Historical root-schema-1 manifests may also embed
it; without it they are validation-only until migrated. The object coordinates
duplicate requests, resolved works, artifacts, attempts, exact-origin access
groups, and human handoffs. It is not a network worker, browser controller,
persistence layer, file ingester, or copy of the legacy item schema.

`scripts/paper_finder_state.py` is the executable contract. The field sets and
enums below match that module exactly. Unknown or missing fields are validation
errors in every v2 record.

## Contents

- [Root schema](#root-schema)
- [Request records](#request-records)
- [Work and version identity](#work-and-version-identity)
- [Artifact records](#artifact-records)
- [Access groups and typed evidence](#access-groups-and-typed-evidence)
- [Attempt and suppression records](#attempt-and-suppression-records)
- [Handoff records and lifecycle](#handoff-records-and-lifecycle)
- [Done-state invariant](#done-state-invariant)
- [Public API](#public-api)

## Root schema

The v2 object has exactly:

| Field | Implemented value |
| --- | --- |
| `schema_version` | integer `2` |
| `status` | `active`, `review`, or `done` |
| `access_policy` | `prompt_if_needed` or `public_only` |
| `requests` | request records |
| `works` | work records |
| `artifacts` | artifact records |
| `attempts` | attempt records, including suppression records |
| `access_groups` | exact-origin access records |
| `handoffs` | human-handoff records |

There are no top-level `versions`, `evidence_revisions`, or `suppressions`
collections. Versions are bounded IDs in `work.version_ids`; typed evidence is
stored on access groups and copied into attempts; a suppression is a completed
attempt.

All entity IDs and version IDs are bounded, nonempty, and globally unique. Foreign
keys must resolve. The validator bounds collection sizes and the entire JSON tree,
requires normalized safe paths and origins, and rejects secret/session/header
material and secret-bearing URLs throughout the state.

## Request records

A request has exactly:

```text
id
input_index
title
work_id
artifact_id
comment
selected_candidate_id
selected_version_id
pending_action
decision_history
status
```

- `input_index` is a unique nonnegative integer and `title` is the preserved,
  trimmed input title.
- `work_id` always references a work.
- `artifact_id`, `selected_candidate_id`, `selected_version_id`, and
  `pending_action` are nullable.
- `selected_version_id`, when present, belongs to `work_id` and requires a
  `selected_candidate_id`. Candidate IDs are bounded opaque IDs; v2 does not store
  candidate metadata.
- `comment` is a bounded string and `decision_history` is a bounded array.
- `status` is `pending`, `retrieved`, `attention`, `failed`, or `skipped`.

`pending_action` and each decision-history entry use the same closed schema:

```text
action
candidate_id
version_id
comment
outcome
```

Action is `select_candidate`, `accept_fallback`, `retry`,
`retry_authenticated`, `retry_public`, `skip`, or `stop_retrying`. Outcome is
`queued`, `applied`, `succeeded`, `failed`, or `cancelled`. A pending action must
have `outcome: queued`; history cannot retain `queued`. Candidate selection and
fallback acceptance require `candidate_id`; other actions forbid it. A version ID
is optional but, when present, requires a candidate and must belong to the
request's work.

A retrieved request must reference a verified artifact on the same work and, when
selected, the same version. Other request statuses must have `artifact_id: null`.
The request's work must also be `retrieved`.

The module validates current snapshots, not a persisted request-transition log.
Callers normally move `pending` through `attention` or retrieval work to one of
`retrieved`, `failed`, or `skipped`; only the current enum and cross-record
invariants are enforced.

## Work and version identity

A work has exactly:

```text
id
canonical_title
identity_keys
version_ids
status
merge_basis
```

`status` is `search_pending`, `selected`, `retrieved`, `attention`, or `failed`.
`merge_basis` is `provisional`, `strong_identifier`, or `documented_lineage`.
`version_ids` is a nonempty bounded array of unique IDs; there are no version
objects in v2.

Each identity key has exactly `kind` and `value`. Supported kinds are `doi`,
`pmid`, `pmcid`, `arxiv`, and `isbn`; values must be stored in the canonical form
returned by `normalize_identity_key`. An arXiv trailing `vN` is stripped because
manifestation identity belongs in `version_ids`. A normalized identity key cannot
belong to two works.

`new_state` creates one provisional work and version ID for every request, even
for byte-identical titles. `bind_work_identity` can automatically coalesce only
untouched `search_pending` works whose normalized canonical titles agree. It
refuses a merge after access planning, handoffs, attempts, artifacts, selections,
pending actions, history, or other request progress. A successful merge combines
identity keys and version IDs, rebinds requests, and sets
`merge_basis: strong_identifier`.

Normalized title agreement is usable only when normalization produces nonempty
searchable tokens for every affected title. Punctuation-, symbol-, or emoji-only
titles remain provisional and require review rather than automatic coalescing.

When multiple requests share a work, validation requires either:

- `strong_identifier` plus at least one identity key, with every normalized
  request title equal to the normalized canonical title; or
- `documented_lineage` plus identical normalized request titles.

A provisional work cannot own multiple requests. A retrieved work requires at
least one verified artifact. In a done state, every request bound to that work must
be retrieved and must reference a matching verified artifact; a failed work cannot
have a retrieved request.

## Artifact records

An artifact has exactly:

```text
id
work_id
version_id
provider_origin
format
verified_url
local_relpath
bytes
sha256
status
```

`format` is `pdf`, `html`, or `other`; `status` is `candidate`, `verified`, or
`rejected`. The work/version binding must agree. `provider_origin` is the exact
canonical ASCII-host public HTTPS origin, and a non-null `verified_url` must be a stable safe
HTTPS URL on that origin.

For a verified artifact, format is only `pdf` or `html`; URL, safe relative path,
positive byte count, and lowercase SHA-256 are all required. Its path begins with
`papers/`. Every path component is portable: no control characters, NTFS alternate
stream colon, trailing dot/space, or Windows device basename. Paths and digests
are unique across artifact records. V2 deliberately
does not contain retrieval URL, page count, detailed verification evidence,
provenance subrecords, discovery evidence, or route metrics; those remain in the
validated legacy item/result representation.

## Access groups and typed evidence

An access group has exactly:

```text
id
provider_origin
access_mode
access_generation
evidence_revision
evidence_codes
work_ids
prompt_status
authentication
challenge
entitlement
capture
download
next_action
```

Groups are unique by exact canonical origin, access mode, and generation. Their ID
is deterministic from that tuple. `work_ids` is nonempty, sorted, unique, and
fully referenced.

The implemented enums are:

- `access_mode`: `public`, `authenticated`;
- `prompt_status`: `not_needed`, `pending`, `acknowledged`, `declined`;
- `authentication`: `unknown`, `not_required`, `signed_out`, `signed_in`;
- `challenge`: `unknown`, `none`, `human_required`, `passed`;
- `entitlement`: `unknown`, `not_required`, `entitled`, `not_entitled`;
- `capture`: `unknown`, `direct`, `browser_save_required`, `unavailable`;
- `download`: `not_attempted`, `available`, `awaiting_user`, `completed`,
  `failed`;
- `next_action`: `probe`, `sign_in`, `complete_challenge`, `retry_public`,
  `manual_download`, `none`.

Public access uses generation `0`, `authentication: not_required`, and
`prompt_status: not_needed`. Authenticated access uses a positive generation.
`public_only` rejects authenticated groups and attempts and rejects sign-in
handoffs; it does not erase a public human-challenge state. Planning an
authenticated route under `prompt_if_needed` starts with
`prompt_status: not_needed`, `authentication: unknown`, and `next_action: probe`.
A prompt becomes pending only after an observed signed-out state sets
`next_action: sign_in`.

The validator keeps typed fields consistent:

- public access cannot request sign-in;
- a pending prompt must request sign-in;
- sign-in requires authenticated, signed-out state;
- signed-in state cannot retain a pending or declined prompt;
- declined access cannot request sign-in or challenge completion;
- signed-out, human-challenge, missing-entitlement, browser-save, and completed
  download states each permit only their corresponding safe next actions.

Typed evidence is implemented as `evidence_revision` plus `evidence_codes` on the
group. Codes are unique and drawn from:

```text
provider_probe
authentication_changed
challenge_changed
entitlement_changed
capture_changed
download_changed
user_preference_changed
new_route_available
```

`evidence_revision` is a nonnegative integer exactly equal to the number of codes.
Each code can therefore appear at most once in a group. Append a code only for the
material typed fact it names; comments, timestamps, filenames, and cosmetic URL
changes are not evidence. `plan_access_groups` initializes revision `0` with an
empty code list.

## Attempt and suppression records

An attempt has exactly:

```text
id
work_id
version_id
route_kind
provider_origin
access_mode
access_generation
evidence_revision
evidence_codes
retry_fingerprint
access_group_id
trigger
suppressed_by_attempt_id
status
outcome
```

Route kind is `registry`, `publisher_page`, `embedded_document`,
`direct_download`, `repository`, `collection_index`, or `other`. Attempt status is
`planned`, `running`, `completed`, or `cancelled`. Outcome is `retrieved`,
`no_result`, `access_blocked`, `transient_failure`, `invalid_artifact`,
`cancelled`, or `suppressed_unchanged`. Trigger is `initial`, `user_retry`,
`retry_public`, `retry_authenticated`, `human_download`, or `suppression`.

The attempt must match exactly one access group for work, origin, access mode, and
generation. Its evidence codes are a prefix of that group's current code list;
its revision equals its own code count and cannot exceed the group's revision.
`reserve_attempt` requires the requested revision to equal the group's current
revision and copies the full current code list into the new record.

The current-state rules are exact:

- `planned` and `running` have `outcome: null`;
- `completed` has a non-cancelled outcome;
- `cancelled` has `outcome: cancelled`;
- `retry_public` uses public access and `retry_authenticated` uses authenticated
  access;
- no two attempts with one fingerprint may be active; and
- `public_only` permits only public attempts.

The retry fingerprint is SHA-256 over canonical compact JSON containing, in this
order:

```text
[work_id, version_id, route_kind, provider_origin,
 access_mode, access_generation, evidence_revision]
```

It does not hash request IDs, evidence-code text, timestamps, comments, filenames,
metrics, or browser/session material. A changed exact route, access generation, or
current typed evidence revision creates a different fingerprint. Missing
entitlement is the one implemented route-level closure: an authenticated group
recording `not_entitled` cannot reserve provider work for that work/version/route
merely because its evidence revision advanced.

The first provider invocation in a context uses `initial` or `human_download`.
After one completed attempt, at most one unchanged retry is allowed, and it must
be explicitly triggered by `user_retry`, `retry_public`, or
`retry_authenticated`. No unchanged invocation follows a retrieved outcome, two
completed attempts, or an existing suppression. No provider invocation is
reserved for an authenticated group/route currently recording `not_entitled`.

A suppression is not a separate collection. `reserve_attempt` appends one attempt
with:

```text
trigger: suppression
status: completed
outcome: suppressed_unchanged
suppressed_by_attempt_id: <eligible original completed attempt>
```

All non-suppression attempts have `suppressed_by_attempt_id: null`. At most one
suppression exists per fingerprint, it points directly to an original completed
non-cancelled, non-suppression attempt, and it carries no fabricated provider
metrics. Normally the pointer targets the first completed attempt with the same
fingerprint. When an authenticated group newly records `not_entitled`, the pointer
may instead target the earlier completed attempt for the same work, version,
route, origin, mode, generation, and access group even though the new typed
evidence revision gives the suppression a different fingerprint. If no eligible
completed original exists—for example, an identical attempt is still active or
entitlement is known missing before any attempt—the API raises `RetryCircuitOpen`
instead of fabricating a suppression.

## Handoff records and lifecycle

A handoff has exactly:

```text
id
kind
request_ids
work_ids
access_group_ids
access_generation
version_ids
expected_filenames
status
resolution
```

Kind is `candidate_selection`, `fallback_acceptance`, `sign_in`,
`human_challenge`, `manual_download`, `retry_review`, or `failure_review`. Status
is `open`, `submitted`, `applied`, `resolved`, or `cancelled`. Resolution is one
of `selected`, `accepted`, `signed_in`, `declined`, `challenge_passed`,
`file_received`, `retry`, `retry_public`, `skip`, `stop`, or `cancelled`.

The implemented current-state coupling is:

- `open` has `resolution: null`;
- `submitted`, `applied`, and `resolved` require a non-cancelled resolution
  permitted for their kind;
- `cancelled` requires `resolution: cancelled`.

The intended lifecycle is `open` → `submitted` → `applied` → `resolved`, with
`cancelled` terminal from a nonterminal state. The schema stores no timestamps or
predecessor history, so `validate_state` checks the current status/resolution and
cross-record invariants; it cannot prove that callers persisted every predecessor.

Allowed non-cancelled resolutions by kind are exact:

| Kind | Resolutions |
| --- | --- |
| `candidate_selection` | `selected` |
| `fallback_acceptance` | `accepted` |
| `sign_in` | `signed_in`, `declined`, `retry_public` |
| `human_challenge` | `challenge_passed`, `retry_public` |
| `manual_download` | `file_received`, `retry_public`, `skip` |
| `retry_review`, `failure_review` | `retry`, `retry_public`, `skip`, `stop` |

Every handoff references at least one request, work, or access group. ID arrays are
sorted and unique. Request/work and version/work references must agree.

Sign-in and challenge handoffs reference exactly one access group, cover its whole
work scope, carry no version or filename hints, and match its generation. Active
sign-in state requires authenticated, signed-out, pending-or-acknowledged access
with `next_action: sign_in`; active challenge state requires `human_required` and
`next_action: complete_challenge`. Only one such active handoff exists per group
and generation.

A manual-download handoff references exactly one work/version. Only that kind may
carry safe basename hints in `expected_filenames`; when present they align
one-to-one with `version_ids`. Safe hints use the same portable component rule as
artifact paths. Only one manual-download handoff may be active for a work/version.

Candidate-selection and fallback handoffs reference exactly one request and work
and no access group. They carry at most one version. Applied/resolved state
requires a selected candidate on the request; when the handoff carries a version,
that version must equal the request's selected version. A resolved candidate
handoff requires no pending request action and requires a matching applied or
succeeded request decision in history for the same candidate and selected version.

A resolved `retry_review` or `failure_review` whose resolution is `retry` or
`retry_public` cannot be followed immediately by done state. For every referenced
work, a terminal attempt must match the handoff's work and, when supplied, its
access-group and version scope. `retry` requires a completed, non-cancelled
`user_retry`/`retry_authenticated` attempt; `retry_public` requires a completed,
non-cancelled `retry_public` attempt. A valid completed `suppressed_unchanged`
attempt also satisfies the rule when its direct original pointer is valid and in
scope; for `retry_public`, that suppression must use public access. A cancelled
attempt does not satisfy a resolved retry instruction; cancel or re-resolve the
handoff instead.

## Done-state invariant

When `status` is `done`, `validate_state` requires all of the following:

- every handoff is `resolved` or `cancelled`;
- every request is `retrieved`, `failed`, or `skipped` and has no pending action;
- every work is `retrieved` or `failed`;
- no attempt is `planned` or `running`;
- every resolved retry/failure handoff requesting `retry` or `retry_public` has a
  matching terminal attempt, as scoped above;
- no artifact remains in `candidate` status;
- no access prompt is `pending` and every access group has `next_action: none`;
- every request bound to a retrieved work is retrieved and references a matching
  verified artifact; and
- failed works have no retrieved requests.

The validator does not require a suppression for every failed retry request; it
validates any suppression record that exists and enforces the retry circuit on the
attempt history.

## Public API

The module exports exactly:

```text
RetryCircuitOpen
SCHEMA_VERSION
StateValidationError
assert_retry_allowed
assert_valid_state
bind_work_identity
canonical_provider_origin
new_state
normalize_identity_key
plan_access_groups
reserve_attempt
retry_fingerprint
validate_state
```

These functions are pure and return new state where mutation is required.
`reserve_attempt` is the atomic way to reserve work or append a suppression;
`assert_retry_allowed` only checks and returns the fingerprint. The caller remains
responsible for persistence, provider access, attempt completion, artifact bytes,
handoff updates, and synchronization with the limited legacy projection described
in [batch-contract.md](batch-contract.md). The batch review server itself mirrors
only a queued item's comment and pending-action projection into its v2 request; it
does not apply the action or create a handoff.
