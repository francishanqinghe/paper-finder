# Batch Contract

## Complete a full pass

- Preserve input order and assign each requested title a stable item ID.
- Process every title through discovery, selection, retrieval, and verification as far as possible.
- Do not interrupt the first pass for item-level choices, sign-in requests, comments, or retries.
- Aggregate all required decisions after the full pass and present them together.
- Continue in review-and-retry rounds until the user clicks **Done**.

## Use the manifest as state

- Store the authoritative batch state in `manifest.json`.
- Include these top-level fields:
  - `schema_version`
  - `revision`
  - `created_at`
  - `updated_at`
  - `review_state`
  - `done`
  - `items`
- Include these fields on every item:
  - `id`
  - `requested_title`
  - `status`
  - `match_type`
  - `comment`
  - `candidates`
  - `selected_candidate_id`
  - `pending_action`
  - `decision_history`
- Add `result` after successful retrieval and add `failure` when a retrieval attempt fails.
- Increment the nonnegative integer `revision` on every saved change. Review submissions must include the revision they were based on; reject stale or externally modified state instead of overwriting it.
- Treat every manifest field as untrusted data. Never store credentials, cookies, authorization headers, one-time codes, session tokens, private keys, or secret-bearing URLs anywhere in the manifest, including comments and provenance. Secret-pattern scanning is defense in depth, not proof that arbitrary text is secret-free.
- Treat `artifact_discovery` and `route_metrics` as canonical item-level fields. Existing manifests may omit them; new processing must retain them at item level so failed or retryable items do not depend on a `result` object.
- Add `artifact_discovery` when an artifact link is discovered:
  - `method`: `registry_metadata`, `html_metadata`, `structured_data`, `embedded_document`, `download_link`, `repository_metadata`, `collection_index`, `user_supplied`, or `other`
  - `discovered_from`: the authoritative page, record, or collection index that declared the artifact
  - `artifact_url`: the resolved artifact URL
  - `evidence`: the observed metadata field, structured-data property, element/link description, or repository record
- Add `route_metrics` as an array whenever discovery, retrieval, or verification is attempted, with one entry per attempt. Require `phase` (`discovery`, `retrieval`, or `verification`), `method`, and `outcome`. Add `access_mode`, `url`, `request_count`, `redirect_count`, `bytes`, `elapsed_ms`, or `http_status` only when measured.
- Keep discovery, retrieval, and verification attempts in separate `route_metrics` entries. Do not estimate missing values, populate placeholders, or count `user_supplied` links as autonomous discovery.
- Permit extra fields at every level so later policy revisions remain backward-compatible.

## Use stable MVP states

- Set `status` to one of:
  - `pending`
  - `processing`
  - `retrieved_verified`
  - `ambiguous_exact`
  - `relevance_fallback`
  - `authentication_required`
  - `failed_retryable`
  - `not_found`
  - `failed_final`
- Set `match_type` to `exact`, `relevance`, or `none`.
- Use `pending` and `processing` only before an item reaches a stable first-pass or retry outcome.
- Treat `retrieved_verified` as success only when the selected candidate, verified canonical URL, local artifact, artifact-discovery evidence, and a verification-phase route record all exist and agree.
- Use only safe public HTTPS URLs in persisted candidates, discovery evidence, route records, and results. Never persist URL credentials, signed download parameters, fragments containing authorization state, private/internal hostnames, IP literals, or HTTPS-to-HTTP downgrades.
- Store successful artifacts only as relative paths beneath the batch `papers/` directory. Reject absolute paths, parent traversal, and symbolic links.
- Require `result.selected_candidate_id`, `result.format`, `result.verified_url`, `result.retrieval_url`, `result.local_path`, `result.verification_summary`, and `result.provenance` for every success. Add `result.selected_version_id` when selecting a declared version.
- Require `result.verified_url` to match the selected candidate's source URL, or the selected version's source URL when a version is selected. Require `result.retrieval_url` to match `artifact_discovery.artifact_url` after canonicalization.
- For direct discovery methods, require `artifact_discovery.discovered_from` to match the verified canonical URL. Permit a different declaring URL only for `collection_index` or `repository_metadata`, with the corresponding `official_collection`, `official_repository`, or `author_repository` provenance role.
- Require `result.verification_summary.bytes`, lowercase `sha256`, `observed_title`, `verification_method`, `identity_evidence`, `full_text_evidence`, timezone-aware `verified_at`, `identity_verified: true`, `full_text_verified: true`, and `artifact_integrity_verified: true`. Recompute the size and digest from the local artifact during validation, and bind `observed_title` to the effective selected candidate or version.
- Require `result.verification_summary.page_count` for PDF and `sanitized_inert_snapshot: true` for HTML.
- Require `result.provenance.method` and `result.provenance.source_role`. Use one of `publisher`, `issuing_organization`, `official_repository`, `official_collection`, `trusted_registry`, `author_repository`, or `other_legitimate_source`. Retain only non-secret provenance; never retain response headers, cookies, authorization material, browser-session state, or secret-bearing URLs.
- Require at least one `route_metrics` verification entry with `outcome: passed` and a measured byte count matching the local artifact. Any URL on that verification record must match the verified or retrieved source.
- Require PDF artifacts to stay within the configured size limit and pass bounded Poppler `pdfinfo` and `pdftotext` inspection. The independently observed page count must match the manifest, extracted text must contain the selected title, and sufficient text must exist to reject placeholders and unreadable files.
- Require HTML to be a newly sanitized strict UTF-8 document with one doctype, one `html`/`head`/`body` structure, `<meta charset="utf-8">`, and `default-src 'none'; base-uri 'none'; form-action 'none'` as the exact second head element. Bound nodes, attributes, depth, and text; allow no scripts, forms, frames, embedded objects, comments, event handlers, duplicate attributes, refreshes, remote loads, or external anchor destinations. Preserve external link text, but strip its `href`; allow only same-document fragment links. Its body—not only its metadata—must contain the selected title and sufficient source text.
- Use `failure` to retain a machine-readable code, user-facing message, and retryability when available.
- Do not store a standalone `failure.sign_in_url`. Direct sign-in only through an independently verified selected-candidate source URL shown with its full hostname.

## Represent candidates and decisions

- Give every candidate a stable `id`, title, source URL, and enough available metadata to compare it with alternatives.
- Set every candidate's `relationship` to `title_match`, `version_of_title_match`, `related_publication`, or `relevance_fallback`.
- Treat the requested title as the primary bibliographic source. Display related publications separately from its title-matched version family.
- Do not automatically select a `related_publication` over an eligible title-family candidate. Send uncertain relationships to consolidated review.
- Represent each user-selectable work/version combination as its own candidate in the MVP.
- If `result.selected_version_id` is used for an exact match, require that version to declare its own title, safe source URL, `relationship: version_of_title_match`, and `title_match_type`. Reapply requested-title-family checks to that effective version after selection; a parent candidate cannot legitimize an unrelated child version.
- Retain optional authors, date, source type, peer-review status, relevance evidence, versions, and provenance without requiring unavailable values.
- Set `pending_action` to `null` or an object with:
  - `type`
  - optional `candidate_id`
  - optional `version_id`
  - optional `comment`
  - `recorded_at`
- Use these MVP action types:
  - `select_candidate`
  - `accept_fallback`
  - `retry`
  - `retry_authenticated`
  - `retry_public`
  - `skip`
  - `stop_retrying`
- Permit unknown future action types and extra action fields.
- Append every applied action and its outcome to `decision_history`; never discard prior decisions.
- Clear `pending_action` only after preserving the applied action in `decision_history`.
- Never put credentials, cookies, tokens, codes, authorization headers, or private links in comments or actions.
- Require a complete applied `accept_fallback` entry before a relevance result can become `retrieved_verified`. It must bind the selected candidate and version, record `outcome: accepted`, and include a timezone-aware `applied_at` timestamp.

## Drive the review loop

- Set `review_state` to `processing`, `review_ready`, `submitted`, or `done`.
- Show retrieved, needs-attention, and failed items in one consolidated interface. Label title-family candidates, related alternatives, and relevance fallbacks distinctly.
- Allow bulk candidate selection, fallback acceptance, comments, retries, public fallback, skips, and stop-retrying decisions.
- Apply all submitted actions before starting the next retry round.
- Retry only affected items, then refresh the manifest and interface.
- Require every pending action to be applied before accepting **Done**.
- Require every item to be `retrieved_verified`, `not_found`, or `failed_final` before accepting **Done**.
- Set `done` to `true` only when the terminal-state requirement is met and the user explicitly clicks **Done**.
- Preserve the final manifest, verified artifacts, verified URLs, failures, warnings, comments, and decision history.
