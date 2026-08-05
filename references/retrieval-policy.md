# Retrieval Policy

This file defines provider-neutral discovery, selection, access, and artifact
verification behavior. The implemented operational schema and retry API are in
[operations-v2.md](operations-v2.md); legacy manifest evidence and bridge rules
are in [batch-contract.md](batch-contract.md).

## Contents

- [Interpret the target](#interpret-the-target)
- [Resolve exact matches before relevance](#resolve-exact-matches-before-relevance)
- [Use legitimate access](#use-legitimate-access)
- [Discover artifact links from evidence](#discover-artifact-links-from-evidence)
- [Require both outputs](#require-both-outputs)
- [Apply the implemented bounded PDF validator](#apply-the-implemented-bounded-pdf-validator)
- [Require inert HTML](#require-inert-html)
- [Preserve review space](#preserve-review-space)

## Interpret the target

- Treat “original” as a legitimate version of the requested item, not as one
  uniquely privileged file.
- Treat the requested title as identifying the primary bibliographic source.
  Distinguish it and its versions from differently titled publications about the
  same study, trial, dataset, or analysis.
- Group versions only when identifiers, title, authors, venue, dates, or
  independently documented lineage support the relationship. A shared study,
  author, provider, topic, or filename is insufficient.
- Preserve distinct works that share a title. Use supplied author, year, venue, or
  identifier hints to resolve them; otherwise queue consolidated selection.

## Resolve exact matches before relevance

Before selecting automatically, complete a hard-bounded exact-title pass for each
unique requested title. Run no more than these four queries and inspect no more
than 40 raw returned rows or hits in total:

1. pass the preserved title as the title query to a structured bibliographic
   registry or index; inspect at most its first 10 raw rows;
2. on that route, run one title query normalized only for Unicode, case,
   whitespace, and punctuation/dashes when it differs; inspect at most 10 raw rows;
3. query an independent source-oriented web, catalog, or repository route with
   the preserved exact title; inspect at most its first 10 raw hits; and
4. on that route, run the same one normalized-title query when distinct; inspect at
   most 10 raw hits.

The ceiling counts raw rows before de-duplication. Do not request another page or
scan extra rows to replace duplicates. De-duplicate candidate records first by an
equal strong identifier, otherwise by an equal canonical landing URL, otherwise by
the tuple of normalized candidate title, venue/source, and publication date.
Preserve both records when those keys or lineage conflict. If the normalized query
equals the preserved query, omit it without substituting a broader query.

A route/query is exhausted only when it returns fewer than 10 rows, the 10-row
ceiling is inspected, or a concrete failure is recorded. Route classes are
independent only when neither is a landing page, redirect, or alternate endpoint
of the other and they do not expose the same upstream result feed. Looking up an
already discovered DOI or identifier verifies a candidate; it does not satisfy a
title-query discovery route. Record queries/failures in working evidence, do not
stop after the first match, and do not broaden to topical relevance until both
route classes are complete. For large batches, process at most 100 unique titles
per chunk with bounded concurrency and complete every chunk before review.

Classify each candidate as:

- `title_match`: the same title after allowed normalization or expansion;
- `version_of_title_match`: a legitimate manifestation or revision of the
  title-matched work;
- `related_publication`: a distinct bibliographic work about the same subject; or
- `relevance_fallback`: a relevance result considered only because no title-family
  match was found.

Prefer an eligible title-family candidate over a related publication. Apply
peer-review and recency only inside the title-family: prefer an eligible
peer-reviewed full paper, article, or proceedings paper and, among those versions,
the latest. A meeting abstract does not enter that tier merely because conference
acceptance was reviewed. When no peer-reviewed full paper is eligible, use this
reliability order: meeting abstract, preprint, news report, slide deck, other.
Within the same source type, prefer an official publisher/organizer version, then
an institutional repository version, then an author-hosted or other legitimate
copy. If provenance authority is uncertain, queue selection.

Only for candidates still tied under peer review, recency, source reliability,
and provenance authority, apply title fidelity:

1. `verbatim` differs only by Unicode canonical equivalence and
   leading/trailing/repeated whitespace;
2. `normalized` has the same word/token sequence after Unicode, case, whitespace,
   and punctuation/dash normalization, with no token added or removed;
3. prefix-preserving `expanded` begins with the full normalized requested title
   after only parenthetical acronym/initialism insertions are removed from the
   candidate title string, with any remainder limited to a trailing subtitle; and
4. any other allowed `expanded` match.

An abstract number, poster/session/conference/trial label, or other added prefix is
substantive and therefore falls in the fourth tier. The two expanded tiers do not
add schema enum values. Registry relevance scores are discovery hints, not
title-fidelity scores. If candidates remain tied or classification is uncertain,
queue selection rather than applying a finer ad hoc score.

Do not replace a title-matched meeting abstract with a differently titled journal
article merely because the latter is newer or peer reviewed. Display it as a
related alternative. Queue a decision when distinct exact-title works remain,
candidates tie, or lineage is uncertain. Record candidates considered and the
reason for every automatic choice in the legacy item metadata.

Search by relevance only after exact-title discovery is exhausted. Show the
requested and candidate titles plus mismatch evidence prominently. A relevance
artifact cannot count as success until the legacy decision history contains the
complete applied `accept_fallback` record required by the batch contract and the
corresponding v2 request decision/handoff state is applied where used.

## Use legitimate access

- Prefer an existing user-authorized browser session, but keep authenticated work
  inside that browser.
- Independently verify an official HTTPS origin using identifiers, trusted
  registries, and organization ownership before sign-in. Before public download,
  establish that the origin or uploader is a plausible source for the resolved
  work; complete fine-grained provenance adjudication on quarantined bytes. Never
  trust a content-supplied sign-in link by itself.
- Never ask for, copy, persist, or forward passwords, one-time codes, cookies,
  authorization headers, session/browser state, signed URLs, or credentials.
- Do not bypass paywalls, CAPTCHAs, access controls, or provider restrictions.
- Treat authentication, human challenge, entitlement, capture, and download as
  separate typed observations. Signed in does not prove entitlement, and a
  visible PDF does not prove a direct download exists.
- Group access only by exact verified origin, access mode, and generation. Probe
  and process all compatible works together.
- Use v2 `access_policy: prompt_if_needed` to permit one consolidated sign-in
  handoff when an authenticated group is observed signed out and needs sign-in.
  Planning such a route does not itself set a prompt pending.
- Use `access_policy: public_only` to forbid authenticated groups, authenticated
  attempts, and sign-in handoffs. Continue legitimate public publisher,
  repository, author, registry, and collection routes. A public human challenge
  remains a distinct typed condition; `public_only` is not a CAPTCHA bypass.
- After observed missing entitlement, close that authenticated group/route for the
  work/version under the implemented retry circuit. An
  `entitlement_changed` revision does not itself reopen it. Continue a different
  legitimate route, a new access generation, or public access.

Persist only the non-secret access fields and evidence codes allowed by the closed
v2 schema. Never persist or fingerprint browser/profile identifiers, session URLs,
raw headers, signed URLs, or hashes derived from secrets.

## Discover artifact links from evidence

Resolve the selected bibliographic source before seeking its file. Observe the
artifact declaration in identifier/registry metadata, standard HTML metadata,
structured data, an embedded document, an explicit download link, repository
metadata, or an official collection index. Resolve relative URLs against the page
that declares them and record the method, declaring URL, artifact URL, and observed
evidence in the legacy `artifact_discovery` record.

For a selected work/version with a verified DOI, PMID, or other strong identifier,
run a distinct identifier-driven OA/artifact-location pass after work resolution.
It neither satisfies nor extends exact-title discovery. Run no more than four
location queries and inspect no more than the first 10 raw records or hits from
each, in this order:

1. broad OA/repository metadata by the strongest verified identifier;
2. canonical-source metadata;
3. the active environment's native general-web search for the preserved exact
   title plus only a literal artifact term such as `PDF` or `full text`; and
4. only if no plausible copy survives, native general-web search for the strongest
   verified identifier plus the artifact term.

Do not require title and identifier in one all-terms query, and do not substitute a
scraped result page or RSS/syndication feed when native search is available. A URL
from structured metadata that later fails direct transfer, browser save/capture,
and applicable HTML capture does not suppress the remaining web query or prove
absence. If none of the inspected hits contains the identifier or a distinctive
exact title phrase, record the response as a nonresponsive-query failure rather
than an exhausted route. These queries locate copies; they must not broaden to
topical relevance, and every lead still requires work-identity, uploader,
completeness, and provenance verification. De-duplicate normalized artifact and
landing URLs. Record each query, its bound, and its concrete outcome even when no
location is returned.

Never invent an endpoint by rewriting a landing URL, guessing a suffix, or copying
a pattern from another item. Prefer a single-item publisher or issuing-organization
artifact when accessible. Use an official collection only when its exact edition
contains the complete selected source rather than a citation, placeholder,
deferral, or truncated record.

Search-engine snippets, indexes, caches, generated summaries, and third-party
reconstructions are discovery leads only. Do not copy their text into a local
artifact or treat it as full-source evidence. Artifact content must be captured
from the verified source itself or a legitimate complete copy. Publisher and
issuing-organization copies, institutional repositories, verified author uploads,
and professional-organization archives may all be legitimate. For an author upload
or organization archive, verify control of the account/domain or documented
uploader identity, bind the file to the resolved work, and verify completeness. A
subscriber watermark alone does not disqualify a copy; evaluate uploader authority,
identity, completeness, and any actual access restriction instead. If no complete
content survives the transfer ladder, record the outcomes and queue review instead
of constructing a substitute snapshot.

Accept only public HTTPS target URLs. Reject credentials, signed or secret-bearing
URLs, IP-literal targets, loopback, private, link-local, internal, and
metadata-service targets. Revalidate every redirect and reject HTTPS downgrade.
For a direct transport, resolve and validate target addresses at request time and
connect the socket to one of those exact vetted addresses without a second hostname
lookup. Treat a configured trusted managed proxy as an environment trust boundary,
but reject proxy URLs containing userinfo, query, fragment, or non-root path. Such
a transport may internally expose synthetic proxy/egress addresses; treat them only
as transport internals while continuing to validate the original target URL and
every redirect through that managed transport. Never persist those internal
addresses, reinterpret them as target ownership, or whitelist them for a different
transport. Bound requests, redirects, elapsed time, bytes, concurrency, and disk
use.

Record a supplied link as `user_supplied`; do not report it as autonomous
discovery. Keep discovery, retrieval, and verification route metrics separate and
record only measured values. V2 attempts coordinate route/access/retry context but
do not contain legacy artifact-discovery or metric records.

The legacy `other` discovery method is review-only for uncovered long-tail cases;
it cannot establish a `retrieved_verified` result in the MVP.

## Require both outputs

Success requires both a stable canonical URL from a legitimate source and a local
verified full-text artifact. Preserve a safe retrieval URL separately in the
legacy result when it differs. A URL-only result, artifact-only result, login or
challenge page, citation, supplement, correction, or unrelated file is not
success unless that source type was intentionally selected.

Use a legitimate PDF when available; otherwise save a newly sanitized inert HTML
snapshot of the complete selected source. An official complete abstract HTML page
or PDF is sufficient when the selected source is itself a meeting abstract. An
abstract page is not full text for a selected article.

For each plausible public artifact, use this transfer ladder before requesting
human action:

1. use `scripts/paper_finder_fetch.py download` for a bounded credential-free HTTPS
   transfer of an evidence-declared URL into a new collision-safe batch-quarantine
   path;
2. if the artifact renders through a trusted managed browser but the first transfer
   fails, use that browser's bounded save/capture path;
3. when no PDF can be transferred, capture the complete rendered source body and
   pass it through `paper_finder_fetch.py sanitize-html` to create a newly
   sanitized inert HTML artifact; and
4. only after every applicable public rung records a concrete failure, create one
   consolidated manual-download or access handoff.

The transfer and HTML-sanitization helpers refuse existing destinations and have
no overwrite mode. Preserve prior quarantine evidence and choose a new
deterministic relative path for every attempt.

Do not infer that public access is unavailable merely because one client cannot
transfer an artifact rendered by another. Download plausible public copies into
quarantine before fine provenance ranking. Quarantine is not acceptance; verify
identity, completeness, provenance, and integrity before installation under
`papers/`.

Verify the selected identity using title plus available identifiers, authors,
venue, date, and provenance. Verify source ownership independently and bind one
artifact to one v2 work/version before sharing it among requests that resolve to
that same work.

## Apply the implemented bounded PDF validator

Treat PDFs as untrusted bytes and fail closed. Automated verification requires all
of the following under fixed size, time, memory, file-descriptor, and parser-output
limits:

1. recognizable PDF content rather than HTML, login, or challenge content;
2. size of at least 1 KiB and no more than the configured 200 MiB limit;
3. a complete terminal/revision chain in a structure supported by the implemented
   bounded validator, with no bytes outside that chain;
4. internally consistent cross-reference tables or streams and object offsets for
   every accepted revision;
5. independent cumulative decoded-entry and structure-byte budgets, with
   conservative rejection of appended, forged, overlapping, cyclic, truncated, or
   resource-exhausting structures;
6. bounded Poppler `pdfinfo` and `pdftotext` success;
7. a positive independently observed page count matching the legacy declaration;
8. sufficient extracted text containing the effective selected title; and
9. recomputed size and SHA-256 matching both legacy verification evidence and the
   synchronized v2 artifact record.

Do not reject a PDF solely because it uses a common valid xref stream or incremental
update. It is eligible only when the current implemented validator accepts the
complete bounded revision chain; an unsupported structure still fails closed.
Appended payloads, malformed or inconsistent xref/body structures, parser failures,
insufficient text, and title mismatch do not pass. Encrypted, scanned, image-only,
or OCR-dependent PDFs will not pass when bounded parsing and title-bearing text are
absent. The MVP does not auto-ingest OCR output. Preserve failed quarantined bytes
for the consolidated review or manual flow without marking success.

A `.pdf` suffix, MIME label, browser filename, or user-supplied file is only a
hint. Manual files cannot establish canonical legitimacy by themselves.

## Require inert HTML

An HTML artifact is a new strict-UTF-8 document with exactly one doctype and one
`html`/`head`/`body`. Its first head element is exactly
`<meta charset="utf-8">`; its second contains exactly
`default-src 'none'; base-uri 'none'; form-action 'none'`.

Bound bytes, nodes, attributes, nesting, and text. Remove scripts, forms, frames,
embedded objects, comments, event handlers, duplicate attributes, refreshes,
remote loads, and external anchor destinations. Preserve external link text
without its `href`; allow same-document fragments only. The body—not merely
metadata—contains the effective title and enough source text for the selected
source type. Reject error, access, citation-only, and truncated pages.

## Preserve review space

Do not invent provider-specific exceptions for corrections, retractions, uncommon
version relationships, date semantics, ties, encrypted/scanned documents, or
unsupported source types. Do not escalate merely because one transfer route failed
or a watermark is present. Exhaust the bounded provider-neutral location and
transfer routes, preserve the evidence, and then queue one consolidated decision.
Formalize a repeated case only after the provider-neutral contract and portable
tests support it.
