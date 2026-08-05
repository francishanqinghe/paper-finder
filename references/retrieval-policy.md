# Retrieval Policy

## Interpret the target

- Treat “original” as a legitimate version of the requested item, not as one uniquely privileged file.
- Treat the requested title as identifying the primary bibliographic source.
- Distinguish that source and its versions from related publications about the same study, trial, or analysis.
- Group versions only when title, identifiers, authors, venue, dates, or documented lineage support the relationship. A shared study or trial alone is insufficient.
- Keep distinct works with the same title as separate candidates. Do not choose among them by recency alone.

## Use legitimate access

- Prefer an existing authenticated browser session that the user has authorized.
- If sign-in is required, independently verify the official HTTPS origin, show its full hostname, and let the user navigate there in the authorized browser.
- Never ask the user to provide credentials in chat. Never collect or store passwords, session tokens, cookies, or authentication codes.
- Fall back to public access when no authenticated session is available, the user declines to sign in, or authenticated retrieval fails.
- Do not bypass paywalls, CAPTCHAs, access controls, or provider restrictions.

## Resolve exact matches

- Search for an exact title match before using relevance matching.
- Classify every candidate by its relationship to the requested title:
  - `title_match`: the title matches exactly after normalization or harmless acronym, parenthetical, or subtitle expansion.
  - `version_of_title_match`: a legitimate manifestation or revision of the title-matched bibliographic source.
  - `related_publication`: a distinct publication about the same study, trial, or analysis with a materially different title or bibliographic identity.
  - `relevance_fallback`: a relevance-based candidate found only because no title match was found.
- Prefer an eligible `title_match` or `version_of_title_match` over a `related_publication`.
- Apply peer-review and recency priority only within the title-matched version family. Prefer a peer-reviewed version; if several eligible peer-reviewed versions remain, select the latest.
- Treat a title-family version as eligible only when it is legitimate, retrievable, verifiable, and matched to the requested bibliographic source.
- When no eligible peer-reviewed title-family version exists, apply this MVP reliability order within that family:
  1. meeting abstract
  2. preprint
  3. news report
  4. slide deck
  5. other
- Do not automatically replace a title-matched meeting abstract with a differently titled journal article. Surface that article as a related alternative.
- Queue a consolidated user decision when distinct works share the exact title, candidates tie under these rules, or a candidate's relationship is uncertain.
- Record the candidates considered and the reason for every automatic choice.

## Use relevance fallback

- Rank relevant candidates only after an exact match cannot be found.
- Label every relevance candidate and any staged artifact as a fallback.
- Show a prominent mismatch warning with the requested title, candidate title, and available evidence.
- Require consolidated user acceptance before treating a relevance fallback as the requested item.

## Discover artifact links

- Discover artifact URLs only after resolving the selected bibliographic source.
- Inspect authoritative identifier or registry metadata, standard HTML metadata such as citation-PDF fields or alternate PDF declarations, structured data, `iframe`/`embed`/`object` sources, explicit download links, and repository file metadata.
- Resolve relative URLs against the document that declares them. Retain the discovery method, declaring URL, resolved artifact URL, and the observed evidence.
- Accept only public HTTPS destinations. Resolve and check network addresses at request time and after every redirect; reject credentials, private or metadata-service addresses, internal hostnames, IP literals, and HTTPS downgrade.
- Use one of these provider-agnostic methods: `registry_metadata`, `html_metadata`, `structured_data`, `embedded_document`, `download_link`, `repository_metadata`, `collection_index`, `user_supplied`, or `other`.
- Never invent an artifact endpoint by rewriting, pattern-matching, or guessing a landing URL, path, suffix, or query.
- Prefer a verified single-item artifact from the publisher or issuing organization when accessible.
- Use an official collection as a fallback or amortized batch cache. Verify that its exact edition contains the complete selected source rather than a placeholder, deferral notice, citation, or truncated record.
- Record a supplied link as `user_supplied`; do not report it as autonomous discovery or include it in autonomous-discovery efficiency.
- Measure discovery, retrieval, and verification separately. Record only observed requests, redirects, bytes, elapsed time, status, and outcomes.

## Verify retrieval

- Require both a verified source URL and a verified local artifact before reporting successful retrieval.
- Preserve a stable canonical or source landing URL. A temporary signed download URL may be used only inside the authorized browser flow and must never be persisted in the manifest, logs, comments, or report.
- Confirm that the artifact is readable and has the claimed media type.
- Confirm from metadata or content that the artifact represents the selected work and version.
- Accept an official complete abstract HTML page or PDF when the selected source is itself a meeting abstract.
- Reject an abstract-only page as a substitute for a selected full article. Also reject error pages, supplements, unrelated files, and mislabeled downloads.
- Mark success only after both URL and artifact checks pass.

## Preserve iteration space

- Leave uncommon publication relationships, date semantics, ties, corrections, retractions, and source types unspecified in the MVP.
- Queue an unsupported or uncertain case for user review instead of inventing a rule.
- Record user decisions so later revisions can turn repeated decisions into explicit policy.
