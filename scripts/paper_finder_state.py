#!/usr/bin/env python3
"""Pure schema-v2 state primitives for paper-finder.

This module deliberately performs no network access, browser access, persistence,
or filesystem discovery.  It models durable, non-secret coordination state only.
Callers remain responsible for retrieval and for writing verified artifacts.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
import unicodedata
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import parse_qsl, urlparse, urlunparse


SCHEMA_VERSION = 2

STATE_STATUSES = {"active", "review", "done"}
ACCESS_POLICIES = {"prompt_if_needed", "public_only"}
REQUEST_STATUSES = {"pending", "retrieved", "attention", "failed", "skipped"}
WORK_STATUSES = {"search_pending", "selected", "retrieved", "attention", "failed"}
WORK_MERGE_BASES = {"provisional", "strong_identifier", "documented_lineage"}
ARTIFACT_STATUSES = {"candidate", "verified", "rejected"}
ARTIFACT_FORMATS = {"pdf", "html", "other"}
ACCESS_MODES = {"public", "authenticated"}
PROMPT_STATUSES = {"not_needed", "pending", "acknowledged", "declined"}
AUTHENTICATION_STATES = {"unknown", "not_required", "signed_out", "signed_in"}
CHALLENGE_STATES = {"unknown", "none", "human_required", "passed"}
ENTITLEMENT_STATES = {"unknown", "not_required", "entitled", "not_entitled"}
CAPTURE_STATES = {"unknown", "direct", "browser_save_required", "unavailable"}
DOWNLOAD_STATES = {"not_attempted", "available", "awaiting_user", "completed", "failed"}
NEXT_ACTIONS = {
    "probe",
    "sign_in",
    "complete_challenge",
    "retry_public",
    "manual_download",
    "none",
}
ATTEMPT_STATUSES = {"planned", "running", "completed", "cancelled"}
ATTEMPT_OUTCOMES = {
    "retrieved",
    "no_result",
    "access_blocked",
    "transient_failure",
    "invalid_artifact",
    "cancelled",
    "suppressed_unchanged",
}
ATTEMPT_TRIGGERS = {
    "initial",
    "user_retry",
    "retry_public",
    "retry_authenticated",
    "human_download",
    "suppression",
}
ROUTE_KINDS = {
    "registry",
    "publisher_page",
    "embedded_document",
    "direct_download",
    "repository",
    "collection_index",
    "other",
}
IDENTITY_KINDS = {"doi", "pmid", "pmcid", "arxiv", "isbn"}
HANDOFF_KINDS = {
    "candidate_selection",
    "fallback_acceptance",
    "sign_in",
    "human_challenge",
    "manual_download",
    "retry_review",
    "failure_review",
}
HANDOFF_STATUSES = {"open", "submitted", "applied", "resolved", "cancelled"}
HANDOFF_RESOLUTIONS = {
    "selected",
    "accepted",
    "signed_in",
    "declined",
    "challenge_passed",
    "file_received",
    "retry",
    "retry_public",
    "skip",
    "stop",
    "cancelled",
}
HANDOFF_RESOLUTIONS_BY_KIND = {
    "candidate_selection": {"selected"},
    "fallback_acceptance": {"accepted"},
    "sign_in": {"signed_in", "declined", "retry_public"},
    "human_challenge": {"challenge_passed", "retry_public"},
    "manual_download": {"file_received", "retry_public", "skip"},
    "retry_review": {"retry", "retry_public", "skip", "stop"},
    "failure_review": {"retry", "retry_public", "skip", "stop"},
}
REQUEST_ACTIONS = {
    "select_candidate",
    "accept_fallback",
    "retry",
    "retry_authenticated",
    "retry_public",
    "skip",
    "stop_retrying",
}
DECISION_OUTCOMES = {"queued", "applied", "succeeded", "failed", "cancelled"}
ACCESS_EVIDENCE_CODES = {
    "provider_probe",
    "authentication_changed",
    "challenge_changed",
    "entitlement_changed",
    "capture_changed",
    "download_changed",
    "user_preference_changed",
    "new_route_available",
}

ROOT_FIELDS = {
    "schema_version",
    "status",
    "access_policy",
    "requests",
    "works",
    "artifacts",
    "attempts",
    "access_groups",
    "handoffs",
}
REQUEST_FIELDS = {
    "id",
    "input_index",
    "title",
    "work_id",
    "artifact_id",
    "comment",
    "selected_candidate_id",
    "selected_version_id",
    "pending_action",
    "decision_history",
    "status",
}
REQUEST_DECISION_FIELDS = {
    "action",
    "candidate_id",
    "version_id",
    "comment",
    "outcome",
}
WORK_FIELDS = {
    "id",
    "canonical_title",
    "identity_keys",
    "version_ids",
    "status",
    "merge_basis",
}
IDENTITY_FIELDS = {"kind", "value"}
ARTIFACT_FIELDS = {
    "id",
    "work_id",
    "version_id",
    "provider_origin",
    "format",
    "verified_url",
    "local_relpath",
    "bytes",
    "sha256",
    "status",
}
ATTEMPT_FIELDS = {
    "id",
    "work_id",
    "version_id",
    "route_kind",
    "provider_origin",
    "access_mode",
    "access_generation",
    "evidence_revision",
    "evidence_codes",
    "retry_fingerprint",
    "access_group_id",
    "trigger",
    "suppressed_by_attempt_id",
    "status",
    "outcome",
}
ACCESS_GROUP_FIELDS = {
    "id",
    "provider_origin",
    "access_mode",
    "access_generation",
    "evidence_revision",
    "evidence_codes",
    "work_ids",
    "prompt_status",
    "authentication",
    "challenge",
    "entitlement",
    "capture",
    "download",
    "next_action",
}
HANDOFF_FIELDS = {
    "id",
    "kind",
    "request_ids",
    "work_ids",
    "access_group_ids",
    "access_generation",
    "version_ids",
    "expected_filenames",
    "status",
    "resolution",
}
ACCESS_PLAN_FIELDS = {
    "work_id",
    "provider_origin",
    "access_mode",
    "access_generation",
}

MAX_REQUESTS = 5_000
MAX_WORKS = 5_000
MAX_ARTIFACTS = 10_000
MAX_ATTEMPTS = 50_000
MAX_ACCESS_GROUPS = 10_000
MAX_HANDOFFS = 10_000
MAX_TEXT_CHARACTERS = 10_000
MAX_URL_CHARACTERS = 8_192
MAX_ID_CHARACTERS = 200
MAX_STATE_NESTING_DEPTH = 100
MAX_STATE_SCAN_NODES = 250_000
MAX_MAPPING_FIELDS = 1_000
MAX_NESTED_COLLECTION = 50_000
MAX_ACCESS_PLANS = 50_000
MAX_IDENTITY_KEYS_PER_WORK = 100
MAX_VERSIONS_PER_WORK = 1_000
MAX_DECISION_HISTORY_PER_REQUEST = 10_000
MAX_REFERENCES_PER_HANDOFF = 5_000
MAX_MAPPING_KEY_CHARACTERS = 200
MAX_INTEGER_DECIMAL_DIGITS = 100
MAX_SECRET_FINDINGS = 100
MAX_STATE_ERRORS = 500
WINDOWS_RESERVED_PATH_BASENAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    "conin$",
    "conout$",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}

DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
LEGACY_NUMERIC_HOST = re.compile(
    r"(?i)(?:0x[0-9a-f]+|0[0-7]+|[0-9]+)"
    r"(?:\.(?:0x[0-9a-f]+|0[0-7]+|[0-9]+))*"
)
INTERNAL_HOSTS = {
    "localhost",
    "metadata.google.internal",
    "metadata.azure.internal",
}
INTERNAL_SUFFIXES = (
    ".localhost",
    ".local",
    ".localdomain",
    ".internal",
    ".intranet",
    ".lan",
    ".home",
    ".corp",
)
FORBIDDEN_FIELD_NAMES = {
    "authorization",
    "proxy_authorization",
    "cookie",
    "cookies",
    "set_cookie",
    "password",
    "passwd",
    "access_token",
    "refresh_token",
    "session_token",
    "session_id",
    "session",
    "session_state",
    "session_url",
    "sid",
    "jsessionid",
    "phpsessid",
    "asp_net_session_id",
    "browser_session_id",
    "browser_id",
    "browser_profile_id",
    "browser_state",
    "profile_id",
    "auth_token",
    "bearer",
    "jwt",
    "token",
    "id_token",
    "api_key",
    "apikey",
    "x_api_key",
    "client_secret",
    "private_key",
    "security_token",
    "csrf_token",
    "xsrf_token",
    "one_time_code",
    "otp",
    "authorization_code",
    "client_assertion",
    "saml_response",
    "credential",
    "credentials",
    "secret",
    "headers",
    "raw_headers",
    "response_headers",
    "request_headers",
    "page_evidence",
    "evidence",
    "page_html",
    "response_body",
    "raw_response",
}
FORBIDDEN_FIELD_SUFFIXES = tuple(
    "_" + field_name for field_name in sorted(FORBIDDEN_FIELD_NAMES)
)
SIGNED_URL_KEYS = {
    "code",
    "expires",
    "hdnea",
    "hdnts",
    "hmac",
    "key_pair_id",
    "policy",
    "sig",
    "signature",
    "token",
    "access_token",
    "auth_token",
    "session_token",
    "client_assertion",
    "x_amz_algorithm",
    "x_amz_credential",
    "x_amz_date",
    "x_amz_expires",
    "x_amz_security_token",
    "x_amz_signature",
    "x_amz_signedheaders",
    "x_goog_algorithm",
    "x_goog_credential",
    "x_goog_date",
    "x_goog_expires",
    "x_goog_signature",
    "x_goog_signedheaders",
}
SECRET_PATTERNS = (
    re.compile(r"(?im)^\s*(?:authorization|proxy-authorization|cookie|set-cookie)\s*:"),
    re.compile(
        r"(?i)\b(?:access[_-]?token|refresh[_-]?token|session[_-]?token|"
        r"auth[_-]?token|session[_-]?id|api[_-]?key|x-api-key|password|"
        r"one[_-]?time[_-]?code|otp|csrf[_-]?token|xsrf[_-]?token|"
        r"client[_-]?secret|authorization[_-]?code|credential|signature)"
        r"\s*[=:]\s*[^\s,;]{6,}"
    ),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+\-/=]{8,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"),
    re.compile(r"\b(?:gh[pousr]_|github_pat_|sk-)[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{12,}\b"),
)


class StateValidationError(ValueError):
    """Raised when schema-v2 state violates one or more invariants."""


class RetryCircuitOpen(ValueError):
    """Raised when unchanged completed attempts have exhausted the retry budget."""


class StateDiagnosticLimit(RuntimeError):
    def __init__(self, diagnostics: list[str]) -> None:
        super().__init__("state diagnostic limit reached")
        self.diagnostics = diagnostics


class CappedStateErrors(list[str]):
    def append(self, message: str) -> None:
        if len(self) < MAX_STATE_ERRORS:
            super().append(message)
            return
        super().append(
            f"additional state errors omitted after {MAX_STATE_ERRORS} diagnostics"
        )
        raise StateDiagnosticLimit(list(self))


def _normalized_key(value: Any) -> str:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value))
    return re.sub(r"[^a-z0-9]+", "_", text.casefold()).strip("_")


def _is_forbidden_field(value: Any) -> bool:
    key = _normalized_key(value)
    key_parts = key.split("_")
    scoped_browser_state = bool(
        key_parts
        and key_parts[-1] in {"id", "identifier", "state", "url"}
        and any(part in {"browser", "profile", "session"} for part in key_parts[:-1])
    )
    return (
        key in FORBIDDEN_FIELD_NAMES
        or key.endswith(FORBIDDEN_FIELD_SUFFIXES)
        or scoped_browser_state
        or key.startswith("x_amz_")
        or key.startswith("x_goog_")
        or key.endswith("_access_token")
        or key.endswith("_refresh_token")
        or key.endswith("_session_token")
        or key.endswith("_client_secret")
        or key.endswith("_private_key")
    )


def _has_sensitive_url_parameters(value: str) -> bool:
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"}:
        return False
    if parsed.username is not None or parsed.password is not None:
        return True
    parameter_sections = [parsed.query, parsed.fragment, parsed.params]
    for path_segment in parsed.path.split("/"):
        if ";" in path_segment:
            parameter_sections.append(path_segment.split(";", 1)[1])
    parameters: list[tuple[str, str]] = []
    try:
        for section in parameter_sections:
            # Python's query parser treats only '&' as a separator.  URL and
            # Java path parameters also commonly use ';', which must not hide
            # a credential-bearing pair after an innocuous first parameter.
            parameters.extend(
                parse_qsl(section.replace(";", "&"), keep_blank_values=True)
            )
    except ValueError:
        return True
    return any(
        parameter_value
        and (
            _normalized_key(key) in SIGNED_URL_KEYS
            or _is_forbidden_field(key)
        )
        for key, parameter_value in parameters
    )


def _secret_locations(value: Any, location: str = "$") -> list[str]:
    findings: list[str] = []
    stack: list[tuple[Any, str, int]] = [(value, location, 0)]
    scanned = 0
    while stack:
        current, current_location, depth = stack.pop()
        scanned += 1
        if scanned > MAX_STATE_SCAN_NODES:
            findings.append("$<state-scan-limit>")
            break
        if depth > MAX_STATE_NESTING_DEPTH:
            findings.append(current_location + "<nesting-limit>")
            continue
        if isinstance(current, Mapping):
            for key, child in current.items():
                # Mapping keys are untrusted too.  Never reflect them into a
                # diagnostic path; an unknown key can itself contain a secret.
                child_location = current_location + ".<field>"
                if isinstance(key, str) and (
                    _is_forbidden_field(key)
                    or any(pattern.search(key) for pattern in SECRET_PATTERNS)
                    or _has_sensitive_url_parameters(key)
                ):
                    findings.append(child_location)
                stack.append((child, child_location, depth + 1))
        elif isinstance(current, (list, tuple)):
            for index, child in enumerate(current):
                stack.append((child, f"{current_location}[{index}]", depth + 1))
        elif isinstance(current, str):
            if any(pattern.search(current) for pattern in SECRET_PATTERNS):
                findings.append(current_location)
            if _has_sensitive_url_parameters(current):
                findings.append(current_location)
        if len(findings) >= MAX_SECRET_FINDINGS:
            findings.append("$<additional-secret-locations>")
            break
    return sorted(set(findings))


def _state_tree_limit_errors(value: Any) -> list[str]:
    """Reject non-JSON container graphs before deeper schema traversal."""

    errors: list[str] = CappedStateErrors()
    stack: list[tuple[Any, str, int, bool]] = [(value, "$", 0, False)]
    active_containers: set[int] = set()
    scanned = 0
    while stack:
        current, location, depth, exiting = stack.pop()
        if exiting:
            active_containers.discard(id(current))
            continue
        scanned += 1
        if scanned > MAX_STATE_SCAN_NODES:
            errors.append(f"$ exceeds the {MAX_STATE_SCAN_NODES}-node state limit")
            break
        if depth > MAX_STATE_NESTING_DEPTH:
            errors.append(
                f"{location} exceeds the {MAX_STATE_NESTING_DEPTH}-level nesting limit"
            )
            continue
        if isinstance(current, Mapping):
            identity = id(current)
            if identity in active_containers:
                errors.append(location + " cycles a container")
                continue
            active_containers.add(identity)
            if len(current) > MAX_MAPPING_FIELDS:
                errors.append(
                    f"{location} exceeds the {MAX_MAPPING_FIELDS}-field mapping limit"
                )
                active_containers.discard(identity)
                continue
            stack.append((current, location, depth, True))
            for key, child in current.items():
                if not isinstance(key, str):
                    errors.append(location + " contains a non-string mapping key")
                    continue
                if len(key) > MAX_MAPPING_KEY_CHARACTERS:
                    errors.append(location + " contains an overlong mapping key")
                    continue
                if any(ord(character) < 32 or ord(character) == 127 for character in key):
                    errors.append(location + " contains an invalid mapping key")
                    continue
                stack.append(
                    (child, location + ".<field>", depth + 1, False)
                )
        elif isinstance(current, (list, tuple)):
            identity = id(current)
            if identity in active_containers:
                errors.append(location + " cycles a container")
                continue
            active_containers.add(identity)
            if len(current) > MAX_NESTED_COLLECTION:
                errors.append(
                    f"{location} exceeds the {MAX_NESTED_COLLECTION}-entry nested limit"
                )
                active_containers.discard(identity)
                continue
            stack.append((current, location, depth, True))
            for index, child in enumerate(current):
                stack.append((child, f"{location}[{index}]", depth + 1, False))
        elif (
            isinstance(current, int)
            and not isinstance(current, bool)
            and abs(current) >= 10**MAX_INTEGER_DECIMAL_DIGITS
        ):
            errors.append(location + " contains an overlarge integer")
    return errors


def canonical_provider_origin(value: Any) -> str:
    """Return a safe canonical HTTPS origin or raise ``ValueError``.

    Origins contain a scheme, public-hostname-shaped authority, and optional port.
    They never contain credentials, path components, query strings, or fragments.
    No DNS lookup is performed because this module never performs network access.
    """

    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > MAX_URL_CHARACTERS
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("provider origin must be a clean nonempty string")
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("provider origin is malformed") from exc
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("provider origin must be an exact credential-free HTTPS origin")
    if "%" in parsed.netloc:
        raise ValueError("provider origin must not contain percent escapes")
    try:
        parsed.netloc.encode("ascii")
        hostname = parsed.hostname.encode("ascii").decode("ascii").casefold()
    except UnicodeError as exc:
        # Python's legacy built-in IDNA codec does not match modern browser host
        # processing (for example, faß.de can collapse to fass.de). Until a
        # single IDNA2008/UTS46 implementation is part of the contract, reject
        # non-ASCII authorities so exact-origin grouping cannot be misbound.
        raise ValueError("provider origin hostname must be ASCII") from exc
    if hostname.endswith(".") or hostname in INTERNAL_HOSTS:
        raise ValueError("provider origin hostname is not public-hostname-shaped")
    if any(hostname.endswith(suffix) for suffix in INTERNAL_SUFFIXES):
        raise ValueError("provider origin hostname is not public-hostname-shaped")
    try:
        address = ipaddress.ip_address(hostname.split("%", 1)[0])
    except ValueError:
        address = None
    if address is not None or LEGACY_NUMERIC_HOST.fullmatch(hostname):
        raise ValueError("provider origin must use a hostname, not an IP literal")
    labels = hostname.split(".")
    if len(labels) < 2 or any(DNS_LABEL.fullmatch(label) is None for label in labels):
        raise ValueError("provider origin hostname is invalid")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("provider origin port is invalid")
    authority = hostname if port in (None, 443) else f"{hostname}:{port}"
    return urlunparse(("https", authority, "", "", "", ""))


def _safe_stable_url(value: Any) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or len(value) > MAX_URL_CHARACTERS
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("URL must be a clean string")
    if _secret_locations(value):
        raise ValueError("URL must not contain credentials or signed access parameters")
    try:
        parsed = urlparse(value)
    except ValueError as exc:
        raise ValueError("URL is malformed") from exc
    origin = canonical_provider_origin(
        urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    )
    if not parsed.path and not parsed.query:
        raise ValueError("verified URL must identify a resource, not only an origin")
    if parsed.fragment:
        raise ValueError("verified URL must not contain a fragment")
    return origin


def normalize_identity_key(kind: Any, value: Any) -> tuple[str, str]:
    if not _is_enum(kind, IDENTITY_KINDS):
        raise ValueError("identity kind is unsupported")
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > MAX_TEXT_CHARACTERS
    ):
        raise ValueError("identity value must be a clean nonempty string")
    if any(pattern.search(value) for pattern in SECRET_PATTERNS):
        raise ValueError("identity value contains secret-like material")
    normalized = value
    if kind == "doi":
        if re.match(r"(?i)^https?://", value):
            try:
                parsed_doi = urlparse(value)
            except ValueError as exc:
                raise ValueError("DOI URL is malformed") from exc
            if parsed_doi.username is not None or parsed_doi.password is not None:
                raise ValueError("DOI URL must not contain credentials")
            # Resolver URLs are durable identifiers only when the DOI is wholly
            # in the path. Query and fragment components are navigation or
            # tracking state and must never be normalized into persisted identity.
            if "?" in value or "#" in value:
                raise ValueError("DOI URL must not contain a query or fragment")
            if parsed_doi.netloc.casefold() not in {"doi.org", "dx.doi.org"}:
                raise ValueError("DOI identity is invalid")
            normalized = parsed_doi.path.removeprefix("/").casefold()
        else:
            normalized = re.sub(r"(?i)^doi:\s*", "", value).casefold()
        if re.fullmatch(r"10\.[0-9]{4,9}/\S+", normalized) is None:
            raise ValueError("DOI identity is invalid")
    elif kind == "pmid":
        if re.fullmatch(r"[1-9][0-9]*", value) is None:
            raise ValueError("PMID identity is invalid")
    elif kind == "pmcid":
        normalized = value.upper()
        if re.fullmatch(r"PMC[1-9][0-9]*", normalized) is None:
            raise ValueError("PMCID identity is invalid")
    elif kind == "arxiv":
        normalized = re.sub(r"(?i)^arxiv:\s*", "", value).casefold()
        modern = re.fullmatch(
            r"(?P<year>[0-9]{2})(?P<month>[0-9]{2})\.[0-9]{4,5}"
            r"(?:v[1-9][0-9]*)?",
            normalized,
        )
        legacy = re.fullmatch(
            r"[a-z][a-z.\-]+/[0-9]{7}(?:v[1-9][0-9]*)?",
            normalized,
        )
        if modern is None and legacy is None:
            raise ValueError("arXiv identity is invalid")
        if modern is not None and not 1 <= int(modern.group("month")) <= 12:
            raise ValueError("arXiv identity is invalid")
        # arXiv's trailing vN selects a manifestation of the same intellectual
        # work.  Version identity belongs in ``version_ids``, not the work key.
        normalized = re.sub(r"v[1-9][0-9]*$", "", normalized)
    elif kind == "isbn":
        normalized = re.sub(r"[\s-]", "", value).upper()
        if re.fullmatch(r"(?:[0-9]{9}[0-9X]|[0-9]{13})", normalized) is None:
            raise ValueError("ISBN identity is invalid")
    return kind, normalized


def _normalized_title(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return " ".join(re.findall(r"\w+", normalized, flags=re.UNICODE))


def _request_has_applied_candidate_decision(request: Mapping[str, Any]) -> bool:
    candidate_id = request.get("selected_candidate_id")
    version_id = request.get("selected_version_id")
    history = request.get("decision_history")
    if not _is_nonempty_string(candidate_id) or not isinstance(history, list):
        return False
    return any(
        isinstance(decision, Mapping)
        and _is_enum(
            decision.get("action"), {"select_candidate", "accept_fallback"}
        )
        and decision.get("candidate_id") == candidate_id
        and decision.get("version_id") == version_id
        and _is_enum(decision.get("outcome"), {"applied", "succeeded"})
        for decision in history[:MAX_DECISION_HISTORY_PER_REQUEST]
    )


def _handoff_has_terminal_retry_attempt(
    handoff: Mapping[str, Any],
    work_id: str,
    attempts: Sequence[Any],
    attempt_by_id: Mapping[str, Mapping[str, Any]],
) -> bool:
    resolution = handoff.get("resolution")
    expected_triggers = (
        {"retry_public"}
        if resolution == "retry_public"
        else {"user_retry", "retry_authenticated"}
    )
    group_ids = handoff.get("access_group_ids")
    scoped_group_ids = (
        set(group_ids)
        if isinstance(group_ids, list)
        and all(isinstance(group_id, str) for group_id in group_ids)
        else set()
    )
    version_ids = handoff.get("version_ids")
    scoped_version_ids = (
        set(version_ids)
        if isinstance(version_ids, list)
        and all(isinstance(version_id, str) for version_id in version_ids)
        else set()
    )

    def matches_scope(attempt: Mapping[str, Any]) -> bool:
        attempt_group_id = attempt.get("access_group_id")
        attempt_version_id = attempt.get("version_id")
        return bool(
            attempt.get("work_id") == work_id
            and (
                not scoped_group_ids
                or (
                    isinstance(attempt_group_id, str)
                    and attempt_group_id in scoped_group_ids
                )
            )
            and (
                not scoped_version_ids
                or (
                    isinstance(attempt_version_id, str)
                    and attempt_version_id in scoped_version_ids
                )
            )
        )

    for attempt in attempts:
        if not isinstance(attempt, Mapping) or not matches_scope(attempt):
            continue
        if attempt.get("status") == "completed" and _is_enum(
            attempt.get("trigger"), expected_triggers
        ):
            return True
        if (
            attempt.get("status") == "completed"
            and attempt.get("outcome") == "suppressed_unchanged"
            and (resolution != "retry_public" or attempt.get("access_mode") == "public")
        ):
            pointer = attempt.get("suppressed_by_attempt_id")
            original = attempt_by_id.get(pointer) if isinstance(pointer, str) else None
            if (
                original is not None
                and original.get("status") == "completed"
                and original.get("outcome")
                not in ("suppressed_unchanged", "cancelled")
                and matches_scope(original)
            ):
                return True
    return False


def new_state(
    titles: Sequence[str], *, access_policy: str = "prompt_if_needed"
) -> dict[str, Any]:
    """Create v2 state with one request and one provisional work per title.

    Even byte-for-byte duplicate titles remain separate requests and provisional
    works.  They may be coalesced later only after a strong identity key matches.
    """

    if isinstance(titles, (str, bytes)) or not isinstance(titles, Sequence):
        raise TypeError("titles must be a sequence of strings")
    if len(titles) > MAX_REQUESTS:
        raise ValueError(f"titles exceeds the {MAX_REQUESTS}-request limit")
    if not _is_enum(access_policy, ACCESS_POLICIES):
        raise ValueError("access_policy is unsupported")
    requests: list[dict[str, Any]] = []
    works: list[dict[str, Any]] = []
    for index, title in enumerate(titles):
        if not isinstance(title, str) or not title.strip() or title != title.strip():
            raise ValueError(f"title at index {index} must be a trimmed nonempty string")
        if len(title) > MAX_TEXT_CHARACTERS:
            raise ValueError(
                f"title at index {index} exceeds {MAX_TEXT_CHARACTERS} characters"
            )
        if _secret_locations(title):
            raise ValueError(f"title at index {index} contains secret-like material")
        suffix = f"{index + 1:06d}"
        work_id = f"work-{suffix}"
        requests.append(
            {
                "id": f"request-{suffix}",
                "input_index": index,
                "title": title,
                "work_id": work_id,
                "artifact_id": None,
                "comment": "",
                "selected_candidate_id": None,
                "selected_version_id": None,
                "pending_action": None,
                "decision_history": [],
                "status": "pending",
            }
        )
        works.append(
            {
                "id": work_id,
                "canonical_title": title,
                "identity_keys": [],
                "version_ids": [f"version-{suffix}"],
                "status": "search_pending",
                "merge_basis": "provisional",
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "active",
        "access_policy": access_policy,
        "requests": requests,
        "works": works,
        "artifacts": [],
        "attempts": [],
        "access_groups": [],
        "handoffs": [],
    }


def retry_fingerprint(
    *,
    work_id: str,
    version_id: str,
    route_kind: str,
    provider_origin: str,
    access_mode: str,
    access_generation: int,
    evidence_revision: int,
) -> str:
    """Hash exactly the non-secret context that can make a retry meaningfully new."""

    if not isinstance(work_id, str) or not work_id:
        raise ValueError("work_id must be a nonempty string")
    if not isinstance(version_id, str) or not version_id:
        raise ValueError("version_id must be a nonempty string")
    if not _is_enum(route_kind, ROUTE_KINDS):
        raise ValueError("route_kind is unsupported")
    origin = canonical_provider_origin(provider_origin)
    _validate_access_context(access_mode, access_generation)
    if not _is_nonnegative_int(evidence_revision):
        raise ValueError("evidence_revision must be a nonnegative integer")
    payload = [
        work_id,
        version_id,
        route_kind,
        origin,
        access_mode,
        access_generation,
        evidence_revision,
    ]
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    return "retry-sha256:" + hashlib.sha256(encoded).hexdigest()


def _access_group_id(origin: str, access_mode: str, access_generation: int) -> str:
    payload = json.dumps(
        [origin, access_mode, access_generation], separators=(",", ":")
    ).encode("utf-8")
    return "access-" + hashlib.sha256(payload).hexdigest()[:20]


def _validate_access_context(access_mode: Any, access_generation: Any) -> None:
    if not _is_enum(access_mode, ACCESS_MODES):
        raise ValueError("access_mode is unsupported")
    if not _is_nonnegative_int(access_generation):
        raise ValueError("access_generation must be a nonnegative integer")
    if access_mode == "public" and access_generation != 0:
        raise ValueError("public access must use generation zero")
    if access_mode == "authenticated" and access_generation < 1:
        raise ValueError("authenticated access must use a positive generation")


def plan_access_groups(
    plans: Iterable[Mapping[str, Any]], *, access_policy: str
) -> list[dict[str, Any]]:
    """Group planned work deterministically by exact origin and access generation.

    Host suffixes, registrable domains, and textual similarity never cause grouping.
    Consequently, each authenticated provider generation has exactly one prompt.
    """

    if not _is_enum(access_policy, ACCESS_POLICIES):
        raise ValueError("access_policy is unsupported")
    grouped: dict[tuple[str, str, int], set[str]] = {}
    for index, plan in enumerate(plans):
        if index >= MAX_ACCESS_PLANS:
            raise ValueError(
                f"access plans exceed the {MAX_ACCESS_PLANS}-entry limit"
            )
        if not isinstance(plan, Mapping):
            raise TypeError(f"access plan {index} must be a mapping")
        unknown = set(plan) - ACCESS_PLAN_FIELDS
        missing = ACCESS_PLAN_FIELDS - set(plan)
        if unknown or missing:
            raise ValueError(f"access plan {index} must use the closed plan schema")
        work_id = plan["work_id"]
        if (
            not _is_nonempty_string(work_id)
            or len(work_id) > MAX_ID_CHARACTERS
        ):
            raise ValueError(f"access plan {index} has invalid work_id")
        origin = canonical_provider_origin(plan["provider_origin"])
        access_mode = plan["access_mode"]
        access_generation = plan["access_generation"]
        _validate_access_context(access_mode, access_generation)
        if access_policy == "public_only" and access_mode != "public":
            raise ValueError("public_only state cannot plan authenticated access")
        key = (origin, access_mode, access_generation)
        if key not in grouped and len(grouped) >= MAX_ACCESS_GROUPS:
            raise ValueError(
                f"access plans exceed the {MAX_ACCESS_GROUPS}-group limit"
            )
        grouped.setdefault(key, set()).add(work_id)
    result: list[dict[str, Any]] = []
    for origin, access_mode, access_generation in sorted(grouped):
        result.append(
            {
                "id": _access_group_id(origin, access_mode, access_generation),
                "provider_origin": origin,
                "access_mode": access_mode,
                "access_generation": access_generation,
                "evidence_revision": 0,
                "evidence_codes": [],
                "work_ids": sorted(grouped[(origin, access_mode, access_generation)]),
                # Planning a browser-capable route does not itself mean a prompt
                # is needed.  A later signed-out observation can transition this
                # field to ``pending`` exactly when next_action becomes sign_in.
                "prompt_status": "not_needed",
                "authentication": (
                    "unknown" if access_mode == "authenticated" else "not_required"
                ),
                "challenge": "unknown",
                "entitlement": "unknown",
                "capture": "unknown",
                "download": "not_attempted",
                "next_action": "probe",
            }
        )
    return result


def bind_work_identity(
    state: Mapping[str, Any], *, work_id: str, kind: str, value: str
) -> tuple[dict[str, Any], str]:
    """Bind a strong identifier, coalescing an untouched provisional duplicate.

    If another work already owns the identity, requests are rebound to that work and
    the provisional work is removed.  Adding a new identity or coalescing is refused
    once an affected work has planning, decisions, attempts, artifacts, or other
    progress, because that history requires an explicit reconciliation. An already
    bound identity remains an idempotent no-op. The input state is never mutated.
    """

    assert_valid_state(state)
    identity_kind, identity_value = normalize_identity_key(kind, value)
    updated = copy.deepcopy(state)
    works = updated["works"]
    target = next((work for work in works if work["id"] == work_id), None)
    if target is None:
        raise ValueError("work_id does not exist")
    owner = next(
        (
            work
            for work in works
            if any(
                key["kind"] == identity_kind and key["value"] == identity_value
                for key in work["identity_keys"]
            )
        ),
        None,
    )

    def has_progress(affected_work_ids: set[str]) -> bool:
        if any(
            record["work_id"] in affected_work_ids
            for collection in ("artifacts", "attempts")
            for record in updated[collection]
        ):
            return True
        if any(
            affected_work_ids.intersection(group["work_ids"])
            for group in updated["access_groups"]
        ):
            return True
        if any(
            affected_work_ids.intersection(handoff["work_ids"])
            for handoff in updated["handoffs"]
        ):
            return True
        if any(
            request["work_id"] in affected_work_ids
            and (
                request["status"] != "pending"
                or request["artifact_id"] is not None
                or request["selected_candidate_id"] is not None
                or request["selected_version_id"] is not None
                or request["pending_action"] is not None
                or request["decision_history"]
            )
            for request in updated["requests"]
        ):
            return True
        return any(
            work["id"] in affected_work_ids and work["status"] != "search_pending"
            for work in works
        )

    if owner is None or owner["id"] == work_id:
        already_bound = any(
            key["kind"] == identity_kind and key["value"] == identity_value
            for key in target["identity_keys"]
        )
        if already_bound and target.get("merge_basis") == "strong_identifier":
            return updated, work_id
        if has_progress({work_id}):
            raise ValueError(
                "cannot bind or coalesce works after planning, decisions, or retrieval history"
            )
        if not already_bound:
            target["identity_keys"].append(
                {"kind": identity_kind, "value": identity_value}
            )
            target["identity_keys"].sort(key=lambda key: (key["kind"], key["value"]))
        target["merge_basis"] = "strong_identifier"
        assert_valid_state(updated)
        return updated, work_id

    owner_normalized_title = _normalized_title(str(owner.get("canonical_title", "")))
    target_normalized_title = _normalized_title(str(target.get("canonical_title", "")))
    if (
        not owner_normalized_title
        or not target_normalized_title
        or owner_normalized_title != target_normalized_title
    ):
        raise ValueError(
            "shared identifier conflicts with the works' canonical titles; review required"
        )

    merge_ids = {work_id, owner["id"]}
    if has_progress(merge_ids):
        raise ValueError(
            "cannot bind or coalesce works after planning, decisions, or retrieval history"
        )

    merged_identity_keys = {
        (key["kind"], key["value"])
        for work in (owner, target)
        for key in work["identity_keys"]
    }
    merged_identity_keys.add((identity_kind, identity_value))
    owner["identity_keys"] = [
        {"kind": key_kind, "value": key_value}
        for key_kind, key_value in sorted(merged_identity_keys)
    ]
    owner["version_ids"] = sorted(set(owner["version_ids"] + target["version_ids"]))
    owner["merge_basis"] = "strong_identifier"
    for request in updated["requests"]:
        if request["work_id"] == work_id:
            request["work_id"] = owner["id"]
    updated["works"] = [work for work in works if work["id"] != work_id]
    assert_valid_state(updated)
    return updated, owner["id"]


def assert_retry_allowed(
    state: Mapping[str, Any],
    *,
    work_id: str,
    version_id: str,
    route_kind: str,
    provider_origin: str,
    access_mode: str,
    access_generation: int,
    evidence_revision: int,
    trigger: str = "user_retry",
) -> str:
    """Return the fingerprint only when a new attempt can be reserved safely."""

    assert_valid_state(state)
    fingerprint, group = _retry_context(
        state,
        work_id=work_id,
        version_id=version_id,
        route_kind=route_kind,
        provider_origin=provider_origin,
        access_mode=access_mode,
        access_generation=access_generation,
        evidence_revision=evidence_revision,
    )
    blocker, reason = _retry_blocker(
        state,
        fingerprint=fingerprint,
        group=group,
        trigger=trigger,
        work_id=work_id,
        version_id=version_id,
        route_kind=route_kind,
    )
    if blocker is not None or reason is not None:
        raise RetryCircuitOpen(reason or "the unchanged retry context is closed")
    return fingerprint


def reserve_attempt(
    state: Mapping[str, Any],
    *,
    attempt_id: str,
    work_id: str,
    version_id: str,
    route_kind: str,
    provider_origin: str,
    access_mode: str,
    access_generation: int,
    evidence_revision: int,
    trigger: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Atomically reserve an attempt or append one honest suppression record.

    The input mapping is never mutated.  An active identical attempt is an error;
    a closed context backed by a completed attempt produces one completed
    ``suppressed_unchanged`` record pointing directly to that original attempt.
    """

    assert_valid_state(state)
    if (
        not _is_nonempty_string(attempt_id)
        or len(attempt_id) > MAX_ID_CHARACTERS
    ):
        raise ValueError("attempt_id must be a bounded nonempty string")
    existing_ids = {
        record.get("id")
        for collection in (
            "requests",
            "works",
            "artifacts",
            "attempts",
            "access_groups",
            "handoffs",
        )
        for record in state[collection]
        if isinstance(record, Mapping)
    }
    existing_ids.update(
        version_id_value
        for work in state["works"]
        for version_id_value in work["version_ids"]
    )
    if attempt_id in existing_ids:
        raise ValueError("attempt_id must be globally unique")

    fingerprint, group = _retry_context(
        state,
        work_id=work_id,
        version_id=version_id,
        route_kind=route_kind,
        provider_origin=provider_origin,
        access_mode=access_mode,
        access_generation=access_generation,
        evidence_revision=evidence_revision,
    )
    blocker, reason = _retry_blocker(
        state,
        fingerprint=fingerprint,
        group=group,
        trigger=trigger,
        work_id=work_id,
        version_id=version_id,
        route_kind=route_kind,
    )
    updated = copy.deepcopy(state)
    canonical_origin = canonical_provider_origin(provider_origin)
    record = {
        "id": attempt_id,
        "work_id": work_id,
        "version_id": version_id,
        "route_kind": route_kind,
        "provider_origin": canonical_origin,
        "access_mode": access_mode,
        "access_generation": access_generation,
        "evidence_revision": evidence_revision,
        "evidence_codes": list(group["evidence_codes"]),
        "retry_fingerprint": fingerprint,
        "access_group_id": group["id"],
        "trigger": trigger,
        "suppressed_by_attempt_id": None,
        "status": "planned",
        "outcome": None,
    }
    if blocker is not None:
        if any(
            attempt.get("retry_fingerprint") == fingerprint
            and attempt.get("outcome") == "suppressed_unchanged"
            for attempt in state["attempts"]
        ):
            raise RetryCircuitOpen(
                "the unchanged retry context already has a suppression record"
            )
        record.update(
            trigger="suppression",
            suppressed_by_attempt_id=blocker["id"],
            status="completed",
            outcome="suppressed_unchanged",
        )
    elif reason is not None:
        # Active attempts and pre-observed entitlement blocks do not have an
        # eligible completed original to point to, so no suppression is fabricated.
        raise RetryCircuitOpen(reason)
    updated["attempts"].append(record)
    assert_valid_state(updated)
    return updated, copy.deepcopy(record)


def _retry_context(
    state: Mapping[str, Any],
    *,
    work_id: str,
    version_id: str,
    route_kind: str,
    provider_origin: str,
    access_mode: str,
    access_generation: int,
    evidence_revision: int,
) -> tuple[str, Mapping[str, Any]]:
    fingerprint = retry_fingerprint(
        work_id=work_id,
        version_id=version_id,
        route_kind=route_kind,
        provider_origin=provider_origin,
        access_mode=access_mode,
        access_generation=access_generation,
        evidence_revision=evidence_revision,
    )
    canonical_origin = canonical_provider_origin(provider_origin)
    groups = [
        group
        for group in state["access_groups"]
        if group["provider_origin"] == canonical_origin
        and group["access_mode"] == access_mode
        and group["access_generation"] == access_generation
        and work_id in group["work_ids"]
    ]
    if len(groups) != 1:
        raise ValueError("retry context must reference exactly one access group")
    group = groups[0]
    if group["evidence_revision"] != evidence_revision:
        raise ValueError(
            "evidence_revision must equal the access group's typed evidence revision"
        )
    work = next((entry for entry in state["works"] if entry["id"] == work_id), None)
    if work is None or version_id not in work["version_ids"]:
        raise ValueError("retry context must reference a version on its work")
    return fingerprint, group


def _is_not_entitled_transition(
    original: Mapping[str, Any], group: Mapping[str, Any]
) -> bool:
    original_revision = original.get("evidence_revision")
    group_revision = group.get("evidence_revision")
    original_codes = original.get("evidence_codes")
    group_codes = group.get("evidence_codes")
    return bool(
        group.get("access_mode") == "authenticated"
        and group.get("entitlement") == "not_entitled"
        and _is_nonnegative_int(original_revision)
        and _is_nonnegative_int(group_revision)
        and group_revision > original_revision
        and isinstance(original_codes, list)
        and isinstance(group_codes, list)
        and original_codes == group_codes[: len(original_codes)]
        and "entitlement_changed" in group_codes[len(original_codes) :]
    )


def _retry_blocker(
    state: Mapping[str, Any],
    *,
    fingerprint: str,
    group: Mapping[str, Any],
    trigger: str,
    work_id: str,
    version_id: str,
    route_kind: str,
) -> tuple[Mapping[str, Any] | None, str | None]:
    if not _is_enum(trigger, ATTEMPT_TRIGGERS - {"suppression"}):
        raise ValueError("attempt trigger is unsupported for a provider invocation")
    matching = [
        attempt
        for attempt in state["attempts"]
        if attempt["retry_fingerprint"] == fingerprint
    ]
    if any(attempt["status"] in {"planned", "running"} for attempt in matching):
        return None, "an unchanged attempt is already planned or running"
    if any(attempt.get("outcome") == "suppressed_unchanged" for attempt in matching):
        return None, "the unchanged retry context already has a suppression record"
    completed = [
        attempt
        for attempt in matching
        if attempt["status"] == "completed"
        and attempt.get("outcome") != "suppressed_unchanged"
    ]
    first_completed = completed[0] if completed else None
    if group["access_mode"] == "authenticated" and group["entitlement"] == "not_entitled":
        first_completed = next(
            (
                attempt
                for attempt in state["attempts"]
                if attempt.get("status") == "completed"
                and attempt.get("outcome") != "suppressed_unchanged"
                and attempt.get("access_group_id") == group.get("id")
                and attempt.get("work_id") == work_id
                and attempt.get("version_id") == version_id
                and attempt.get("route_kind") == route_kind
                and _is_not_entitled_transition(attempt, group)
            ),
            None,
        )
        return (
            first_completed,
            "missing entitlement closes the unchanged authenticated route",
        )
    retrieved = next(
        (attempt for attempt in completed if attempt.get("outcome") == "retrieved"),
        None,
    )
    if retrieved is not None:
        return completed[0], "the unchanged retry context already retrieved an artifact"
    if len(completed) >= 2:
        return (
            completed[0],
            "unchanged retry context already has an initial attempt and one retry",
        )
    if not completed and trigger not in {"initial", "human_download"}:
        return None, "a retry trigger cannot reserve the first attempt in a context"
    if completed and trigger not in {
        "user_retry",
        "retry_public",
        "retry_authenticated",
    }:
        return None, "the one unchanged retry must be explicitly user requested"
    if trigger == "retry_public" and group["access_mode"] != "public":
        return None, "retry_public requires a public access group"
    if trigger == "retry_authenticated" and group["access_mode"] != "authenticated":
        return None, "retry_authenticated requires an authenticated access group"
    return None, None


def _validate_state_impl(state: Any) -> list[str]:
    """Return all detectable schema and cross-entity validation errors."""

    errors: list[str] = CappedStateErrors()
    if not isinstance(state, Mapping):
        return ["$ must be an object"]
    tree_errors = _state_tree_limit_errors(state)
    if tree_errors:
        return tree_errors
    secret_locations = _secret_locations(state)
    if secret_locations:
        errors.append(
            "secret, session, header, or free-form evidence material is forbidden"
        )
    _check_closed(state, ROOT_FIELDS, "$", errors)
    schema_version = state.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != SCHEMA_VERSION
    ):
        errors.append("$.schema_version must be integer 2")
    if not _is_enum(state.get("status"), STATE_STATUSES):
        errors.append("$.status is invalid")
    if not _is_enum(state.get("access_policy"), ACCESS_POLICIES):
        errors.append("$.access_policy is invalid")

    collection_limits = {
        "requests": MAX_REQUESTS,
        "works": MAX_WORKS,
        "artifacts": MAX_ARTIFACTS,
        "attempts": MAX_ATTEMPTS,
        "access_groups": MAX_ACCESS_GROUPS,
        "handoffs": MAX_HANDOFFS,
    }
    collections: dict[str, list[Any]] = {}
    for name in ("requests", "works", "artifacts", "attempts", "access_groups", "handoffs"):
        value = state.get(name)
        if not isinstance(value, list):
            errors.append(f"$.{name} must be an array")
            collections[name] = []
        else:
            limit = collection_limits[name]
            if len(value) > limit:
                errors.append(f"$.{name} exceeds the {limit}-entry limit")
            collections[name] = value[:limit]

    global_ids: dict[str, str] = {}
    work_ids: set[str] = set()
    work_by_id: dict[str, Mapping[str, Any]] = {}
    version_owner: dict[str, str] = {}
    request_ids: set[str] = set()
    request_by_id: dict[str, Mapping[str, Any]] = {}
    artifact_ids: set[str] = set()
    access_group_ids: set[str] = set()

    for index, work in enumerate(collections["works"]):
        path = f"$.works[{index}]"
        if not _check_record(work, WORK_FIELDS, path, errors):
            continue
        work_id = _check_id(work.get("id"), path + ".id", global_ids, errors)
        if work_id:
            work_ids.add(work_id)
            work_by_id[work_id] = work
        if not _is_nonempty_string(work.get("canonical_title")):
            errors.append(path + ".canonical_title must be a trimmed nonempty string")
        elif len(work["canonical_title"]) > MAX_TEXT_CHARACTERS:
            errors.append(path + ".canonical_title is too long")
        if not _is_enum(work.get("status"), WORK_STATUSES):
            errors.append(path + ".status is invalid")
        if not _is_enum(work.get("merge_basis"), WORK_MERGE_BASES):
            errors.append(path + ".merge_basis is invalid")
        identities = work.get("identity_keys")
        if not isinstance(identities, list):
            errors.append(path + ".identity_keys must be an array")
        else:
            if len(identities) > MAX_IDENTITY_KEYS_PER_WORK:
                errors.append(
                    path
                    + f".identity_keys exceeds {MAX_IDENTITY_KEYS_PER_WORK} entries"
                )
            seen_keys: set[tuple[str, str]] = set()
            for key_index, identity in enumerate(
                identities[:MAX_IDENTITY_KEYS_PER_WORK]
            ):
                key_path = f"{path}.identity_keys[{key_index}]"
                if not _check_record(identity, IDENTITY_FIELDS, key_path, errors):
                    continue
                try:
                    normalized = normalize_identity_key(identity.get("kind"), identity.get("value"))
                except ValueError:
                    errors.append(key_path + " is not a valid strong identity key")
                    continue
                if normalized != (identity.get("kind"), identity.get("value")):
                    errors.append(key_path + " must be stored in canonical form")
                if normalized in seen_keys:
                    errors.append(key_path + " duplicates an identity on the same work")
                seen_keys.add(normalized)
        versions = work.get("version_ids")
        if not isinstance(versions, list) or not versions:
            errors.append(path + ".version_ids must be a nonempty array")
        else:
            if len(versions) > MAX_VERSIONS_PER_WORK:
                errors.append(
                    path + f".version_ids exceeds {MAX_VERSIONS_PER_WORK} entries"
                )
            local_versions: set[str] = set()
            for version_index, version_id in enumerate(
                versions[:MAX_VERSIONS_PER_WORK]
            ):
                version_path = f"{path}.version_ids[{version_index}]"
                if not _is_nonempty_string(version_id):
                    errors.append(version_path + " must be a nonempty string")
                elif len(version_id) > MAX_ID_CHARACTERS:
                    errors.append(version_path + " is too long")
                elif version_id in local_versions:
                    errors.append(version_path + " is duplicated")
                elif version_id in version_owner or version_id in global_ids:
                    errors.append(version_path + " must be globally unique")
                else:
                    local_versions.add(version_id)
                    version_owner[version_id] = work_id or ""
                    global_ids[version_id] = version_path

    identity_owner: dict[tuple[str, str], str] = {}
    for index, work in enumerate(collections["works"]):
        if not isinstance(work, Mapping) or not isinstance(work.get("identity_keys"), list):
            continue
        for key_index, identity in enumerate(
            work["identity_keys"][:MAX_IDENTITY_KEYS_PER_WORK]
        ):
            if not isinstance(identity, Mapping):
                continue
            try:
                normalized = normalize_identity_key(identity.get("kind"), identity.get("value"))
            except ValueError:
                continue
            owner = identity_owner.setdefault(normalized, work.get("id"))
            if owner != work.get("id"):
                errors.append(
                    f"$.works[{index}].identity_keys[{key_index}] collides with another work"
                )

    input_indexes: set[int] = set()
    for index, request in enumerate(collections["requests"]):
        path = f"$.requests[{index}]"
        if not _check_record(request, REQUEST_FIELDS, path, errors):
            continue
        request_id = _check_id(request.get("id"), path + ".id", global_ids, errors)
        if request_id:
            request_ids.add(request_id)
            request_by_id[request_id] = request
        input_index = request.get("input_index")
        if not _is_nonnegative_int(input_index):
            errors.append(path + ".input_index must be a nonnegative integer")
        elif input_index in input_indexes:
            errors.append(path + ".input_index must be unique")
        else:
            input_indexes.add(input_index)
        if not _is_nonempty_string(request.get("title")):
            errors.append(path + ".title must be a trimmed nonempty string")
        elif len(request["title"]) > MAX_TEXT_CHARACTERS:
            errors.append(path + ".title is too long")
        if not isinstance(request.get("work_id"), str) or request.get("work_id") not in work_ids:
            errors.append(path + ".work_id does not reference a work")
        artifact_id = request.get("artifact_id")
        if artifact_id is not None and not _is_nonempty_string(artifact_id):
            errors.append(path + ".artifact_id must be null or a nonempty string")
        comment = request.get("comment")
        if not isinstance(comment, str) or len(comment) > MAX_TEXT_CHARACTERS:
            errors.append(path + ".comment must be a bounded string")
        selected_candidate_id = request.get("selected_candidate_id")
        if selected_candidate_id is not None and (
            not _is_nonempty_string(selected_candidate_id)
            or len(selected_candidate_id) > MAX_ID_CHARACTERS
        ):
            errors.append(
                path + ".selected_candidate_id must be null or a bounded identifier"
            )
        selected_version_id = request.get("selected_version_id")
        if selected_version_id is not None:
            if not _is_nonempty_string(selected_version_id):
                errors.append(path + ".selected_version_id must be null or an identifier")
            elif version_owner.get(selected_version_id) != request.get("work_id"):
                errors.append(path + ".selected_version_id belongs to another work")
            if selected_candidate_id is None:
                errors.append(
                    path + ".selected_version_id requires selected_candidate_id"
                )
        pending_action = request.get("pending_action")
        if pending_action is not None:
            _validate_request_decision(
                pending_action,
                path + ".pending_action",
                request.get("work_id"),
                version_owner,
                errors,
                pending=True,
            )
        decision_history = request.get("decision_history")
        if not isinstance(decision_history, list):
            errors.append(path + ".decision_history must be an array")
        else:
            if len(decision_history) > MAX_DECISION_HISTORY_PER_REQUEST:
                errors.append(
                    path
                    + ".decision_history exceeds "
                    + str(MAX_DECISION_HISTORY_PER_REQUEST)
                    + " entries"
                )
            for decision_index, decision in enumerate(
                decision_history[:MAX_DECISION_HISTORY_PER_REQUEST]
            ):
                _validate_request_decision(
                    decision,
                    f"{path}.decision_history[{decision_index}]",
                    request.get("work_id"),
                    version_owner,
                    errors,
                    pending=False,
                )
        if not _is_enum(request.get("status"), REQUEST_STATUSES):
            errors.append(path + ".status is invalid")

    requests_by_work: dict[str, list[Mapping[str, Any]]] = {}
    for index, request in enumerate(collections["requests"]):
        if isinstance(request, Mapping) and isinstance(request.get("work_id"), str):
            requests_by_work.setdefault(request["work_id"], []).append(request)
            work = work_by_id.get(request["work_id"])
            if (
                work is not None
                and isinstance(request.get("title"), str)
                and isinstance(work.get("canonical_title"), str)
                and request["title"] != work["canonical_title"]
                and (
                    not _normalized_title(request["title"])
                    or not _normalized_title(work["canonical_title"])
                    or _normalized_title(request["title"])
                    != _normalized_title(work["canonical_title"])
                )
                and not _request_has_applied_candidate_decision(request)
            ):
                errors.append(
                    f"$.requests[{index}].title does not match its bound work "
                    "without an applied candidate decision"
                )
    for work_id, bound_requests in requests_by_work.items():
        if len(bound_requests) < 2:
            continue
        work = work_by_id.get(work_id)
        if work is None:
            continue
        merge_basis = work.get("merge_basis")
        if merge_basis == "strong_identifier":
            if not work.get("identity_keys"):
                errors.append(
                    "a shared work lacks the required strong identity key"
                )
            canonical_title = _normalized_title(
                str(work.get("canonical_title", ""))
            )
            if not canonical_title or any(
                _normalized_title(str(request.get("title", "")))
                != canonical_title
                for request in bound_requests
            ):
                errors.append(
                    "a strong-identifier merge has conflicting titles"
                )
        elif merge_basis == "documented_lineage":
            normalized_titles = {
                _normalized_title(str(request.get("title", "")))
                for request in bound_requests
            }
            if "" in normalized_titles or len(normalized_titles) != 1:
                errors.append(
                    "a documented-lineage merge has conflicting titles"
                )
        elif not _is_enum(
            merge_basis, {"strong_identifier", "documented_lineage"}
        ):
            errors.append(
                "a work shares multiple requests without an explicit merge basis"
            )

    artifact_by_id: dict[str, Mapping[str, Any]] = {}
    digest_owner: dict[str, str] = {}
    relpath_owner: dict[str, str] = {}
    for index, artifact in enumerate(collections["artifacts"]):
        path = f"$.artifacts[{index}]"
        if not _check_record(artifact, ARTIFACT_FIELDS, path, errors):
            continue
        artifact_id = _check_id(artifact.get("id"), path + ".id", global_ids, errors)
        if artifact_id:
            artifact_ids.add(artifact_id)
            artifact_by_id[artifact_id] = artifact
        _check_work_version(artifact, path, work_ids, version_owner, errors)
        origin = _checked_origin(artifact.get("provider_origin"), path + ".provider_origin", errors)
        if not _is_enum(artifact.get("format"), ARTIFACT_FORMATS):
            errors.append(path + ".format is invalid")
        if not _is_enum(artifact.get("status"), ARTIFACT_STATUSES):
            errors.append(path + ".status is invalid")
        verified_url = artifact.get("verified_url")
        if verified_url is not None:
            try:
                url_origin = _safe_stable_url(verified_url)
            except ValueError:
                errors.append(path + ".verified_url must be a stable safe HTTPS resource URL")
            else:
                if origin and url_origin != origin:
                    errors.append(path + ".verified_url origin must equal provider_origin")
        local_relpath = artifact.get("local_relpath")
        if local_relpath is not None and not _is_safe_relpath(local_relpath):
            errors.append(path + ".local_relpath must be a normalized relative POSIX path")
        elif (
            artifact.get("status") == "verified"
            and isinstance(local_relpath, str)
            and PurePosixPath(local_relpath).parts[:1] != ("papers",)
        ):
            errors.append(path + ".local_relpath for a verified artifact must be under papers/")
        if isinstance(local_relpath, str) and _is_safe_relpath(local_relpath):
            previous_path = relpath_owner.setdefault(
                local_relpath, str(artifact.get("id"))
            )
            if previous_path != str(artifact.get("id")):
                errors.append(path + ".local_relpath is already used by another artifact")
        byte_count = artifact.get("bytes")
        if byte_count is not None and (
            not isinstance(byte_count, int)
            or isinstance(byte_count, bool)
            or byte_count <= 0
        ):
            errors.append(path + ".bytes must be a positive integer when present")
        digest = artifact.get("sha256")
        if digest is not None and (
            not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            errors.append(path + ".sha256 must be a lowercase SHA-256 digest")
        if artifact.get("status") == "verified" and (
            verified_url is None
            or local_relpath is None
            or byte_count is None
            or digest is None
        ):
            errors.append(
                path
                + " verified artifacts require URL, relative path, byte count, and digest"
            )
        if artifact.get("status") == "verified" and not _is_enum(
            artifact.get("format"), {"pdf", "html"}
        ):
            errors.append(path + " verified artifacts must be PDF or HTML")
        if isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest):
            previous_artifact = digest_owner.setdefault(
                digest, str(artifact.get("id"))
            )
            if previous_artifact != str(artifact.get("id")):
                errors.append(path + ".sha256 already identifies another artifact")

    for index, request in enumerate(collections["requests"]):
        if not isinstance(request, Mapping):
            continue
        path = f"$.requests[{index}]"
        artifact_id = request.get("artifact_id")
        status = request.get("status")
        if status == "retrieved":
            artifact = artifact_by_id.get(artifact_id)
            if artifact is None or artifact.get("status") != "verified":
                errors.append(path + ".artifact_id must reference a verified artifact")
            elif artifact.get("work_id") != request.get("work_id"):
                errors.append(path + ".artifact_id belongs to another work")
            elif (
                request.get("selected_version_id") is not None
                and artifact.get("version_id") != request.get("selected_version_id")
            ):
                errors.append(path + ".artifact_id does not match selected_version_id")
        elif artifact_id is not None:
            errors.append(path + ".artifact_id is allowed only for retrieved requests")

    access_group_by_id: dict[str, Mapping[str, Any]] = {}
    access_tuples: set[tuple[str, str, int]] = set()
    for index, group in enumerate(collections["access_groups"]):
        path = f"$.access_groups[{index}]"
        if not _check_record(group, ACCESS_GROUP_FIELDS, path, errors):
            continue
        group_id = _check_id(group.get("id"), path + ".id", global_ids, errors)
        if group_id:
            access_group_ids.add(group_id)
            access_group_by_id[group_id] = group
        origin = _checked_origin(group.get("provider_origin"), path + ".provider_origin", errors)
        access_mode = group.get("access_mode")
        access_generation = group.get("access_generation")
        try:
            _validate_access_context(access_mode, access_generation)
        except ValueError:
            errors.append(path + " has invalid access mode/generation state")
        evidence_revision = group.get("evidence_revision")
        evidence_codes = group.get("evidence_codes")
        if not _is_nonnegative_int(evidence_revision):
            errors.append(path + ".evidence_revision must be a nonnegative integer")
        if not isinstance(evidence_codes, list):
            errors.append(path + ".evidence_codes must be an array")
        elif not _is_unique_strings(evidence_codes):
            errors.append(path + ".evidence_codes must be unique typed codes")
        else:
            if any(code not in ACCESS_EVIDENCE_CODES for code in evidence_codes):
                errors.append(path + ".evidence_codes contains an unsupported code")
            if evidence_revision != len(evidence_codes):
                errors.append(
                    path
                    + ".evidence_revision must equal the number of typed evidence codes"
                )
        if origin and _is_enum(access_mode, ACCESS_MODES) and _is_nonnegative_int(access_generation):
            access_tuple = (origin, access_mode, access_generation)
            if access_tuple in access_tuples:
                errors.append(path + " duplicates a provider access generation")
            access_tuples.add(access_tuple)
            expected_id = _access_group_id(*access_tuple)
            if group_id and group_id != expected_id:
                errors.append(path + ".id is not deterministic for its access context")
        group_work_ids = group.get("work_ids")
        if not isinstance(group_work_ids, list) or not group_work_ids:
            errors.append(path + ".work_ids must be a nonempty array")
        elif not _is_sorted_unique_strings(group_work_ids):
            errors.append(path + ".work_ids must be sorted and unique")
        else:
            for work_id in group_work_ids:
                if work_id not in work_ids:
                    errors.append(path + ".work_ids contains an unknown work")
        prompt_status = group.get("prompt_status")
        if not _is_enum(prompt_status, PROMPT_STATUSES):
            errors.append(path + ".prompt_status is invalid")
        elif access_mode == "public" and prompt_status != "not_needed":
            errors.append(path + " public access must not create a prompt")
        typed_fields = (
            ("authentication", AUTHENTICATION_STATES),
            ("challenge", CHALLENGE_STATES),
            ("entitlement", ENTITLEMENT_STATES),
            ("capture", CAPTURE_STATES),
            ("download", DOWNLOAD_STATES),
            ("next_action", NEXT_ACTIONS),
        )
        for field, allowed in typed_fields:
            if not _is_enum(group.get(field), allowed):
                errors.append(path + f".{field} is invalid")
        authentication = group.get("authentication")
        challenge = group.get("challenge")
        entitlement = group.get("entitlement")
        capture = group.get("capture")
        download = group.get("download")
        next_action = group.get("next_action")
        if access_mode == "public" and authentication != "not_required":
            errors.append(path + " public access must not carry authentication state")
        if access_mode == "public" and next_action == "sign_in":
            errors.append(path + " public access cannot request sign-in")
        if authentication == "signed_in" and _is_enum(
            prompt_status, {"pending", "declined"}
        ):
            errors.append(path + " signed-in state has an inconsistent prompt state")
        if prompt_status == "pending" and next_action != "sign_in":
            errors.append(path + " pending prompt state must request sign-in")
        if next_action == "sign_in" and (
            access_mode != "authenticated" or authentication != "signed_out"
        ):
            errors.append(path + " sign-in action requires authenticated signed-out state")
        if next_action == "sign_in" and not _is_enum(
            prompt_status, {"pending", "acknowledged"}
        ):
            errors.append(path + " sign-in action requires an active or acknowledged prompt")
        if prompt_status == "declined" and _is_enum(
            next_action, {"sign_in", "complete_challenge"}
        ):
            errors.append(path + " declined browser access must use a public or terminal action")
        if authentication == "signed_out" and not _is_enum(
            next_action, {"probe", "sign_in", "retry_public", "none"}
        ):
            errors.append(path + " signed-out state has an inconsistent next action")
        if challenge == "human_required" and not _is_enum(
            next_action, {"complete_challenge", "retry_public", "none"}
        ):
            errors.append(path + " human challenge has an inconsistent next action")
        if next_action == "complete_challenge" and challenge != "human_required":
            errors.append(
                path + " challenge-completion action requires a human-required state"
            )
        if entitlement == "not_entitled" and not _is_enum(
            next_action, {"retry_public", "manual_download", "none"}
        ):
            errors.append(path + " missing entitlement cannot request another sign-in")
        if (
            capture == "browser_save_required" or download == "awaiting_user"
        ) and not _is_enum(next_action, {"manual_download", "none"}):
            errors.append(path + " browser-save state must use a manual-download action")
        if download == "completed" and next_action != "none":
            errors.append(path + " completed download must have no further access action")
        if state.get("access_policy") == "public_only" and access_mode != "public":
            errors.append(path + " violates public_only access policy")
        if state.get("access_policy") == "public_only" and next_action == "sign_in":
            errors.append(path + " public_only access cannot request authentication")

    attempt_by_id: dict[str, Mapping[str, Any]] = {}
    active_by_fingerprint: dict[str, list[Mapping[str, Any]]] = {}
    completed_by_fingerprint: dict[str, list[Mapping[str, Any]]] = {}
    suppressed_by_fingerprint: dict[str, list[Mapping[str, Any]]] = {}
    for index, attempt in enumerate(collections["attempts"]):
        path = f"$.attempts[{index}]"
        if not _check_record(attempt, ATTEMPT_FIELDS, path, errors):
            continue
        attempt_id = _check_id(attempt.get("id"), path + ".id", global_ids, errors)
        if attempt_id:
            attempt_by_id[attempt_id] = attempt
        _check_work_version(attempt, path, work_ids, version_owner, errors)
        origin = _checked_origin(attempt.get("provider_origin"), path + ".provider_origin", errors)
        access_mode = attempt.get("access_mode")
        access_generation = attempt.get("access_generation")
        try:
            _validate_access_context(access_mode, access_generation)
        except ValueError:
            errors.append(path + " has invalid access mode/generation state")
        if not _is_enum(attempt.get("route_kind"), ROUTE_KINDS):
            errors.append(path + ".route_kind is invalid")
        if not _is_nonnegative_int(attempt.get("evidence_revision")):
            errors.append(path + ".evidence_revision must be a nonnegative integer")
        attempt_evidence_codes = attempt.get("evidence_codes")
        if not isinstance(attempt_evidence_codes, list):
            errors.append(path + ".evidence_codes must be an array")
        elif not _is_unique_strings(attempt_evidence_codes):
            errors.append(path + ".evidence_codes must be unique typed codes")
        else:
            if any(code not in ACCESS_EVIDENCE_CODES for code in attempt_evidence_codes):
                errors.append(path + ".evidence_codes contains an unsupported code")
            if attempt.get("evidence_revision") != len(attempt_evidence_codes):
                errors.append(
                    path
                    + ".evidence_revision must equal the number of typed evidence codes"
                )
        trigger = attempt.get("trigger")
        if not _is_enum(trigger, ATTEMPT_TRIGGERS):
            errors.append(path + ".trigger is invalid")
        elif trigger == "retry_public" and access_mode != "public":
            errors.append(path + " retry_public requires public access")
        elif trigger == "retry_authenticated" and access_mode != "authenticated":
            errors.append(path + " retry_authenticated requires authenticated access")
        status = attempt.get("status")
        outcome = attempt.get("outcome")
        if not _is_enum(status, ATTEMPT_STATUSES):
            errors.append(path + ".status is invalid")
        elif _is_enum(status, {"planned", "running"}) and outcome is not None:
            errors.append(path + " unfinished attempts must not have an outcome")
        elif status == "completed" and not _is_enum(
            outcome, ATTEMPT_OUTCOMES - {"cancelled"}
        ):
            errors.append(path + " completed attempts require a completed outcome")
        elif status == "cancelled" and outcome != "cancelled":
            errors.append(path + " cancelled attempts require cancelled outcome")
        suppressed_pointer = attempt.get("suppressed_by_attempt_id")
        if outcome == "suppressed_unchanged":
            if status != "completed" or trigger != "suppression":
                errors.append(path + " suppression must be a completed suppression trigger")
            if not _is_nonempty_string(suppressed_pointer):
                errors.append(path + " suppression requires an original-attempt pointer")
        else:
            if trigger == "suppression":
                errors.append(path + " suppression trigger requires a suppression outcome")
            if suppressed_pointer is not None:
                errors.append(path + " non-suppression attempt must not carry a pointer")
        expected_fingerprint: str | None = None
        try:
            expected_fingerprint = retry_fingerprint(
                work_id=attempt.get("work_id"),
                version_id=attempt.get("version_id"),
                route_kind=attempt.get("route_kind"),
                provider_origin=attempt.get("provider_origin"),
                access_mode=access_mode,
                access_generation=access_generation,
                evidence_revision=attempt.get("evidence_revision"),
            )
        except (TypeError, ValueError):
            pass
        if expected_fingerprint and attempt.get("retry_fingerprint") != expected_fingerprint:
            errors.append(path + ".retry_fingerprint does not match its context")
        fingerprint = attempt.get("retry_fingerprint")
        if isinstance(fingerprint, str):
            if _is_enum(status, {"planned", "running"}):
                active_by_fingerprint.setdefault(fingerprint, []).append(attempt)
            elif status == "completed" and outcome == "suppressed_unchanged":
                suppressed_by_fingerprint.setdefault(fingerprint, []).append(attempt)
            elif status == "completed":
                completed_by_fingerprint.setdefault(fingerprint, []).append(attempt)
        access_group_id = attempt.get("access_group_id")
        group = (
            access_group_by_id.get(access_group_id)
            if isinstance(access_group_id, str)
            else None
        )
        if group is None:
            errors.append(path + ".access_group_id does not reference an access group")
        else:
            if attempt.get("work_id") not in group.get("work_ids", []):
                errors.append(path + " work is not present in its access group")
            for field in ("provider_origin", "access_mode", "access_generation"):
                if attempt.get(field) != group.get(field):
                    errors.append(path + f".{field} disagrees with its access group")
            group_codes = group.get("evidence_codes")
            if (
                isinstance(attempt_evidence_codes, list)
                and isinstance(group_codes, list)
                and attempt_evidence_codes
                != group_codes[: len(attempt_evidence_codes)]
            ):
                errors.append(path + ".evidence_codes are not an access-group revision prefix")
            if (
                _is_nonnegative_int(attempt.get("evidence_revision"))
                and _is_nonnegative_int(group.get("evidence_revision"))
                and attempt.get("evidence_revision") > group.get("evidence_revision")
            ):
                errors.append(path + ".evidence_revision exceeds its access group")
            if (
                group.get("access_mode") == "authenticated"
                and group.get("entitlement") == "not_entitled"
                and _is_enum(status, {"planned", "running"})
            ):
                errors.append(path + " cannot invoke an unchanged non-entitled route")
        if state.get("access_policy") == "public_only" and access_mode != "public":
            errors.append(path + " violates public_only access policy")

    for fingerprint, active_attempts in active_by_fingerprint.items():
        if len(active_attempts) > 1:
            errors.append(
                "$.attempts contains duplicate active attempts for one retry fingerprint"
            )
        completed_attempts = completed_by_fingerprint.get(fingerprint, [])
        if len(completed_attempts) >= 2 or any(
            attempt.get("outcome") == "retrieved" for attempt in completed_attempts
        ):
            errors.append("$.attempts keeps an active attempt after its circuit closed")
        if suppressed_by_fingerprint.get(fingerprint):
            errors.append("$.attempts keeps an active attempt after suppression")
        if not completed_attempts and any(
            not _is_enum(attempt.get("trigger"), {"initial", "human_download"})
            for attempt in active_attempts
        ):
            errors.append(
                "$.attempts first active attempt in a context must be initial "
                "or human-download initiated"
            )
        if completed_attempts and not _is_enum(
            active_attempts[0].get("trigger"),
            {"user_retry", "retry_public", "retry_authenticated"},
        ):
            errors.append("$.attempts unchanged active retry is not user requested")

    for fingerprint, completed_attempts in completed_by_fingerprint.items():
        if completed_attempts and not _is_enum(
            completed_attempts[0].get("trigger"), {"initial", "human_download"}
        ):
            errors.append(
                "$.attempts first completed attempt in a context must be initial "
                "or human-download initiated"
            )
        if len(completed_attempts) > 2:
            errors.append("$.attempts exceeds the unchanged-context retry limit")
        if len(completed_attempts) == 2 and not _is_enum(
            completed_attempts[1].get("trigger"),
            {"user_retry", "retry_public", "retry_authenticated"},
        ):
            errors.append("$.attempts unchanged retry is not explicitly user requested")
        if any(
            attempt.get("outcome") == "retrieved"
            for attempt in completed_attempts[:-1]
        ):
            errors.append("$.attempts continued after an unchanged successful attempt")
        if completed_attempts:
            group = access_group_by_id.get(
                str(completed_attempts[0].get("access_group_id"))
            )
            if (
                group
                and group.get("access_mode") == "authenticated"
                and group.get("entitlement") == "not_entitled"
                and len(completed_attempts) > 1
            ):
                errors.append(
                    "$.attempts retried an unchanged authenticated route after missing entitlement"
                )

    for fingerprint, suppressions in suppressed_by_fingerprint.items():
        if len(suppressions) > 1:
            errors.append("$.attempts duplicates a suppression record")
        completed_attempts = completed_by_fingerprint.get(fingerprint, [])
        for suppression in suppressions:
            pointer = suppression.get("suppressed_by_attempt_id")
            original = attempt_by_id.get(pointer) if isinstance(pointer, str) else None
            same_route_context = bool(
                original
                and all(
                    original.get(field) == suppression.get(field)
                    for field in (
                        "work_id",
                        "version_id",
                        "route_kind",
                        "provider_origin",
                        "access_mode",
                        "access_generation",
                        "access_group_id",
                    )
                )
            )
            suppression_group = access_group_by_id.get(
                str(suppression.get("access_group_id"))
            )
            fingerprint_matches = bool(
                original and original.get("retry_fingerprint") == fingerprint
            )
            entitlement_transition = bool(
                same_route_context
                and suppression_group
                and original
                and _is_not_entitled_transition(original, suppression_group)
            )
            circuit_closed = bool(
                fingerprint_matches
                and (
                    len(completed_attempts) >= 2
                    or any(
                        attempt.get("outcome") == "retrieved"
                        for attempt in completed_attempts
                    )
                )
            )
            if (
                original is None
                or original.get("status") != "completed"
                or _is_enum(
                    original.get("outcome"),
                    {"suppressed_unchanged", "cancelled"},
                )
                or not same_route_context
            ):
                errors.append(
                    "$.attempts suppression pointer must reference an original completed attempt"
                )
            elif not (circuit_closed or entitlement_transition):
                errors.append(
                    "$.attempts suppression is premature for an open retry circuit"
                )
            elif (
                fingerprint_matches
                and completed_attempts
                and original is not completed_attempts[0]
            ):
                errors.append(
                    "$.attempts suppression must point directly to the original attempt"
                )

    active_access_handoffs: set[tuple[str, int]] = set()
    active_manual_handoffs: set[tuple[str, str]] = set()
    for index, handoff in enumerate(collections["handoffs"]):
        path = f"$.handoffs[{index}]"
        if not _check_record(handoff, HANDOFF_FIELDS, path, errors):
            continue
        _check_id(handoff.get("id"), path + ".id", global_ids, errors)
        if not _is_enum(handoff.get("kind"), HANDOFF_KINDS):
            errors.append(path + ".kind is invalid")
        reference_values: dict[str, list[str]] = {}
        for field, valid_ids in (
            ("request_ids", request_ids),
            ("work_ids", work_ids),
            ("access_group_ids", access_group_ids),
        ):
            values = handoff.get(field)
            if not isinstance(values, list):
                errors.append(path + f".{field} must be an array")
                reference_values[field] = []
            elif len(values) > MAX_REFERENCES_PER_HANDOFF:
                errors.append(
                    path
                    + f".{field} exceeds {MAX_REFERENCES_PER_HANDOFF} references"
                )
                reference_values[field] = []
            elif not _is_sorted_unique_strings(values):
                errors.append(path + f".{field} must be sorted and unique")
                reference_values[field] = []
            elif any(value not in valid_ids for value in values):
                errors.append(path + f".{field} contains an unknown reference")
                reference_values[field] = values
            else:
                reference_values[field] = values
        if not any(reference_values.values()):
            errors.append(path + " must reference at least one entity")
        status = handoff.get("status")
        resolution = handoff.get("resolution")
        if not _is_enum(status, HANDOFF_STATUSES):
            errors.append(path + ".status is invalid")
        elif status == "open" and resolution is not None:
            errors.append(path + " open handoffs must not have a resolution")
        elif _is_enum(status, {"submitted", "applied", "resolved"}) and not _is_enum(
            resolution, HANDOFF_RESOLUTIONS - {"cancelled"}
        ):
            errors.append(path + " non-open handoffs require a resolution")
        elif status == "cancelled" and resolution != "cancelled":
            errors.append(path + " cancelled handoffs require cancelled resolution")
        kind = handoff.get("kind")
        if (
            _is_enum(status, {"submitted", "applied", "resolved"})
            and _is_enum(kind, HANDOFF_KINDS)
            and not _is_enum(resolution, HANDOFF_RESOLUTIONS_BY_KIND[kind])
        ):
            errors.append(path + ".resolution is inconsistent with handoff kind")

        version_references = handoff.get("version_ids")
        if not isinstance(version_references, list):
            errors.append(path + ".version_ids must be an array")
            version_references = []
        elif len(version_references) > MAX_VERSIONS_PER_WORK:
            errors.append(path + ".version_ids has too many entries")
            version_references = []
        elif not _is_sorted_unique_strings(version_references):
            errors.append(path + ".version_ids must be sorted and unique")
            version_references = []
        else:
            for version_id in version_references:
                if version_id not in version_owner:
                    errors.append(path + ".version_ids contains an unknown version")

        expected_filenames = handoff.get("expected_filenames")
        if not isinstance(expected_filenames, list):
            errors.append(path + ".expected_filenames must be an array")
            expected_filenames = []
        elif len(expected_filenames) > MAX_VERSIONS_PER_WORK:
            errors.append(path + ".expected_filenames has too many entries")
            expected_filenames = []
        else:
            filenames_are_safe = True
            for filename in expected_filenames:
                if not _is_safe_filename(filename):
                    errors.append(path + ".expected_filenames contains an unsafe hint")
                    filenames_are_safe = False
            if expected_filenames and len(expected_filenames) != len(version_references):
                errors.append(
                    path + ".expected_filenames must align one-to-one with version_ids"
                )
            if not filenames_are_safe:
                expected_filenames = []

        access_generation = handoff.get("access_generation")
        group_references = reference_values["access_group_ids"]
        handoff_work_ids = reference_values["work_ids"]
        handoff_request_ids = reference_values["request_ids"]
        if group_references:
            if not _is_nonnegative_int(access_generation):
                errors.append(path + ".access_generation is required for access groups")
            for group_id in group_references:
                group = access_group_by_id.get(group_id)
                if (
                    group
                    and _is_nonnegative_int(access_generation)
                    and group.get("access_generation") != access_generation
                ):
                    errors.append(path + ".access_generation disagrees with its group")
                group_work_scope = group.get("work_ids") if group else None
                if group and any(
                    not isinstance(group_work_scope, list)
                    or work_id not in group_work_scope
                    for work_id in handoff_work_ids
                ):
                    errors.append(
                        path + " access-group scope does not cover its handoff works"
                    )
        elif access_generation is not None:
            errors.append(path + ".access_generation must be null without an access group")

        for request_id in handoff_request_ids:
            request = request_by_id.get(request_id)
            if request and request.get("work_id") not in handoff_work_ids:
                errors.append(path + ".request_ids and work_ids disagree")
        for version_id in version_references:
            if version_owner.get(version_id) not in handoff_work_ids:
                errors.append(path + ".version_ids and work_ids disagree")

        if _is_enum(kind, {"sign_in", "human_challenge"}):
            if len(group_references) != 1:
                errors.append(path + " access handoff must reference exactly one group")
            else:
                group = access_group_by_id.get(group_references[0])
                if group and handoff_work_ids != group.get("work_ids"):
                    errors.append(path + " access handoff must cover its complete provider group")
                if kind == "sign_in" and group and group.get("access_mode") != "authenticated":
                    errors.append(path + " sign-in handoff requires authenticated access")
                if (
                    kind == "sign_in"
                    and _is_enum(status, {"open", "submitted", "applied"})
                    and group
                    and (
                        group.get("authentication") != "signed_out"
                        or group.get("next_action") != "sign_in"
                        or not _is_enum(
                            group.get("prompt_status"), {"pending", "acknowledged"}
                        )
                    )
                ):
                    errors.append(path + " active sign-in handoff disagrees with access state")
                if (
                    kind == "human_challenge"
                    and _is_enum(status, {"open", "submitted", "applied"})
                    and group
                    and (
                        group.get("challenge") != "human_required"
                        or group.get("next_action") != "complete_challenge"
                    )
                ):
                    errors.append(path + " active challenge handoff disagrees with access state")
            if kind == "sign_in" and state.get("access_policy") == "public_only":
                errors.append(path + " public_only state cannot create a sign-in handoff")
            if version_references or expected_filenames:
                errors.append(path + " access handoff cannot carry file/version hints")
            if len(group_references) == 1 and _is_nonnegative_int(access_generation):
                access_key = (group_references[0], access_generation)
                if _is_enum(status, {"open", "submitted", "applied"}) and access_key in active_access_handoffs:
                    errors.append(path + " duplicates an active access handoff for this generation")
                elif _is_enum(status, {"open", "submitted", "applied"}):
                    active_access_handoffs.add(access_key)
                group = access_group_by_id.get(group_references[0])
                if status == "resolved" and group:
                    if resolution == "signed_in" and group.get("authentication") != "signed_in":
                        errors.append(path + " signed-in resolution disagrees with access state")
                    if resolution == "declined" and group.get("prompt_status") != "declined":
                        errors.append(path + " declined resolution disagrees with prompt state")
                    if (
                        resolution == "challenge_passed"
                        and group.get("challenge") != "passed"
                    ):
                        errors.append(path + " challenge resolution disagrees with access state")
        if kind == "manual_download":
            if len(handoff_work_ids) != 1 or len(version_references) != 1:
                errors.append(path + " manual-download handoff requires one work/version")
            elif _is_enum(status, {"open", "submitted", "applied"}):
                manual_key = (handoff_work_ids[0], version_references[0])
                if manual_key in active_manual_handoffs:
                    errors.append(path + " duplicates an active manual-download handoff")
                active_manual_handoffs.add(manual_key)
        elif expected_filenames:
            errors.append(path + " expected filenames are only valid for manual download")

        if _is_enum(kind, {"candidate_selection", "fallback_acceptance"}):
            if len(handoff_request_ids) != 1 or len(handoff_work_ids) != 1:
                errors.append(path + " candidate handoff requires one request and work")
            if len(version_references) > 1:
                errors.append(path + " candidate handoff permits at most one version")
            if group_references:
                errors.append(path + " candidate handoff must not reference access state")
            request = (
                request_by_id.get(handoff_request_ids[0])
                if len(handoff_request_ids) == 1
                else None
            )
            if _is_enum(status, {"applied", "resolved"}) and request is not None:
                if request.get("selected_candidate_id") is None:
                    errors.append(path + " applied candidate handoff lacks a selected candidate")
                if (
                    version_references
                    and request.get("selected_version_id") != version_references[0]
                ):
                    errors.append(path + " selected version disagrees with handoff")
                if status == "resolved" and request.get("pending_action") is not None:
                    errors.append(path + " resolved candidate handoff retains a pending action")
                expected_action = (
                    "select_candidate"
                    if kind == "candidate_selection"
                    else "accept_fallback"
                )
                decision_history = request.get("decision_history")
                decision_history = (
                    decision_history if isinstance(decision_history, list) else []
                )
                if status == "resolved" and not any(
                    decision.get("action") == expected_action
                    and decision.get("candidate_id")
                    == request.get("selected_candidate_id")
                    and decision.get("version_id")
                    == request.get("selected_version_id")
                    and _is_enum(decision.get("outcome"), {"applied", "succeeded"})
                    for decision in decision_history[:MAX_DECISION_HISTORY_PER_REQUEST]
                    if isinstance(decision, Mapping)
                ):
                    errors.append(path + " resolved candidate handoff lacks an applied decision")

    verified_work_ids = {
        artifact.get("work_id")
        for artifact in collections["artifacts"]
        if isinstance(artifact, Mapping)
        and artifact.get("status") == "verified"
        and isinstance(artifact.get("work_id"), str)
    }
    for index, request in enumerate(collections["requests"]):
        if (
            isinstance(request, Mapping)
            and request.get("status") == "retrieved"
            and (
                not isinstance(request.get("work_id"), str)
                or request.get("work_id") not in verified_work_ids
            )
        ):
            errors.append(f"$.requests[{index}] retrieved state requires a verified artifact")
        if (
            isinstance(request, Mapping)
            and request.get("status") == "retrieved"
            and work_by_id.get(str(request.get("work_id")), {}).get("status")
            != "retrieved"
        ):
            errors.append(f"$.requests[{index}] retrieved state requires a retrieved work")
    for index, work in enumerate(collections["works"]):
        if (
            isinstance(work, Mapping)
            and work.get("status") == "retrieved"
            and (
                not isinstance(work.get("id"), str)
                or work.get("id") not in verified_work_ids
            )
        ):
            errors.append(f"$.works[{index}] retrieved state requires a verified artifact")

    if state.get("status") == "done":
        if any(
            isinstance(handoff, Mapping)
            and not _is_enum(handoff.get("status"), {"resolved", "cancelled"})
            for handoff in collections["handoffs"]
        ):
            errors.append("$.status cannot be done while a handoff is unfinished")
        if any(
            isinstance(request, Mapping)
            and not _is_enum(request.get("status"), {"retrieved", "failed", "skipped"})
            for request in collections["requests"]
        ):
            errors.append("$.status cannot be done while requests need attention")
        if any(
            isinstance(request, Mapping) and request.get("pending_action") is not None
            for request in collections["requests"]
        ):
            errors.append("$.status cannot be done while request actions are pending")
        if any(
            isinstance(work, Mapping)
            and not _is_enum(work.get("status"), {"retrieved", "failed"})
            for work in collections["works"]
        ):
            errors.append("$.status cannot be done while works are nonterminal")
        if any(
            isinstance(attempt, Mapping)
            and _is_enum(attempt.get("status"), {"planned", "running"})
            for attempt in collections["attempts"]
        ):
            errors.append("$.status cannot be done while attempts are unfinished")
        if any(
            isinstance(group, Mapping) and group.get("prompt_status") == "pending"
            for group in collections["access_groups"]
        ):
            errors.append("$.status cannot be done while an access prompt is pending")
        if any(
            isinstance(group, Mapping) and group.get("next_action") != "none"
            for group in collections["access_groups"]
        ):
            errors.append("$.status cannot be done while provider actions remain")
        if any(
            isinstance(artifact, Mapping) and artifact.get("status") == "candidate"
            for artifact in collections["artifacts"]
        ):
            errors.append("$.status cannot be done while artifact candidates remain")
        for handoff in collections["handoffs"]:
            if not (
                isinstance(handoff, Mapping)
                and handoff.get("status") == "resolved"
                and _is_enum(
                    handoff.get("kind"), {"retry_review", "failure_review"}
                )
                and _is_enum(handoff.get("resolution"), {"retry", "retry_public"})
            ):
                continue
            referenced_work_ids = handoff.get("work_ids")
            if not (
                isinstance(referenced_work_ids, list)
                and referenced_work_ids
                and all(isinstance(work_id, str) for work_id in referenced_work_ids)
                and all(
                    _handoff_has_terminal_retry_attempt(
                        handoff,
                        work_id,
                        collections["attempts"],
                        attempt_by_id,
                    )
                    for work_id in referenced_work_ids
                )
            ):
                errors.append(
                    "$.status cannot be done before a resolved retry handoff "
                    "has a matching terminal attempt"
                )
        for work_id, bound_requests in requests_by_work.items():
            work = work_by_id.get(work_id)
            if work is None:
                continue
            retrieved_requests = [
                request for request in bound_requests if request.get("status") == "retrieved"
            ]
            if work.get("status") == "retrieved":
                if len(retrieved_requests) != len(bound_requests):
                    errors.append(
                        "$.status done state requires every request bound to a "
                        "retrieved work to be retrieved"
                    )
                if any(
                    (
                        (artifact := artifact_by_id.get(request.get("artifact_id")))
                        is None
                        or artifact.get("status") != "verified"
                        or artifact.get("work_id") != work_id
                        or (
                            request.get("selected_version_id") is not None
                            and artifact.get("version_id")
                            != request.get("selected_version_id")
                        )
                    )
                    for request in retrieved_requests
                ):
                    errors.append(
                        "$.status done state requires every retrieved request bound "
                        "to a retrieved work to reference its verified artifact"
                    )
            if work.get("status") == "failed" and retrieved_requests:
                errors.append(
                    "$.status done state has a failed work despite a retrieved request"
                )
    return errors


def validate_state(state: Any) -> list[str]:
    """Validate without propagating exceptions from malformed JSON-shaped input."""

    try:
        return _validate_state_impl(state)
    except StateDiagnosticLimit as exc:
        return exc.diagnostics
    except Exception:
        # Diagnostics must be non-reflective: exception text can contain an
        # attacker-controlled mapping key or scalar value.
        return ["$ could not be validated safely"]


def assert_valid_state(state: Any) -> None:
    errors = validate_state(state)
    if errors:
        raise StateValidationError("invalid paper-finder v2 state:\n- " + "\n- ".join(errors))


def _validate_request_decision(
    value: Any,
    path: str,
    work_id: Any,
    version_owner: Mapping[str, str],
    errors: list[str],
    *,
    pending: bool,
) -> None:
    if not _check_record(value, REQUEST_DECISION_FIELDS, path, errors):
        return
    action = value.get("action")
    if not _is_enum(action, REQUEST_ACTIONS):
        errors.append(path + ".action is invalid")
    candidate_id = value.get("candidate_id")
    if candidate_id is not None and (
        not _is_nonempty_string(candidate_id)
        or len(candidate_id) > MAX_ID_CHARACTERS
    ):
        errors.append(path + ".candidate_id must be null or a bounded identifier")
    if _is_enum(action, {"select_candidate", "accept_fallback"}) and candidate_id is None:
        errors.append(path + ".candidate_id is required for candidate decisions")
    if not _is_enum(action, {"select_candidate", "accept_fallback"}) and candidate_id is not None:
        errors.append(path + ".candidate_id is not allowed for this action")
    version_id = value.get("version_id")
    if version_id is not None:
        if not _is_nonempty_string(version_id):
            errors.append(path + ".version_id must be null or an identifier")
        elif version_owner.get(version_id) != work_id:
            errors.append(path + ".version_id belongs to another work")
        if candidate_id is None:
            errors.append(path + ".version_id requires candidate_id")
    comment = value.get("comment")
    if not isinstance(comment, str) or len(comment) > MAX_TEXT_CHARACTERS:
        errors.append(path + ".comment must be a bounded string")
    outcome = value.get("outcome")
    if not _is_enum(outcome, DECISION_OUTCOMES):
        errors.append(path + ".outcome is invalid")
    elif pending and outcome != "queued":
        errors.append(path + ".outcome for a pending action must be queued")
    elif not pending and outcome == "queued":
        errors.append(path + ".outcome in decision history must be applied or terminal")


def _check_closed(
    value: Mapping[str, Any], expected: set[str], path: str, errors: list[str]
) -> None:
    unknown_count = len(set(value) - expected)
    missing = sorted(expected - set(value))
    if unknown_count:
        errors.append(path + f" has unknown fields (count: {unknown_count})")
    if missing:
        errors.append(path + " is missing fields: " + ", ".join(missing))


def _check_record(
    value: Any, expected: set[str], path: str, errors: list[str]
) -> bool:
    if not isinstance(value, Mapping):
        errors.append(path + " must be an object")
        return False
    _check_closed(value, expected, path, errors)
    return True


def _check_id(
    value: Any, path: str, global_ids: dict[str, str], errors: list[str]
) -> str | None:
    if not _is_nonempty_string(value):
        errors.append(path + " must be a trimmed nonempty string")
        return None
    if len(value) > MAX_ID_CHARACTERS:
        errors.append(path + f" exceeds {MAX_ID_CHARACTERS} characters")
        return None
    if value in global_ids:
        errors.append(path + " duplicates " + global_ids[value])
    else:
        global_ids[value] = path
    return value


def _check_work_version(
    record: Mapping[str, Any],
    path: str,
    work_ids: set[str],
    version_owner: Mapping[str, str],
    errors: list[str],
) -> None:
    work_id = record.get("work_id")
    version_id = record.get("version_id")
    if not isinstance(work_id, str) or work_id not in work_ids:
        errors.append(path + ".work_id does not reference a work")
    if not isinstance(version_id, str) or version_id not in version_owner:
        errors.append(path + ".version_id does not reference a version")
    elif version_owner.get(version_id) != work_id:
        errors.append(path + ".version_id belongs to another work")


def _checked_origin(value: Any, path: str, errors: list[str]) -> str | None:
    try:
        origin = canonical_provider_origin(value)
    except ValueError:
        errors.append(path + " must be a safe exact provider origin")
        return None
    if origin != value:
        errors.append(path + " must be stored in canonical form")
    return origin


def _is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_enum(value: Any, allowed: set[str]) -> bool:
    return isinstance(value, str) and value in allowed


def _is_sorted_unique_strings(values: list[Any]) -> bool:
    if not all(_is_nonempty_string(value) for value in values):
        return False
    return values == sorted(values) and len(values) == len(set(values))


def _is_unique_strings(values: list[Any]) -> bool:
    return all(_is_nonempty_string(value) for value in values) and len(values) == len(
        set(values)
    )


def _is_nonempty_string(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and "\x00" not in value
    )


def _is_safe_relpath(value: Any) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > MAX_URL_CHARACTERS
        or "\\" in value
        or re.match(r"^[A-Za-z]:", value)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and str(path) == value
        and value not in {".", ".."}
        and ".." not in path.parts
        and all(_is_portable_path_component(part) for part in path.parts)
    )


def _is_safe_filename(value: Any) -> bool:
    return (
        _is_nonempty_string(value)
        and len(value) <= MAX_ID_CHARACTERS
        and not re.match(r"^[A-Za-z]:", value)
        and _is_portable_path_component(value)
    )


def _is_portable_path_component(value: Any) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or ":" in value
        or value.endswith((".", " "))
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return False
    basename = value.split(".", 1)[0].casefold()
    return basename not in WINDOWS_RESERVED_PATH_BASENAMES


__all__ = [
    "RetryCircuitOpen",
    "SCHEMA_VERSION",
    "StateValidationError",
    "assert_retry_allowed",
    "assert_valid_state",
    "bind_work_identity",
    "canonical_provider_origin",
    "new_state",
    "normalize_identity_key",
    "plan_access_groups",
    "reserve_attempt",
    "retry_fingerprint",
    "validate_state",
]
