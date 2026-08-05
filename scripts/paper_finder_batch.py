#!/usr/bin/env python3
"""Create, validate, review, and export paper-finder batch manifests."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import html
from html.parser import HTMLParser
import ipaddress
import json
import math
import os
import re
import secrets
import selectors
import shutil
import stat
import subprocess
import sys
import threading
import time
import unicodedata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlparse, urlunparse

try:
    import resource
except ImportError:  # pragma: no cover - unavailable on Windows
    resource = None  # type: ignore[assignment]


SCHEMA_VERSION = 1
STATUSES = {
    "pending",
    "processing",
    "retrieved_verified",
    "ambiguous_exact",
    "relevance_fallback",
    "authentication_required",
    "failed_retryable",
    "not_found",
    "failed_final",
}
MATCH_TYPES = {"exact", "relevance", "none"}
CANDIDATE_RELATIONSHIPS = {
    "title_match",
    "version_of_title_match",
    "related_publication",
    "relevance_fallback",
}
TITLE_MATCH_TYPES = {"verbatim", "normalized", "expanded", "different"}
ARTIFACT_DISCOVERY_METHODS = {
    "registry_metadata",
    "html_metadata",
    "structured_data",
    "embedded_document",
    "download_link",
    "repository_metadata",
    "collection_index",
    "user_supplied",
    "other",
}
ROUTE_METRIC_PHASES = {"discovery", "retrieval", "verification"}
PROVENANCE_SOURCE_ROLES = {
    "publisher",
    "issuing_organization",
    "official_repository",
    "official_collection",
    "trusted_registry",
    "author_repository",
    "other_legitimate_source",
}
ACTIONS = {
    "select_candidate",
    "accept_fallback",
    "retry",
    "retry_authenticated",
    "retry_public",
    "skip",
    "stop_retrying",
}
ATTENTION_STATUSES = {
    "pending",
    "processing",
    "ambiguous_exact",
    "relevance_fallback",
    "authentication_required",
    "failed_retryable",
}
FAILED_STATUSES = {"not_found", "failed_final"}
MAX_REQUEST_BYTES = 1_000_000
MAX_HTML_ARTIFACT_BYTES = 20 * 1024 * 1024
MAX_PDF_ARTIFACT_BYTES = 200 * 1024 * 1024
MAX_PDF_TOOL_OUTPUT_BYTES = 25 * 1024 * 1024
PDF_INFO_TIMEOUT_SECONDS = 20
PDF_TEXT_TIMEOUT_SECONDS = 60
MIN_EXTRACTED_TEXT_CHARACTERS = 200
MAX_HTML_NODES = 100_000
MAX_HTML_ATTRIBUTES_PER_ELEMENT = 100
MAX_HTML_ATTRIBUTE_CHARACTERS = 10_000
MAX_HTML_NESTING_DEPTH = 256
MAX_INERT_TEXT_CHARACTERS = 10_000_000
MAX_HTML_VIOLATIONS = 50
MAX_JSON_BYTES = 50 * 1024 * 1024
MAX_JSON_NESTING_DEPTH = 100
MAX_JSON_STRING_CHARACTERS = 100_000
MAX_JSON_KEY_CHARACTERS = 1_000
MAX_TITLE_INPUT_BYTES = 10 * 1024 * 1024
MAX_BATCH_ITEMS = 5_000
MAX_TITLE_CHARACTERS = 10_000
MAX_CANDIDATES_PER_ITEM = 500
MAX_VERSIONS_PER_CANDIDATE = 200
MAX_CANDIDATE_REVIEW_OPTIONS = 500
MAX_ROUTE_METRICS_PER_ITEM = 5_000
MAX_DECISION_HISTORY_PER_ITEM = 10_000
REQUIRED_INERT_CSP = "default-src 'none'; base-uri 'none'; form-action 'none'"
FORBIDDEN_SECRET_KEYS = {
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
    "signature",
}
SECRET_VALUE_PATTERNS = (
    re.compile(
        r"(?im)^\s*(?:authorization|proxy-authorization|cookie|set-cookie)\s*:"
    ),
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
URL_ONLY_SECRET_KEYS = {
    "code",
    "sig",
    "signature",
    "client_assertion",
    "saml_response",
}
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
INERT_HTML_TAGS = {
    "html",
    "head",
    "body",
    "meta",
    "title",
    "main",
    "article",
    "section",
    "header",
    "footer",
    "nav",
    "aside",
    "div",
    "span",
    "p",
    "pre",
    "blockquote",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "ol",
    "ul",
    "li",
    "dl",
    "dt",
    "dd",
    "table",
    "caption",
    "thead",
    "tbody",
    "tfoot",
    "tr",
    "th",
    "td",
    "strong",
    "em",
    "b",
    "i",
    "u",
    "s",
    "sub",
    "sup",
    "code",
    "kbd",
    "samp",
    "var",
    "br",
    "hr",
    "a",
}
RESOURCE_ATTRIBUTES = {
    "src",
    "srcset",
    "action",
    "formaction",
    "data",
    "poster",
    "background",
    "ping",
    "srcdoc",
}
VOID_HTML_TAGS = {"meta", "br", "hr"}
SAFE_GLOBAL_HTML_ATTRIBUTES = {"class", "dir", "id", "lang", "role", "title"}
SAFE_TAG_HTML_ATTRIBUTES = {
    "a": {"href", "rel"},
    "meta": {"charset", "content", "http-equiv"},
    "td": {"colspan", "rowspan"},
    "th": {"colspan", "rowspan", "scope"},
}
INTERNAL_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".localdomain",
    ".internal",
    ".intranet",
    ".lan",
    ".home",
    ".corp",
)
INTERNAL_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata.azure.internal",
}
LEGACY_NUMERIC_HOST = re.compile(
    r"(?i)(?:0x[0-9a-f]+|0[0-7]+|[0-9]+)"
    r"(?:\.(?:0x[0-9a-f]+|0[0-7]+|[0-9]+))*"
)
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
BIDI_CONTROL_CODEPOINTS = {
    0x061C,
    0x200E,
    0x200F,
    *range(0x202A, 0x202F),
    *range(0x2066, 0x206A),
}
MAX_DIAGNOSTIC_CHARACTERS = 2_000


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def diagnostic_text(value: Any) -> str:
    text = str(value)
    rendered: list[str] = []
    for character in text[:MAX_DIAGNOSTIC_CHARACTERS]:
        codepoint = ord(character)
        if (
            codepoint < 0x20
            or 0x7F <= codepoint <= 0x9F
            or codepoint in BIDI_CONTROL_CODEPOINTS
            or codepoint in {0x2028, 0x2029, 0xFEFF}
        ):
            rendered.append(
                f"\\u{codepoint:04x}"
                if codepoint <= 0xFFFF
                else f"\\U{codepoint:08x}"
            )
        else:
            rendered.append(character)
    if len(text) > MAX_DIAGNOSTIC_CHARACTERS:
        rendered.append("…")
    return "".join(rendered)


def print_cli(
    level: str,
    message: Any,
    *,
    error: bool = False,
    flush: bool = False,
) -> None:
    print(
        f"[{level}] {diagnostic_text(message)}",
        file=sys.stderr if error else sys.stdout,
        flush=flush,
    )


def reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key is not allowed: {key}")
        result[key] = value
    return result


def reject_nonfinite_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def validate_json_tree(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    seen_containers: set[int] = set()
    while stack:
        current, depth = stack.pop()
        if depth > MAX_JSON_NESTING_DEPTH:
            raise ValueError(
                f"JSON nesting exceeds the {MAX_JSON_NESTING_DEPTH}-level limit"
            )
        if isinstance(current, float) and not math.isfinite(current):
            raise ValueError("non-finite JSON numbers are not allowed")
        if isinstance(current, str) and len(current) > MAX_JSON_STRING_CHARACTERS:
            raise ValueError(
                "JSON string exceeds the "
                f"{MAX_JSON_STRING_CHARACTERS}-character limit"
            )
        if isinstance(current, dict):
            identity = id(current)
            if identity in seen_containers:
                raise ValueError("cyclic or aliased JSON containers are not allowed")
            seen_containers.add(identity)
            if any(
                not isinstance(key, str) or len(key) > MAX_JSON_KEY_CHARACTERS
                for key in current
            ):
                raise ValueError(
                    "JSON object keys must be strings no longer than "
                    f"{MAX_JSON_KEY_CHARACTERS} characters"
                )
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            identity = id(current)
            if identity in seen_containers:
                raise ValueError("cyclic or aliased JSON containers are not allowed")
            seen_containers.add(identity)
            stack.extend((child, depth + 1) for child in current)


def read_bounded_utf8(path: Path, limit: int, label: str) -> str:
    try:
        with path.open("rb") as handle:
            content = handle.read(limit + 1)
    except FileNotFoundError as exc:
        raise ValueError(f"File not found: {path}") from exc
    if len(content) > limit:
        raise ValueError(f"{label} exceeds the {limit}-byte safety limit: {path}")
    try:
        return content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} must be strict UTF-8: {path}") from exc


def load_json(path: Path) -> Any:
    try:
        value = json.loads(
            read_bounded_utf8(path, MAX_JSON_BYTES, "JSON file"),
            object_pairs_hook=reject_duplicate_json_keys,
            parse_constant=reject_nonfinite_json_constant,
        )
        validate_json_tree(value)
        return value
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc
    except RecursionError as exc:
        raise ValueError(f"JSON nesting is too deep in {path}") from exc


def normalized_secret_key(value: Any) -> str:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value))
    return re.sub(r"[^a-z0-9]+", "_", text.casefold()).strip("_")


def is_secret_key(value: Any, *, in_url: bool = False) -> bool:
    normalized = normalized_secret_key(value)
    if (
        normalized in FORBIDDEN_SECRET_KEYS
        or normalized.startswith("x_amz_")
        or normalized.startswith("x_goog_")
        or normalized.endswith("_access_token")
        or normalized.endswith("_refresh_token")
        or normalized.endswith("_session_token")
        or normalized.endswith("_client_secret")
        or normalized.endswith("_private_key")
    ):
        return True
    return in_url and normalized in URL_ONLY_SECRET_KEYS


def secret_locations(value: Any, location: str = "$") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_location = f"{location}.{key}"
            if (
                is_secret_key(key)
                and child not in (None, False, "")
            ):
                findings.append(child_location)
            findings.extend(secret_locations(child, child_location))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(secret_locations(child, f"{location}[{index}]"))
    elif isinstance(value, str):
        if any(pattern.search(value) for pattern in SECRET_VALUE_PATTERNS):
            findings.append(location)
        try:
            parsed = urlparse(value)
        except ValueError:
            parsed = None
        if parsed and parsed.scheme in {"http", "https"}:
            if parsed.username is not None or parsed.password is not None:
                findings.append(location)
            url_parameters = parse_qsl(
                parsed.query,
                keep_blank_values=True,
            ) + parse_qsl(parsed.fragment, keep_blank_values=True)
            for key, query_value in url_parameters:
                if (
                    is_secret_key(key, in_url=True)
                    and query_value
                ):
                    findings.append(location)
                    break
    return sorted(set(findings))


def reject_secrets(value: Any) -> None:
    findings = secret_locations(value)
    if findings:
        locations = ", ".join(findings[:8])
        suffix = " …" if len(findings) > 8 else ""
        raise ValueError(
            "Refusing to store credential- or token-like material at "
            f"{locations}{suffix}"
        )


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o600
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def save_manifest(path: Path, manifest: dict[str, Any]) -> None:
    validate_json_tree(manifest)
    reject_secrets(manifest)
    revision = manifest.get("revision", 0)
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise ValueError("manifest revision must be a nonnegative integer")
    manifest["revision"] = revision + 1
    manifest["updated_at"] = utc_now()
    atomic_write_text(
        path,
        json.dumps(
            manifest,
            ensure_ascii=False,
            indent=2,
            allow_nan=False,
        )
        + "\n",
    )


def read_titles(path: Path) -> list[str]:
    content = read_bounded_utf8(path, MAX_TITLE_INPUT_BYTES, "Title input")
    if path.suffix.lower() == ".json":
        try:
            value = json.loads(
                content,
                object_pairs_hook=reject_duplicate_json_keys,
                parse_constant=reject_nonfinite_json_constant,
            )
            validate_json_tree(value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {path}: {exc}") from exc
        except RecursionError as exc:
            raise ValueError(f"JSON nesting is too deep in {path}") from exc
        if isinstance(value, dict):
            value = value.get("titles")
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError("JSON title input must be a string list or an object with a string-list 'titles' field")
        titles = [item for item in value if item.strip()]
    else:
        titles = [
            line.rstrip("\r\n")
            for line in content.splitlines(keepends=True)
            if line.strip()
        ]
    if not titles:
        raise ValueError("The title input contains no non-empty titles")
    if len(titles) > MAX_BATCH_ITEMS:
        raise ValueError(f"Title input exceeds the {MAX_BATCH_ITEMS}-item limit")
    if any(len(title) > MAX_TITLE_CHARACTERS for title in titles):
        raise ValueError(
            f"Each title must be at most {MAX_TITLE_CHARACTERS} characters"
        )
    return titles


def new_item(index: int, title: str) -> dict[str, Any]:
    return {
        "id": f"item-{index + 1:04d}",
        "requested_title": title,
        "status": "pending",
        "match_type": "none",
        "comment": "",
        "candidates": [],
        "selected_candidate_id": None,
        "pending_action": None,
        "decision_history": [],
    }


def new_manifest(titles: list[str]) -> dict[str, Any]:
    timestamp = utc_now()
    return {
        "schema_version": SCHEMA_VERSION,
        "revision": 0,
        "created_at": timestamp,
        "updated_at": timestamp,
        "review_state": "processing",
        "done": False,
        "items": [new_item(index, title) for index, title in enumerate(titles)],
    }


def safe_http_url(value: Any) -> str | None:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return None
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None
    try:
        parsed.netloc.encode("ascii")
    except UnicodeEncodeError:
        return None
    if "%" in parsed.netloc:
        return None
    hostname = parsed.hostname.casefold()
    if hostname.endswith(".") or hostname in INTERNAL_HOSTNAMES:
        return None
    if any(hostname.endswith(suffix) for suffix in INTERNAL_HOST_SUFFIXES):
        return None
    try:
        address = ipaddress.ip_address(hostname.split("%", 1)[0])
    except ValueError:
        address = None
    if address is not None or LEGACY_NUMERIC_HOST.fullmatch(hostname):
        return None
    labels = hostname.split(".")
    if len(labels) < 2 or any(DNS_LABEL.fullmatch(label) is None for label in labels):
        return None
    if port is not None and not 1 <= port <= 65535:
        return None
    return value


def canonical_url_key(value: Any) -> str | None:
    safe = safe_http_url(value)
    if safe is None:
        return None
    parsed = urlparse(safe)
    hostname = parsed.hostname.casefold()
    port = parsed.port
    netloc = hostname if port in (None, 443) else f"{hostname}:{port}"
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/") or "/"
    return urlunparse(("https", netloc, path, parsed.params, parsed.query, ""))


def normalized_title(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return " ".join(re.findall(r"\w+", normalized, flags=re.UNICODE))


def title_is_same_or_expanded(requested: str, candidate: str) -> bool:
    requested_tokens = normalized_title(requested).split()
    candidate_tokens = normalized_title(candidate).split()
    if not requested_tokens or not candidate_tokens:
        return False
    candidate_iterator = iter(candidate_tokens)
    return all(
        any(token == candidate_token for candidate_token in candidate_iterator)
        for token in requested_tokens
    )


def is_timestamp_with_timezone(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def allowed_loopback_host_header(value: Any, server_port: int) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = urlparse(f"//{value}")
        port = parsed.port
    except ValueError:
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    if parsed.hostname not in {"127.0.0.1", "localhost"}:
        return False
    return port == server_port or (port is None and server_port == 80)


def resolve_local_path(manifest_path: Path, value: str) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else manifest_path.parent / path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_relative_to(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


class InertHTMLValidator(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.doctype_count = 0
        self.html_count = 0
        self.head_count = 0
        self.body_count = 0
        self.head_closed = False
        self.head_element_count = 0
        self.has_utf8_charset = False
        self.has_restrictive_csp = False
        self.stack: list[str] = []
        self.text_fragments: list[str] = []
        self.body_text_fragments: list[str] = []
        self.node_count = 0
        self.text_characters = 0
        self.violations: list[str] = []

    def violate(self, message: str) -> None:
        if len(self.violations) < MAX_HTML_VIOLATIONS:
            self.violations.append(message)

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        normalized_tag = tag.casefold()
        if normalized_tag not in VOID_HTML_TAGS:
            self.violate(
                f"self-closing <{normalized_tag}> is not allowed in an inert snapshot"
            )
            return
        self.handle_starttag(tag, attrs)

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        normalized_tag = tag.casefold()
        self.node_count += 1
        if self.node_count > MAX_HTML_NODES:
            raise ValueError(f"HTML snapshot exceeds the {MAX_HTML_NODES}-node limit")
        if len(attrs) > MAX_HTML_ATTRIBUTES_PER_ELEMENT:
            raise ValueError(
                "HTML element exceeds the "
                f"{MAX_HTML_ATTRIBUTES_PER_ELEMENT}-attribute limit"
            )
        if any(
            len(name) > MAX_HTML_ATTRIBUTE_CHARACTERS
            or len(value or "") > MAX_HTML_ATTRIBUTE_CHARACTERS
            for name, value in attrs
        ):
            raise ValueError(
                "HTML attribute name or value exceeds the "
                f"{MAX_HTML_ATTRIBUTE_CHARACTERS}-character limit"
            )
        if normalized_tag not in INERT_HTML_TAGS:
            self.violate(f"disallowed <{normalized_tag}> element")
            return

        attribute_names = [name.casefold() for name, _ in attrs]
        seen_attributes: set[str] = set()
        duplicate_names: set[str] = set()
        for name in attribute_names:
            if name in seen_attributes:
                duplicate_names.add(name)
            seen_attributes.add(name)
        if duplicate_names:
            self.violate(
                f"duplicate attribute(s) on <{normalized_tag}>: "
                + ", ".join(sorted(duplicate_names))
            )
            return
        normalized_attrs = {
            name.casefold(): value or "" for name, value in attrs
        }
        allowed_attributes = SAFE_GLOBAL_HTML_ATTRIBUTES | SAFE_TAG_HTML_ATTRIBUTES.get(
            normalized_tag,
            set(),
        )
        for name, value in normalized_attrs.items():
            if (
                name not in allowed_attributes
                and not name.startswith("aria-")
            ):
                self.violate(
                    f"disallowed {name} attribute on <{normalized_tag}>"
                )
            if (
                name.startswith("on")
                or name == "style"
                or name in RESOURCE_ATTRIBUTES
                or name.endswith(":href")
            ):
                self.violate(
                    f"disallowed {name} attribute on <{normalized_tag}>"
                )
            if "javascript:" in value.casefold():
                self.violate(
                    f"active URL in {name} attribute on <{normalized_tag}>"
                )

        if normalized_tag == "html":
            if self.doctype_count != 1 or self.stack or self.html_count:
                self.violate("<html> must occur once immediately after the doctype")
            self.html_count += 1
        elif normalized_tag == "head":
            if self.stack != ["html"] or self.head_count or self.body_count:
                self.violate("<head> must occur once before <body>")
            self.head_count += 1
        elif normalized_tag == "body":
            if (
                self.stack != ["html"]
                or not self.head_closed
                or self.body_count
            ):
                self.violate("<body> must occur once after a closed <head>")
            self.body_count += 1
        elif "head" in self.stack:
            if self.stack != ["html", "head"] or normalized_tag not in {"meta", "title"}:
                self.violate(
                    f"<{normalized_tag}> is not allowed at this location in <head>"
                )
            elif normalized_tag == "title" and self.head_element_count < 2:
                self.violate(
                    "the UTF-8 and CSP meta elements must precede <title>"
                )
        elif "body" not in self.stack:
            self.violate(
                f"<{normalized_tag}> must be inside the document body"
            )

        if normalized_tag == "meta":
            if self.stack != ["html", "head"]:
                self.violate("<meta> is allowed only directly inside <head>")
            elif self.head_element_count == 0:
                if normalized_attrs == {"charset": "utf-8"}:
                    self.has_utf8_charset = True
                else:
                    self.violate(
                        "the first head element must be exactly <meta charset=\"utf-8\">"
                    )
                self.head_element_count += 1
            elif self.head_element_count == 1:
                http_equiv = normalized_attrs.get("http-equiv", "").casefold()
                content = " ".join(
                    normalized_attrs.get("content", "").casefold().split()
                ).rstrip(";")
                if (
                    set(normalized_attrs) == {"http-equiv", "content"}
                    and http_equiv == "content-security-policy"
                    and content == REQUIRED_INERT_CSP
                ):
                    self.has_restrictive_csp = True
                else:
                    self.violate(
                        "the second head element must be the exact required CSP meta"
                    )
                self.head_element_count += 1
            else:
                self.violate("additional <meta> elements are not allowed")
                self.head_element_count += 1

        if normalized_tag == "a" and normalized_attrs.get("href"):
            href = normalized_attrs["href"]
            if not href.startswith("#"):
                self.violate(
                    "external links are not allowed in an inert HTML snapshot"
                )

        if normalized_tag not in VOID_HTML_TAGS:
            if len(self.stack) >= MAX_HTML_NESTING_DEPTH:
                raise ValueError(
                    "HTML snapshot exceeds the "
                    f"{MAX_HTML_NESTING_DEPTH}-element nesting limit"
                )
            self.stack.append(normalized_tag)

    def handle_endtag(self, tag: str) -> None:
        normalized_tag = tag.casefold()
        if normalized_tag in VOID_HTML_TAGS:
            self.violate(f"void element <{normalized_tag}> must not have an end tag")
            return
        if not self.stack or self.stack[-1] != normalized_tag:
            self.violate(f"unexpected or misnested </{normalized_tag}> end tag")
            return
        self.stack.pop()
        if normalized_tag == "head":
            self.head_closed = True

    def handle_data(self, data: str) -> None:
        if data.strip() and "body" not in self.stack and "title" not in self.stack:
            self.violate("text is allowed only inside <title> or <body>")
        if data.strip() and ("body" in self.stack or "title" in self.stack):
            self.text_characters += len(data)
            if self.text_characters > MAX_INERT_TEXT_CHARACTERS:
                raise ValueError(
                    "HTML snapshot exceeds the "
                    f"{MAX_INERT_TEXT_CHARACTERS}-character text limit"
                )
            self.text_fragments.append(data)
            if "body" in self.stack:
                self.body_text_fragments.append(data)

    def handle_decl(self, decl: str) -> None:
        if decl.strip().casefold() != "doctype html" or self.doctype_count or self.html_count:
            self.violate("the document must start with exactly one HTML doctype")
        self.doctype_count += 1

    def handle_comment(self, data: str) -> None:
        self.violate("comments are not allowed in an inert HTML snapshot")

    def handle_pi(self, data: str) -> None:
        self.violate("processing instructions are not allowed")

    def finish(self) -> None:
        if self.doctype_count != 1:
            self.violate("exactly one HTML doctype is required")
        if self.html_count != 1 or self.head_count != 1 or self.body_count != 1:
            self.violate("exactly one html, head, and body element is required")
        if not self.has_utf8_charset:
            self.violate("an exact UTF-8 charset meta is required")
        if not self.has_restrictive_csp:
            self.violate("the exact inert Content Security Policy is required")
        if self.stack:
            self.violate(
                "unclosed HTML element(s): " + ", ".join(self.stack)
            )


def run_bounded_subprocess(
    command: list[str],
    *,
    timeout_seconds: int,
    max_output_bytes: int,
) -> tuple[int | None, bytes, str | None]:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C",
        "LC_ALL": "C",
    }
    preexec_fn = None
    if resource is not None:
        def apply_resource_limits() -> None:
            limits = (
                (resource.RLIMIT_CPU, max(1, timeout_seconds + 5)),
                (resource.RLIMIT_AS, 1024 * 1024 * 1024),
                (resource.RLIMIT_NOFILE, 64),
            )
            for resource_kind, requested_limit in limits:
                try:
                    _, hard_limit = resource.getrlimit(resource_kind)
                    effective_limit = (
                        requested_limit
                        if hard_limit == resource.RLIM_INFINITY
                        else min(requested_limit, hard_limit)
                    )
                    resource.setrlimit(
                        resource_kind,
                        (effective_limit, hard_limit),
                    )
                except (OSError, ValueError):
                    pass

        preexec_fn = apply_resource_limits
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            close_fds=True,
            env=environment,
            preexec_fn=preexec_fn,
        )
    except OSError as exc:
        return None, b"", f"could not start document parser: {exc}"
    if process.stdout is None:
        process.kill()
        process.wait()
        return None, b"", "document parser did not expose bounded output"

    output = bytearray()
    deadline = time.monotonic() + timeout_seconds
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait()
                return None, bytes(output), "document parser exceeded its time limit"
            events = selector.select(timeout=min(0.2, remaining))
            if events:
                chunk = os.read(process.stdout.fileno(), 64 * 1024)
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > max_output_bytes:
                    process.kill()
                    process.wait()
                    return (
                        None,
                        bytes(output[:max_output_bytes]),
                        "document parser exceeded its output limit",
                    )
            elif process.poll() is not None:
                chunk = os.read(process.stdout.fileno(), 64 * 1024)
                if chunk:
                    output.extend(chunk)
                    if len(output) > max_output_bytes:
                        return (
                            None,
                            bytes(output[:max_output_bytes]),
                            "document parser exceeded its output limit",
                        )
                    continue
                break
        return_code = process.wait(timeout=max(1, int(deadline - time.monotonic())))
        return return_code, bytes(output), None
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        process.kill()
        process.wait()
        return None, bytes(output), f"bounded document parsing failed: {exc}"
    finally:
        selector.close()
        process.stdout.close()


def inspect_pdf_with_poppler(
    path: Path,
    *,
    expected_page_count: int,
    expected_title: str,
) -> str | None:
    pdfinfo = shutil.which("pdfinfo")
    pdftotext = shutil.which("pdftotext")
    if not pdfinfo or not pdftotext:
        return (
            "PDF validation requires Poppler's pdfinfo and pdftotext commands; "
            "install Poppler before marking a PDF retrieved_verified"
        )

    info_code, info_output, info_error = run_bounded_subprocess(
        [pdfinfo, str(path)],
        timeout_seconds=PDF_INFO_TIMEOUT_SECONDS,
        max_output_bytes=1_000_000,
    )
    if info_error:
        return info_error
    if info_code != 0:
        summary = info_output.decode("utf-8", errors="replace").strip()[:500]
        return "PDF parser rejected the artifact" + (f": {summary}" if summary else "")
    info_text = info_output.decode("utf-8", errors="replace")
    pages_match = re.search(r"(?m)^Pages:\s+([0-9]+)\s*$", info_text)
    if not pages_match:
        return "PDF parser did not report a page count"
    observed_page_count = int(pages_match.group(1))
    if observed_page_count <= 0:
        return "PDF parser reported no pages"
    if observed_page_count != expected_page_count:
        return (
            "PDF page count differs from verification evidence: "
            f"{observed_page_count} != {expected_page_count}"
        )

    text_code, text_output, text_error = run_bounded_subprocess(
        [pdftotext, "-enc", "UTF-8", "-nopgbrk", "-layout", str(path), "-"],
        timeout_seconds=PDF_TEXT_TIMEOUT_SECONDS,
        max_output_bytes=MAX_PDF_TOOL_OUTPUT_BYTES,
    )
    if text_error:
        return text_error
    if text_code != 0:
        summary = text_output.decode("utf-8", errors="replace").strip()[:500]
        return "PDF text extraction failed" + (f": {summary}" if summary else "")
    extracted_text = text_output.decode("utf-8", errors="replace")
    if len(extracted_text.strip()) < MIN_EXTRACTED_TEXT_CHARACTERS:
        return "PDF does not contain enough extractable text for identity verification"
    if normalized_title(expected_title) not in normalized_title(extracted_text):
        return "PDF extracted text does not contain the selected candidate title"
    return None


def verify_local_artifact(
    path: Path,
    declared_format: Any,
    *,
    expected_bytes: int,
    expected_sha256: str,
    expected_title: str | None = None,
    expected_page_count: int | None = None,
) -> str | None:
    try:
        if path.is_symlink():
            return f"local artifact must not be a symbolic link: {path}"
        if not path.exists():
            return f"local artifact does not exist: {path}"
        if not path.is_file():
            return f"local artifact is not a file: {path}"
        observed_bytes = path.stat().st_size
        if observed_bytes == 0:
            return f"local artifact is empty: {path}"
        if observed_bytes != expected_bytes:
            return (
                f"local artifact byte count differs from verification evidence: "
                f"{observed_bytes} != {expected_bytes}"
            )
        with path.open("rb") as handle:
            sample = handle.read(8192)
            handle.seek(max(0, observed_bytes - 8192))
            trailer = handle.read()
    except OSError as exc:
        return f"could not inspect local artifact {path}: {exc}"
    format_name = str(declared_format or "").strip().lower()
    suffix = path.suffix.lower()
    expects_pdf = format_name == "pdf" or suffix == ".pdf"
    expects_html = format_name in {"html", "htm"} or suffix in {".html", ".htm"}

    if not expects_pdf and not expects_html:
        return f"local artifact must be declared or named as PDF or HTML: {path}"
    if expects_pdf and not sample.startswith(b"%PDF-"):
        return f"local artifact is not a recognizable PDF: {path}"
    if expects_pdf and observed_bytes > MAX_PDF_ARTIFACT_BYTES:
        return f"local PDF artifact exceeds the {MAX_PDF_ARTIFACT_BYTES}-byte safety limit"
    if expects_pdf and observed_bytes < 1024:
        return f"local PDF artifact is implausibly small: {path}"
    if expects_pdf and b"startxref" not in trailer:
        return f"local PDF artifact has no terminal cross-reference pointer: {path}"
    if expects_pdf and b"%%EOF" not in trailer:
        return f"local PDF artifact has no terminal EOF marker: {path}"
    if expects_pdf:
        if not expected_title:
            return "PDF validation requires the selected candidate title"
        if not isinstance(expected_page_count, int) or expected_page_count <= 0:
            return "PDF validation requires a positive declared page count"
        parser_error = inspect_pdf_with_poppler(
            path,
            expected_page_count=expected_page_count,
            expected_title=expected_title,
        )
        if parser_error:
            return parser_error
    if expects_html:
        if observed_bytes > MAX_HTML_ARTIFACT_BYTES:
            return f"local HTML artifact exceeds the {MAX_HTML_ARTIFACT_BYTES}-byte safety limit"
        lowered = sample.lower()
        if b"<html" not in lowered and b"<!doctype html" not in lowered:
            return f"local artifact is not recognizable HTML: {path}"
        try:
            document = path.read_bytes().decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return "local HTML artifact must be strict UTF-8"
        except OSError as exc:
            return f"could not inspect local HTML artifact {path}: {exc}"
        validator = InertHTMLValidator()
        try:
            validator.feed(document)
            validator.close()
            validator.finish()
        except Exception as exc:
            return f"local HTML artifact could not be safely parsed: {exc}"
        if validator.violations:
            return "local HTML artifact contains active content: " + "; ".join(
                validator.violations[:5]
            )
        body_text = " ".join(validator.body_text_fragments)
        if len(body_text.strip()) < MIN_EXTRACTED_TEXT_CHARACTERS:
            return "local HTML artifact does not contain enough body text for verification"
        if expected_title and normalized_title(expected_title) not in normalized_title(
            body_text
        ):
            return "local HTML artifact body does not contain the selected candidate title"
    try:
        observed_sha256 = sha256_file(path)
    except OSError as exc:
        return f"could not hash local artifact {path}: {exc}"
    if observed_sha256 != expected_sha256:
        return (
            "local artifact SHA-256 differs from verification evidence: "
            f"{observed_sha256} != {expected_sha256}"
        )
    return None


def validate_artifact_discovery(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"{label} must be an object")
        return

    method = value.get("method")
    if not isinstance(method, str) or not method.strip():
        errors.append(f"{label}.method must be a non-empty string")
    elif method not in ARTIFACT_DISCOVERY_METHODS:
        errors.append(
            f"{label}.method must be one of: "
            f"{', '.join(sorted(ARTIFACT_DISCOVERY_METHODS))}"
        )

    for field in ("discovered_from", "artifact_url"):
        if safe_http_url(value.get(field)) is None:
            errors.append(f"{label}.{field} must be a safe public HTTPS URL")

    evidence = value.get("evidence")
    if not isinstance(evidence, str) or not evidence.strip():
        errors.append(f"{label}.evidence must be a non-empty string")


def validate_route_metrics(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, list):
        errors.append(f"{label} must be an array")
        return
    if len(value) > MAX_ROUTE_METRICS_PER_ITEM:
        errors.append(
            f"{label} exceeds the {MAX_ROUTE_METRICS_PER_ITEM}-entry limit"
        )
        return

    integer_fields = {"request_count", "redirect_count", "bytes"}
    numeric_fields = integer_fields | {"elapsed_ms"}
    for index, metric in enumerate(value):
        metric_label = f"{label}[{index}]"
        if not isinstance(metric, dict):
            errors.append(f"{metric_label} must be an object")
            continue

        phase = metric.get("phase")
        if not isinstance(phase, str) or phase not in ROUTE_METRIC_PHASES:
            errors.append(
                f"{metric_label}.phase must be one of: "
                f"{', '.join(sorted(ROUTE_METRIC_PHASES))}"
            )
        for field in ("method", "outcome"):
            field_value = metric.get(field)
            if not isinstance(field_value, str) or not field_value.strip():
                errors.append(f"{metric_label}.{field} must be a non-empty string")

        if "url" in metric and safe_http_url(metric.get("url")) is None:
            errors.append(
                f"{metric_label}.url must be a safe public HTTPS URL when present"
            )
        if "access_mode" in metric and not isinstance(metric.get("access_mode"), str):
            errors.append(f"{metric_label}.access_mode must be a string when present")
        if "http_status" in metric:
            http_status = metric.get("http_status")
            if (
                not isinstance(http_status, int)
                or isinstance(http_status, bool)
                or http_status < 100
                or http_status > 599
            ):
                errors.append(
                    f"{metric_label}.http_status must be an integer from 100 through 599 when present"
                )

        for field in numeric_fields:
            if field not in metric:
                continue
            field_value = metric.get(field)
            if field in integer_fields:
                if not isinstance(field_value, int) or isinstance(field_value, bool) or field_value < 0:
                    errors.append(
                        f"{metric_label}.{field} must be a nonnegative integer when present"
                    )
            elif (
                not isinstance(field_value, (int, float))
                or isinstance(field_value, bool)
                or (isinstance(field_value, float) and not math.isfinite(field_value))
                or field_value < 0
            ):
                errors.append(
                    f"{metric_label}.{field} must be a nonnegative finite number when present"
                )


def validate_optional_trace_fields(value: dict[str, Any], label: str, errors: list[str]) -> None:
    if "artifact_discovery" in value:
        validate_artifact_discovery(
            value.get("artifact_discovery"),
            f"{label}.artifact_discovery",
            errors,
        )
    if "route_metrics" in value:
        validate_route_metrics(value.get("route_metrics"), f"{label}.route_metrics", errors)


def validate_result_evidence(
    result: dict[str, Any],
    selected_title: str,
    label: str,
    errors: list[str],
) -> tuple[int | None, str | None]:
    declared_format = result.get("format")
    if declared_format not in {"pdf", "html"}:
        errors.append(f"{label}.format must be pdf or html")

    verification = result.get("verification_summary")
    if not isinstance(verification, dict):
        errors.append(f"{label}.verification_summary must be an object")
        return None, None
    expected_bytes = verification.get("bytes")
    if (
        not isinstance(expected_bytes, int)
        or isinstance(expected_bytes, bool)
        or expected_bytes <= 0
    ):
        errors.append(f"{label}.verification_summary.bytes must be a positive integer")
        expected_bytes = None
    expected_sha256 = verification.get("sha256")
    if (
        not isinstance(expected_sha256, str)
        or expected_sha256 != expected_sha256.casefold()
        or not SHA256_PATTERN.fullmatch(expected_sha256)
    ):
        errors.append(
            f"{label}.verification_summary.sha256 must be a lowercase SHA-256"
        )
        expected_sha256 = None
    for field in (
        "identity_verified",
        "full_text_verified",
        "artifact_integrity_verified",
    ):
        if verification.get(field) is not True:
            errors.append(f"{label}.verification_summary.{field} must be true")

    observed_title = verification.get("observed_title")
    if not isinstance(observed_title, str) or not observed_title.strip():
        errors.append(
            f"{label}.verification_summary.observed_title must be a non-empty string"
        )
    elif normalized_title(observed_title) != normalized_title(selected_title):
        errors.append(
            f"{label}.verification_summary.observed_title must match the selected candidate title"
        )
    for field in ("verification_method", "identity_evidence", "full_text_evidence"):
        field_value = verification.get(field)
        if not isinstance(field_value, str) or not field_value.strip():
            errors.append(
                f"{label}.verification_summary.{field} must be a non-empty string"
            )
    if not is_timestamp_with_timezone(verification.get("verified_at")):
        errors.append(
            f"{label}.verification_summary.verified_at must be an ISO timestamp with timezone"
        )
    if declared_format == "pdf":
        page_count = verification.get("page_count")
        if (
            not isinstance(page_count, int)
            or isinstance(page_count, bool)
            or page_count <= 0
        ):
            errors.append(
                f"{label}.verification_summary.page_count must be a positive integer for PDF"
            )
    elif declared_format == "html" and verification.get("sanitized_inert_snapshot") is not True:
        errors.append(
            f"{label}.verification_summary.sanitized_inert_snapshot must be true for HTML"
        )

    provenance = result.get("provenance")
    if not isinstance(provenance, dict):
        errors.append(f"{label}.provenance must be an object")
    else:
        for field in ("method", "source_role"):
            field_value = provenance.get(field)
            if not isinstance(field_value, str) or not field_value.strip():
                errors.append(f"{label}.provenance.{field} must be a non-empty string")
        source_role = provenance.get("source_role")
        if isinstance(source_role, str) and source_role not in PROVENANCE_SOURCE_ROLES:
            errors.append(
                f"{label}.provenance.source_role must be one of: "
                f"{', '.join(sorted(PROVENANCE_SOURCE_ROLES))}"
            )

    retrieval_url = result.get("retrieval_url")
    if retrieval_url is not None and safe_http_url(retrieval_url) is None:
        errors.append(
            f"{label}.retrieval_url must be a safe public HTTPS URL when present"
        )
    return expected_bytes, expected_sha256


def validate_manifest(manifest: Any, manifest_path: Path) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(manifest, dict):
        return ["manifest root must be an object"], warnings
    try:
        validate_json_tree(manifest)
    except ValueError as exc:
        return [str(exc)], warnings
    for location in secret_locations(manifest):
        errors.append(
            f"credential- or token-like material is not allowed at {location}"
        )

    required_top = {
        "schema_version",
        "revision",
        "created_at",
        "updated_at",
        "review_state",
        "done",
        "items",
    }
    for field in sorted(required_top):
        if field not in manifest:
            errors.append(f"missing top-level field: {field}")

    if manifest.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    if (
        not isinstance(manifest.get("revision"), int)
        or isinstance(manifest.get("revision"), bool)
        or manifest.get("revision", -1) < 0
    ):
        errors.append("revision must be a nonnegative integer")
    for field in ("created_at", "updated_at"):
        if not is_timestamp_with_timezone(manifest.get(field)):
            errors.append(f"{field} must be an ISO timestamp with timezone")
    if manifest.get("review_state") not in {"processing", "review_ready", "submitted", "done"}:
        errors.append("review_state must be processing, review_ready, submitted, or done")
    if not isinstance(manifest.get("done"), bool):
        errors.append("done must be a boolean")
    elif manifest.get("done") and manifest.get("review_state") != "done":
        errors.append("review_state must be done when done is true")
    elif not manifest.get("done") and manifest.get("review_state") == "done":
        errors.append("done must be true when review_state is done")
    items = manifest.get("items")
    if not isinstance(items, list):
        errors.append("items must be an array")
        return errors, warnings
    if len(items) > MAX_BATCH_ITEMS:
        errors.append(f"items exceeds the {MAX_BATCH_ITEMS}-item limit")
        return errors, warnings

    seen_item_ids: set[str] = set()
    required_item = {
        "id",
        "requested_title",
        "status",
        "match_type",
        "comment",
        "candidates",
        "selected_candidate_id",
        "pending_action",
        "decision_history",
    }

    for index, item in enumerate(items):
        label = f"items[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{label} must be an object")
            continue
        for field in sorted(required_item):
            if field not in item:
                errors.append(f"{label} missing field: {field}")

        item_id = item.get("id")
        if not isinstance(item_id, str) or not item_id:
            errors.append(f"{label}.id must be a non-empty string")
        elif item_id in seen_item_ids:
            errors.append(f"duplicate item id: {item_id}")
        else:
            seen_item_ids.add(item_id)

        if not isinstance(item.get("requested_title"), str) or not item.get("requested_title", "").strip():
            errors.append(f"{label}.requested_title must be a non-empty string")
        elif len(item["requested_title"]) > MAX_TITLE_CHARACTERS:
            errors.append(
                f"{label}.requested_title exceeds {MAX_TITLE_CHARACTERS} characters"
            )
        if item.get("status") not in STATUSES:
            errors.append(f"{label}.status must be one of: {', '.join(sorted(STATUSES))}")
        if item.get("match_type") not in MATCH_TYPES:
            errors.append(f"{label}.match_type must be exact, relevance, or none")
        if not isinstance(item.get("comment"), str):
            errors.append(f"{label}.comment must be a string")
        elif len(item["comment"]) > 20_000:
            errors.append(f"{label}.comment exceeds 20,000 characters")
        validate_optional_trace_fields(item, label, errors)

        candidates = item.get("candidates")
        if not isinstance(candidates, list):
            errors.append(f"{label}.candidates must be an array")
            candidates = []
        elif len(candidates) > MAX_CANDIDATES_PER_ITEM:
            errors.append(
                f"{label}.candidates exceeds the {MAX_CANDIDATES_PER_ITEM}-candidate limit"
            )
            candidates = candidates[:MAX_CANDIDATES_PER_ITEM]
        candidate_ids: set[str] = set()
        candidate_versions: dict[str, set[str]] = {}
        for candidate_index, candidate in enumerate(candidates):
            candidate_label = f"{label}.candidates[{candidate_index}]"
            if not isinstance(candidate, dict):
                errors.append(f"{candidate_label} must be an object")
                continue
            candidate_id = candidate.get("id")
            if not isinstance(candidate_id, str) or not candidate_id:
                errors.append(f"{candidate_label}.id must be a non-empty string")
            elif candidate_id in candidate_ids:
                errors.append(f"{label} has duplicate candidate id: {candidate_id}")
            else:
                candidate_ids.add(candidate_id)
                candidate_versions[candidate_id] = set()
            if not isinstance(candidate.get("title"), str) or not candidate.get("title", "").strip():
                errors.append(f"{candidate_label}.title must be a non-empty string")
            source_url = candidate.get("source_url")
            if safe_http_url(source_url) is None:
                errors.append(
                    f"{candidate_label}.source_url must be a safe public HTTPS URL"
                )
            relationship = candidate.get("relationship")
            if relationship is not None and (
                not isinstance(relationship, str) or relationship not in CANDIDATE_RELATIONSHIPS
            ):
                errors.append(
                    f"{candidate_label}.relationship must be one of: "
                    f"{', '.join(sorted(CANDIDATE_RELATIONSHIPS))}"
                )
            title_match_type = candidate.get("title_match_type")
            if title_match_type is not None and (
                not isinstance(title_match_type, str) or title_match_type not in TITLE_MATCH_TYPES
            ):
                errors.append(
                    f"{candidate_label}.title_match_type must be one of: "
                    f"{', '.join(sorted(TITLE_MATCH_TYPES))}"
                )
            versions = candidate.get("versions", [])
            if not isinstance(versions, list):
                errors.append(f"{candidate_label}.versions must be an array when present")
            elif isinstance(candidate_id, str) and candidate_id:
                if len(versions) > MAX_VERSIONS_PER_CANDIDATE:
                    errors.append(
                        f"{candidate_label}.versions exceeds the "
                        f"{MAX_VERSIONS_PER_CANDIDATE}-version limit"
                    )
                    versions = versions[:MAX_VERSIONS_PER_CANDIDATE]
                for version_index, version in enumerate(versions):
                    version_label = f"{candidate_label}.versions[{version_index}]"
                    if not isinstance(version, dict):
                        errors.append(f"{version_label} must be an object")
                        continue
                    version_id = version.get("id")
                    if not isinstance(version_id, str) or not version_id:
                        errors.append(f"{version_label}.id must be a non-empty string")
                    elif version_id in candidate_versions[candidate_id]:
                        errors.append(f"{candidate_label} has duplicate version id: {version_id}")
                    else:
                        candidate_versions[candidate_id].add(version_id)
                    if (
                        "source_url" in version
                        and safe_http_url(version.get("source_url")) is None
                    ):
                        errors.append(
                            f"{version_label}.source_url must be a safe public HTTPS URL when present"
                        )

        candidate_review = item.get("candidate_review")
        if candidate_review is not None:
            if not isinstance(candidate_review, list):
                errors.append(f"{label}.candidate_review must be an array when present")
            elif len(candidate_review) > MAX_CANDIDATE_REVIEW_OPTIONS:
                errors.append(
                    f"{label}.candidate_review exceeds the "
                    f"{MAX_CANDIDATE_REVIEW_OPTIONS}-option limit"
                )
            else:
                for option_index, option in enumerate(candidate_review):
                    option_label = f"{label}.candidate_review[{option_index}]"
                    if not isinstance(option, dict):
                        errors.append(f"{option_label} must be an object")
                        continue
                    for field in ("id", "candidate_id", "version_id"):
                        field_value = option.get(field)
                        if not isinstance(field_value, str) or not field_value:
                            errors.append(
                                f"{option_label}.{field} must be a non-empty string"
                            )
                    option_candidate = option.get("candidate_id")
                    option_version = option.get("version_id")
                    if option_candidate not in candidate_ids:
                        errors.append(
                            f"{option_label}.candidate_id does not name a candidate"
                        )
                    elif option_version not in candidate_versions.get(
                        str(option_candidate), set()
                    ):
                        errors.append(
                            f"{option_label}.version_id does not name a version on its candidate"
                        )

        selected = item.get("selected_candidate_id")
        if selected is not None and selected not in candidate_ids:
            errors.append(f"{label}.selected_candidate_id does not name a candidate")

        action = item.get("pending_action")
        if action is not None:
            if not isinstance(action, dict):
                errors.append(f"{label}.pending_action must be null or an object")
            else:
                action_type = action.get("type")
                if not isinstance(action_type, str) or not action_type:
                    errors.append(f"{label}.pending_action.type must be a non-empty string")
                elif action_type not in ACTIONS:
                    warnings.append(f"{label}.pending_action.type is a future/unknown action: {action_type}")
                if not isinstance(action.get("recorded_at"), str) or not action.get("recorded_at"):
                    errors.append(f"{label}.pending_action.recorded_at must be a non-empty string")
                candidate_id = action.get("candidate_id")
                if candidate_id is not None and candidate_id not in candidate_ids:
                    errors.append(f"{label}.pending_action.candidate_id does not name a candidate")
                version_id = action.get("version_id")
                if version_id is not None:
                    if not isinstance(version_id, str) or not version_id:
                        errors.append(f"{label}.pending_action.version_id must be a non-empty string")
                    elif not candidate_id or version_id not in candidate_versions.get(candidate_id, set()):
                        errors.append(
                            f"{label}.pending_action.version_id does not name a version on its candidate"
                        )
        if manifest.get("done") and action is not None:
            errors.append(f"{label}.pending_action must be null when the batch is done")
        if manifest.get("done") and item.get("status") not in {
            "retrieved_verified",
            "not_found",
            "failed_final",
        }:
            errors.append(f"{label}.status must be terminal when the batch is done")

        history = item.get("decision_history")
        if not isinstance(history, list):
            errors.append(f"{label}.decision_history must be an array")
        elif len(history) > MAX_DECISION_HISTORY_PER_ITEM:
            errors.append(
                f"{label}.decision_history exceeds the "
                f"{MAX_DECISION_HISTORY_PER_ITEM}-entry limit"
            )

        result = item.get("result")
        if result is not None and item.get("status") != "retrieved_verified":
            errors.append(
                f"{label}.result is allowed only when status is retrieved_verified"
            )
        if isinstance(result, dict):
            validate_optional_trace_fields(result, f"{label}.result", errors)
        if item.get("status") == "retrieved_verified":
            if not isinstance(result, dict):
                errors.append(f"{label}.result is required for retrieved_verified")
            else:
                if selected is None:
                    errors.append(
                        f"{label}.selected_candidate_id is required for retrieved_verified"
                    )
                if result.get("selected_candidate_id") != selected:
                    errors.append(
                        f"{label}.result.selected_candidate_id must match the item selection"
                    )
                selected_candidate = next(
                    (
                        candidate
                        for candidate in candidates
                        if isinstance(candidate, dict)
                        and candidate.get("id") == selected
                    ),
                    None,
                )
                relationship = (
                    selected_candidate.get("relationship")
                    if isinstance(selected_candidate, dict)
                    else None
                )
                match_type = item.get("match_type")
                selected_title = (
                    selected_candidate.get("title")
                    if isinstance(selected_candidate, dict)
                    and isinstance(selected_candidate.get("title"), str)
                    else item.get("requested_title", "")
                )
                if match_type not in {"exact", "relevance"}:
                    errors.append(
                        f"{label}.match_type must be exact or relevance for retrieved_verified"
                    )
                if match_type == "exact":
                    if relationship not in {
                        "title_match",
                        "version_of_title_match",
                    }:
                        errors.append(
                            f"{label} exact success must select a title-family candidate"
                        )
                    title_match_type = (
                        selected_candidate.get("title_match_type")
                        if isinstance(selected_candidate, dict)
                        else None
                    )
                    if title_match_type not in {"verbatim", "normalized", "expanded"}:
                        errors.append(
                            f"{label} exact success requires verbatim, normalized, or expanded title evidence"
                        )
                    if not title_is_same_or_expanded(
                        str(item.get("requested_title", "")),
                        str(selected_title),
                    ):
                        errors.append(
                            f"{label} selected candidate title is not the requested title or an ordered expansion"
                        )
                if (
                    match_type == "relevance"
                    and relationship != "relevance_fallback"
                ):
                    errors.append(
                        f"{label} relevance success must select a relevance_fallback candidate"
                    )
                selected_version = result.get("selected_version_id")
                if selected_version is not None and (
                    not isinstance(selected_version, str)
                    or selected_version
                    not in candidate_versions.get(str(selected), set())
                ):
                    errors.append(
                        f"{label}.result.selected_version_id does not name a version "
                        "on the selected candidate"
                    )
                selected_version_entry = next(
                    (
                        version
                        for version in (
                            selected_candidate.get("versions", [])
                            if isinstance(selected_candidate, dict)
                            else []
                        )
                        if isinstance(version, dict)
                        and version.get("id") == selected_version
                    ),
                    None,
                )
                if (
                    isinstance(selected_version_entry, dict)
                    and isinstance(selected_version_entry.get("title"), str)
                    and selected_version_entry["title"].strip()
                ):
                    selected_title = selected_version_entry["title"]
                if selected_version is not None:
                    if not isinstance(selected_version_entry, dict):
                        errors.append(
                            f"{label}.result.selected_version_id must resolve to a version object"
                        )
                    else:
                        if (
                            not isinstance(selected_version_entry.get("title"), str)
                            or not selected_version_entry.get("title", "").strip()
                        ):
                            errors.append(
                                f"{label} selected version must declare its observed title"
                            )
                        if match_type == "exact":
                            if selected_version_entry.get("relationship") != "version_of_title_match":
                                errors.append(
                                    f"{label} selected version must be classified as version_of_title_match"
                                )
                            if selected_version_entry.get("title_match_type") not in {
                                "verbatim",
                                "normalized",
                                "expanded",
                            }:
                                errors.append(
                                    f"{label} selected version requires verbatim, normalized, or expanded title evidence"
                                )
                        if safe_http_url(selected_version_entry.get("source_url")) is None:
                            errors.append(
                                f"{label} selected version must declare a safe public HTTPS source_url"
                            )
                        if (
                            match_type == "exact"
                            and not title_is_same_or_expanded(
                                str(item.get("requested_title", "")),
                                str(selected_title),
                            )
                        ):
                            errors.append(
                                f"{label} selected version title is not in the requested title family"
                            )
                verified_url = result.get("verified_url")
                verified_key = canonical_url_key(verified_url)
                selected_source_key = canonical_url_key(
                    selected_version_entry.get("source_url")
                    if isinstance(selected_version_entry, dict)
                    and selected_version_entry.get("source_url")
                    else (
                        selected_candidate.get("source_url")
                        if isinstance(selected_candidate, dict)
                        else None
                    )
                )
                if verified_key is None:
                    errors.append(
                        f"{label}.result.verified_url must be a safe public HTTPS URL"
                    )
                elif selected_source_key is not None and verified_key != selected_source_key:
                    errors.append(
                        f"{label}.result.verified_url must match the selected candidate source_url"
                    )

                artifact_discovery = item.get("artifact_discovery")
                if not isinstance(artifact_discovery, dict):
                    errors.append(
                        f"{label}.artifact_discovery is required for retrieved_verified"
                    )
                else:
                    artifact_key = canonical_url_key(
                        artifact_discovery.get("artifact_url")
                    )
                    retrieval_key = canonical_url_key(result.get("retrieval_url"))
                    if retrieval_key is None:
                        errors.append(
                            f"{label}.result.retrieval_url is required for retrieved_verified"
                        )
                    elif artifact_key is not None and retrieval_key != artifact_key:
                        errors.append(
                            f"{label}.result.retrieval_url must match artifact_discovery.artifact_url"
                        )
                    discovery_method = artifact_discovery.get("method")
                    discovered_from_key = canonical_url_key(
                        artifact_discovery.get("discovered_from")
                    )
                    if (
                        discovery_method not in {"collection_index", "repository_metadata"}
                        and verified_key is not None
                        and discovered_from_key is not None
                        and discovered_from_key != verified_key
                    ):
                        errors.append(
                            f"{label}.artifact_discovery.discovered_from must match the verified canonical URL for this discovery method"
                        )
                route_metrics = item.get("route_metrics")
                passed_verification_metrics = [
                    metric
                    for metric in route_metrics or []
                    if isinstance(metric, dict)
                    and metric.get("phase") == "verification"
                    and str(metric.get("outcome", "")).casefold() == "passed"
                ] if isinstance(route_metrics, list) else []
                if not passed_verification_metrics:
                    errors.append(
                        f"{label}.route_metrics must include a verification phase with outcome passed"
                    )
                allowed_verification_url_keys = {
                    key
                    for key in (
                        verified_key,
                        canonical_url_key(
                            artifact_discovery.get("artifact_url")
                            if isinstance(artifact_discovery, dict)
                            else None
                        ),
                        canonical_url_key(result.get("retrieval_url")),
                    )
                    if key is not None
                }
                for metric in passed_verification_metrics:
                    if (
                        "url" in metric
                        and canonical_url_key(metric.get("url"))
                        not in allowed_verification_url_keys
                    ):
                        errors.append(
                            f"{label}.route_metrics verification URL must match the verified or retrieved source"
                        )
                expected_bytes, expected_sha256 = validate_result_evidence(
                    result,
                    str(selected_title),
                    f"{label}.result",
                    errors,
                )
                if expected_bytes is not None and passed_verification_metrics:
                    if not any(
                        metric.get("bytes") == expected_bytes
                        for metric in passed_verification_metrics
                    ):
                        errors.append(
                            f"{label}.route_metrics verification bytes must match the local artifact evidence"
                        )
                provenance = result.get("provenance")
                if (
                    isinstance(artifact_discovery, dict)
                    and artifact_discovery.get("method") == "collection_index"
                    and isinstance(provenance, dict)
                    and provenance.get("source_role") != "official_collection"
                ):
                    errors.append(
                        f"{label}.result.provenance.source_role must be official_collection for collection_index discovery"
                    )
                if (
                    isinstance(artifact_discovery, dict)
                    and artifact_discovery.get("method") == "repository_metadata"
                    and isinstance(provenance, dict)
                    and provenance.get("source_role") not in {
                        "official_repository",
                        "author_repository",
                    }
                ):
                    errors.append(
                        f"{label}.result.provenance.source_role must identify the repository for repository_metadata discovery"
                    )
                local_path = result.get("local_path")
                if not isinstance(local_path, str) or not local_path:
                    errors.append(f"{label}.result.local_path is required")
                else:
                    relative_path = Path(local_path)
                    manifest_directory = manifest_path.parent.resolve()
                    if (
                        relative_path.is_absolute()
                        or ".." in relative_path.parts
                        or not relative_path.parts
                        or relative_path.parts[0] != "papers"
                    ):
                        errors.append(
                            f"{label}.result.local_path must be a relative path under papers/"
                        )
                    else:
                        unresolved_artifact_path = manifest_directory / relative_path
                        if unresolved_artifact_path.is_symlink():
                            errors.append(
                                f"{label}.result.local_path must not be a symbolic link"
                            )
                        else:
                            artifact_path = unresolved_artifact_path.resolve()
                            if not is_relative_to(
                                artifact_path, manifest_directory / "papers"
                            ):
                                errors.append(
                                    f"{label}.result.local_path escapes the batch "
                                    "papers directory"
                                )
                            elif (
                                expected_bytes is not None
                                and expected_sha256 is not None
                            ):
                                artifact_error = verify_local_artifact(
                                    artifact_path,
                                    result.get("format"),
                                    expected_bytes=expected_bytes,
                                    expected_sha256=expected_sha256,
                                    expected_title=str(selected_title),
                                    expected_page_count=(
                                        result.get("verification_summary", {}).get(
                                            "page_count"
                                        )
                                        if isinstance(
                                            result.get("verification_summary"), dict
                                        )
                                        else None
                                    ),
                                )
                                if artifact_error:
                                    errors.append(f"{label}: {artifact_error}")

        failure = item.get("failure")
        if item.get("status") in {"failed_retryable", "failed_final"} and not isinstance(failure, dict):
            errors.append(f"{label}.failure is required for {item.get('status')}")
        if failure is not None:
            if not isinstance(failure, dict):
                errors.append(f"{label}.failure must be an object when present")
            else:
                if not isinstance(failure.get("code"), str) or not failure.get("code"):
                    errors.append(f"{label}.failure.code must be a non-empty string")
                if not isinstance(failure.get("message"), str) or not failure.get("message"):
                    errors.append(f"{label}.failure.message must be a non-empty string")
                if "sign_in_url" in failure:
                    errors.append(
                        f"{label}.failure.sign_in_url is not accepted; use the "
                        "verified selected-candidate source URL for sign-in"
                    )
                if not isinstance(failure.get("retryable"), bool):
                    errors.append(f"{label}.failure.retryable must be a boolean")
                elif item.get("status") == "failed_retryable" and not failure["retryable"]:
                    errors.append(f"{label}.failure.retryable must be true for failed_retryable")
                elif item.get("status") == "failed_final" and failure["retryable"]:
                    errors.append(f"{label}.failure.retryable must be false for failed_final")

        if item.get("match_type") == "relevance" and item.get("status") == "retrieved_verified":
            selected_result_version = (
                result.get("selected_version_id")
                if isinstance(result, dict)
                else None
            )
            accepted = any(
                isinstance(decision, dict)
                and (decision.get("type") or decision.get("action"))
                == "accept_fallback"
                and decision.get("candidate_id") == selected
                and decision.get("version_id") == selected_result_version
                and decision.get("outcome") == "accepted"
                and is_timestamp_with_timezone(decision.get("applied_at"))
                for decision in history or []
            )
            if not accepted:
                errors.append(
                    f"{label} is a relevance result without a complete applied accept_fallback decision"
                )

    return errors, warnings


def print_validation(errors: list[str], warnings: list[str]) -> None:
    for warning in warnings:
        print_cli("WARN", warning)
    for error in errors:
        print_cli("ERROR", error, error=True)
    if not errors:
        print_cli("OK", f"Manifest is valid ({len(warnings)} warning(s))")


REVIEW_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Paper Finder Review</title>
  <style>
    :root { color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; background: #f4f6f8; color: #18212b; }
    header { position: sticky; top: 0; z-index: 2; background: #12263a; color: white; padding: 18px 24px; }
    header h1 { margin: 0 0 6px; font-size: 22px; }
    header p { margin: 0; color: #c8d6e5; }
    main { max-width: 1100px; margin: 0 auto; padding: 20px; }
    .summary, .tabs, .batch-actions { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 16px; }
    .pill { border-radius: 999px; background: white; border: 1px solid #d9e0e7; padding: 7px 11px; font-size: 13px; }
    button, select, textarea { font: inherit; }
    button { border: 1px solid #8aa0b5; border-radius: 8px; background: white; padding: 8px 12px; cursor: pointer; }
    button.primary { background: #146c94; border-color: #146c94; color: white; }
    button.danger { border-color: #a33a3a; color: #8a2020; }
    button.active { background: #dcedf7; border-color: #146c94; }
    button:disabled { opacity: .5; cursor: not-allowed; }
    .card { background: white; border: 1px solid #d9e0e7; border-left: 5px solid #8aa0b5; border-radius: 10px; padding: 16px; margin-bottom: 14px; box-shadow: 0 2px 7px #0000000a; }
    .card.retrieved { border-left-color: #27864b; }
    .card.attention { border-left-color: #c98513; }
    .card.failed { border-left-color: #b44141; }
    .card h2 { font-size: 18px; margin: 0 0 8px; }
    .meta { color: #536575; font-size: 13px; margin-bottom: 10px; }
    .candidate { display: grid; grid-template-columns: 24px 1fr; gap: 6px; padding: 9px; border: 1px solid #e3e8ed; border-radius: 8px; margin: 7px 0; }
    .candidate-review { border-color: #d6a84b; background: #fff9eb; }
    .review-label { display: inline-block; margin: 0 7px 5px 0; border-radius: 999px; background: #f4dfac; color: #62480e; padding: 3px 7px; font-size: 12px; font-weight: 700; }
    .candidate p { margin: 3px 0; }
    .candidate a, .result a { color: #075f88; overflow-wrap: anywhere; }
    .trace { border: 1px solid #d5dee6; border-radius: 7px; padding: 7px 9px; margin: 8px 0; background: #f8fafb; }
    .trace summary { cursor: pointer; font-weight: 600; }
    .trace p { margin: 5px 0; }
    .trace ol { margin: 7px 0 2px; padding-left: 22px; }
    .trace li { margin: 7px 0; }
    .bulk-control { display: grid; grid-template-columns: minmax(260px, 1fr) minmax(220px, 300px) auto; gap: 12px; align-items: end; margin-bottom: 16px; padding: 14px; border: 1px solid #c8d5df; border-radius: 10px; background: #edf5fa; }
    .bulk-control p { margin: 4px 0 0; }
    .bulk-control label { display: grid; gap: 5px; color: #354d60; font-size: 13px; font-weight: 600; }
    .decision { display: grid; grid-template-columns: minmax(180px, 260px) 1fr auto; gap: 8px; align-items: start; margin-top: 12px; }
    textarea { min-height: 72px; resize: vertical; border: 1px solid #b8c4cf; border-radius: 8px; padding: 8px; }
    select { border: 1px solid #b8c4cf; border-radius: 8px; padding: 8px; width: 100%; }
    .notice { border-radius: 8px; padding: 10px; background: #fff4d8; color: #62480e; margin: 8px 0; }
    .failure { border-radius: 8px; padding: 10px; background: #fdeaea; color: #7d2525; margin: 8px 0; }
    .result { border-radius: 8px; padding: 10px; background: #e9f7ee; margin: 8px 0; }
    #message { min-height: 24px; color: #2d536d; }
    .empty { color: #667786; padding: 28px; text-align: center; background: white; border-radius: 10px; }
    @media (max-width: 720px) { .bulk-control, .decision { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <header>
    <h1>Paper Finder Batch Review</h1>
    <p>Review the completed pass, record decisions together, then apply them in one round.</p>
  </header>
  <main>
    <div id="summary" class="summary"></div>
    <div id="tabs" class="tabs"></div>
    <section id="bulk" class="bulk-control" aria-label="Bulk decision staging">
      <div>
        <strong>Stage a bulk decision</strong>
        <p id="bulk-count" class="meta"></p>
      </div>
      <label for="bulk-action">
        Action
        <select id="bulk-action">
          <option value="">Choose an action…</option>
          <option value="retry">Retry</option>
          <option value="retry_authenticated">Retry after sign-in</option>
          <option value="retry_public">Retry public sources only</option>
          <option value="skip">Skip</option>
          <option value="stop_retrying">Stop retrying</option>
        </select>
      </label>
      <button id="bulk-stage" type="button">Stage for visible attention items</button>
    </section>
    <div id="items"></div>
    <div class="batch-actions">
      <button id="apply" class="primary">Apply decisions</button>
      <button id="done" class="danger">Done</button>
    </div>
    <div id="message" role="status" aria-live="polite"></div>
  </main>
  <script>
    "use strict";
    const apiBase = location.pathname;
    let manifest = null;
    let activeTab = "attention";
    const dirtyItems = new Set();
    const drafts = new Map();
    const bulkActions = new Set([
      "retry",
      "retry_authenticated",
      "retry_public",
      "skip",
      "stop_retrying"
    ]);
    let saveRequests = 0;
    let uiBusy = false;

    function node(tag, text, className) {
      const element = document.createElement(tag);
      if (text !== undefined && text !== null) element.textContent = String(text);
      if (className) element.className = className;
      return element;
    }

    function category(item) {
      if (item.status === "retrieved_verified") return "retrieved";
      if (["not_found", "failed_final"].includes(item.status)) return "failed";
      return "attention";
    }

    function allowedUrl(value) {
      if (
        typeof value !== "string" ||
        value !== value.trim() ||
        /[\\u0000-\\u001f\\u007f\\\\]/.test(value)
      ) return null;
      try {
        const authority = value.match(/^https:\\/\\/([^/?#]*)/i)?.[1];
        if (!authority || /[^\\x00-\\x7f%]/.test(authority) || authority.includes("%")) {
          return null;
        }
        const parsed = new URL(value);
        if (
          parsed.protocol !== "https:" ||
          parsed.username ||
          parsed.password ||
          parsed.port === "0"
        ) return null;
        const hostname = parsed.hostname.toLowerCase();
        const internalSuffixes = [
          ".localhost", ".local", ".localdomain", ".internal",
          ".intranet", ".lan", ".home", ".corp"
        ];
        if (
          hostname === "localhost" ||
          hostname === "metadata.google.internal" ||
          hostname === "metadata.azure.internal" ||
          hostname.endsWith(".") ||
          hostname.includes(":") ||
          /^\\d+(?:\\.\\d+){3}$/.test(hostname) ||
          internalSuffixes.some(suffix => hostname.endsWith(suffix))
        ) return null;
        const labels = hostname.split(".");
        if (
          labels.length < 2 ||
          labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
        ) return null;
        return parsed.href;
      } catch (_) {
        return null;
      }
    }

    function readableValue(value) {
      if (value === undefined || value === null || value === "") return null;
      if (Array.isArray(value)) {
        const values = value.map(readableValue).filter(Boolean);
        return values.length ? values.join("; ") : null;
      }
      if (typeof value === "object") {
        try {
          return JSON.stringify(value);
        } catch (_) {
          return String(value);
        }
      }
      return String(value);
    }

    function addDetail(container, label, value, className) {
      const rendered = readableValue(value);
      if (rendered) container.append(node("p", `${label}: ${rendered}`, className));
    }

    async function request(path, options = {}) {
      const response = await fetch(apiBase + path, {
        ...options,
        headers: {"Content-Type": "application/json", ...(options.headers || {})}
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || `Request failed: ${response.status}`);
      return payload;
    }

    function addLink(container, label, url) {
      const safe = allowedUrl(url);
      if (!safe) return;
      const anchor = node("a", `${label} (${new URL(safe).hostname})`);
      anchor.href = safe;
      anchor.target = "_blank";
      anchor.rel = "noopener noreferrer";
      container.append(anchor);
    }

    function addLabeledLink(container, label, url) {
      const safe = allowedUrl(url);
      if (!safe) return;
      const row = node("p");
      row.append(node("strong", `${label}: `));
      const anchor = node("a", safe);
      anchor.href = safe;
      anchor.target = "_blank";
      anchor.rel = "noopener noreferrer";
      row.append(anchor);
      container.append(row);
    }

    function renderArtifactDiscovery(container, discovery) {
      if (!discovery || typeof discovery !== "object" || Array.isArray(discovery)) return;
      const details = node("details", null, "trace");
      const method = readableValue(discovery.method);
      details.append(node("summary", method ? `Artifact discovery · ${method}` : "Artifact discovery"));
      addLabeledLink(details, "Discovered from", discovery.discovered_from);
      addLabeledLink(details, "Artifact URL", discovery.artifact_url);
      addDetail(details, "Evidence", discovery.evidence);
      container.append(details);
    }

    function renderRouteMetrics(container, metrics) {
      if (!Array.isArray(metrics) || !metrics.length) return;
      const details = node("details", null, "trace");
      details.append(node("summary", `Route metrics · ${metrics.length} phase${metrics.length === 1 ? "" : "s"}`));
      const list = node("ol");
      metrics.forEach(metric => {
        if (!metric || typeof metric !== "object" || Array.isArray(metric)) return;
        const entry = node("li");
        const headline = [metric.phase, metric.method, metric.outcome].filter(Boolean).join(" · ");
        entry.append(node("strong", headline || "Route phase"));
        const measurements = [
          metric.access_mode ? `access: ${metric.access_mode}` : null,
          metric.http_status !== undefined ? `HTTP ${metric.http_status}` : null,
          metric.request_count !== undefined ? `requests: ${metric.request_count}` : null,
          metric.redirect_count !== undefined ? `redirects: ${metric.redirect_count}` : null,
          metric.bytes !== undefined ? `bytes: ${metric.bytes}` : null,
          metric.elapsed_ms !== undefined ? `elapsed: ${metric.elapsed_ms} ms` : null
        ].filter(Boolean).join(" · ");
        if (measurements) entry.append(node("p", measurements, "meta"));
        addLabeledLink(entry, "URL", metric.url);
        list.append(entry);
      });
      details.append(list);
      container.append(details);
    }

    function renderSummary() {
      const target = document.getElementById("summary");
      target.replaceChildren();
      const counts = {all: manifest.items.length, attention: 0, retrieved: 0, failed: 0};
      manifest.items.forEach(item => counts[category(item)] += 1);
      [["All", counts.all], ["Needs attention", counts.attention], ["Retrieved", counts.retrieved], ["Failed", counts.failed]]
        .forEach(([label, count]) => target.append(node("span", `${label}: ${count}`, "pill")));
    }

    function renderTabs() {
      const target = document.getElementById("tabs");
      target.replaceChildren();
      [["attention", "Needs attention"], ["retrieved", "Retrieved"], ["failed", "Failed"], ["all", "All"]]
        .forEach(([value, label]) => {
          const button = node("button", label, activeTab === value ? "active" : "");
          button.type = "button";
          button.disabled = uiBusy;
          button.addEventListener("click", () => {
            if (uiBusy) {
              showMessage("Wait for the current operation to finish.", true);
              return;
            }
            activeTab = value;
            render();
          });
          target.append(button);
        });
    }

    function visibleItems() {
      return manifest.items.filter(item => activeTab === "all" || category(item) === activeTab);
    }

    function visibleAttentionItems() {
      return visibleItems().filter(item => category(item) === "attention");
    }

    function bulkTargets() {
      return visibleAttentionItems().filter(
        item => !item.pending_action && !dirtyItems.has(item.id)
      );
    }

    function renderBulkControls() {
      const visible = visibleAttentionItems();
      const targets = bulkTargets();
      const protectedCount = visible.length - targets.length;
      const count = document.getElementById("bulk-count");
      const select = document.getElementById("bulk-action");
      const stage = document.getElementById("bulk-stage");
      const preserved = protectedCount
        ? ` ${protectedCount} existing per-item decision or unsaved draft${protectedCount === 1 ? "" : "s"} will be preserved.`
        : "";
      count.textContent = `${visible.length} visible needs-attention item${visible.length === 1 ? "" : "s"}; ${targets.length} available for bulk staging.${preserved}`;
      select.disabled = uiBusy || visible.length === 0;
      stage.disabled = uiBusy || targets.length === 0 || !bulkActions.has(select.value);
    }

    function currentDecisionSelection(item) {
      const draft = drafts.get(item.id);
      const hasDraftCandidate = draft &&
        Object.prototype.hasOwnProperty.call(draft, "candidate_id");
      const hasDraftVersion = draft &&
        Object.prototype.hasOwnProperty.call(draft, "version_id");
      return {
        candidate_id: hasDraftCandidate
          ? draft.candidate_id
          : item.pending_action?.candidate_id ?? item.selected_candidate_id ?? null,
        version_id: hasDraftVersion
          ? draft.version_id
          : item.pending_action?.version_id ?? null
      };
    }

    function candidateReviewOptions(item) {
      if (!Array.isArray(item.candidate_review)) return [];
      return item.candidate_review.filter(option =>
        option &&
        typeof option === "object" &&
        typeof option.id === "string" &&
        typeof option.candidate_id === "string" &&
        typeof option.version_id === "string"
      );
    }

    function isReviewOptionSelected(item, option) {
      const selected = currentDecisionSelection(item);
      return selected.candidate_id === option.candidate_id &&
        selected.version_id === option.version_id;
    }

    function isCandidateSelected(item, candidate) {
      const selected = currentDecisionSelection(item);
      if (selected.candidate_id !== candidate.id) return false;
      return !candidateReviewOptions(item).some(
        option => isReviewOptionSelected(item, option)
      );
    }

    function radioDecisionSelection(radio) {
      if (!radio) return {candidate_id: null, version_id: null};
      return {
        candidate_id: radio.dataset.candidateId || radio.value || null,
        version_id: radio.dataset.versionId || null
      };
    }

    function renderCandidate(item, candidate) {
      const wrapper = node("label", null, "candidate");
      const radio = document.createElement("input");
      radio.type = "radio";
      radio.name = `candidate-${item.id}`;
      radio.value = candidate.id;
      radio.dataset.candidateId = candidate.id;
      radio.checked = isCandidateSelected(item, candidate);
      wrapper.append(radio);
      const body = node("div");
      body.append(node("strong", candidate.title || candidate.id));
      const metadata = [
        Array.isArray(candidate.authors) ? candidate.authors.join(", ") : candidate.authors,
        candidate.date || candidate.year,
        candidate.source_type,
        !candidate.peer_review_status && candidate.peer_reviewed === true ? "peer reviewed" : null
      ].filter(Boolean).join(" · ");
      if (metadata) body.append(node("p", metadata, "meta"));
      addDetail(body, "Relationship to request", candidate.relationship, "meta");
      addDetail(body, "Title match", candidate.title_match_type, "meta");
      addDetail(body, "Peer-review status", candidate.peer_review_status, "meta");
      addDetail(body, "Selection outcome", candidate.selection_outcome, "meta");
      addDetail(body, "Match evidence", candidate.match_evidence);
      if (candidate.rationale) body.append(node("p", candidate.rationale));
      addLink(body, "Open source", candidate.source_url);
      wrapper.append(body);
      return wrapper;
    }

    function renderCandidateReview(item, option) {
      const candidate = item.candidates?.find(
        value => value && value.id === option.candidate_id
      );
      const version = candidate?.versions?.find(
        value => value && value.id === option.version_id
      );
      const wrapper = node("label", null, "candidate candidate-review");
      const radio = document.createElement("input");
      radio.type = "radio";
      radio.name = `candidate-${item.id}`;
      radio.value = option.id;
      radio.dataset.candidateId = option.candidate_id;
      radio.dataset.versionId = option.version_id;
      radio.dataset.reviewOption = "true";
      radio.checked = isReviewOptionSelected(item, option);
      radio.disabled = !candidate || !version;
      radio.dataset.permanentlyDisabled = radio.disabled ? "true" : "false";
      wrapper.append(radio);

      const body = node("div");
      body.append(node("span", "Review-only alternative", "review-label"));
      body.append(node("strong", candidate?.title || option.candidate_id));
      addDetail(body, "Relationship to request", option.relationship || candidate?.relationship, "meta");
      addDetail(body, "Why review is required", option.review_reason);
      addDetail(body, "Version", version?.label || option.version_id, "meta");
      addDetail(body, "Disposition", option.disposition, "meta");
      if (!candidate || !version) {
        body.append(node("p", "This review option is incomplete and cannot be selected.", "failure"));
      } else {
        addLink(body, "Open review source", version.source_url || candidate.source_url);
      }
      wrapper.append(body);
      return wrapper;
    }

    function actionOptions(item) {
      const values = [
        ["retry", "Retry"],
        ["retry_authenticated", "Retry after sign-in"],
        ["retry_public", "Retry public sources only"],
        ["skip", "Skip"],
        ["stop_retrying", "Stop retrying"]
      ];
      if (item.candidates?.length) {
        values.unshift(["select_candidate", "Select candidate"]);
        if (item.match_type === "relevance" || item.status === "relevance_fallback") {
          values.unshift(["accept_fallback", "Accept relevance fallback"]);
        }
      }
      const existingType = item.pending_action?.type;
      if (existingType && !values.some(([value]) => value === existingType)) {
        values.unshift([existingType, `Existing action: ${existingType}`]);
      }
      return values;
    }

    async function saveDecision(item, select, textarea) {
      if (saveRequests > 0) {
        showMessage("Wait for the current item decision to finish saving.", true);
        return;
      }
      const candidate = document.querySelector(`input[name="candidate-${CSS.escape(item.id)}"]:checked`);
      const selection = radioDecisionSelection(candidate);
      const action = select.value;
      if (["select_candidate", "accept_fallback"].includes(action) && !candidate) {
        showMessage("Select a candidate before saving this action.", true);
        return;
      }
      saveRequests = 1;
      setDecisionControlsDisabled(true);
      try {
        const payload = await request(`api/items/${encodeURIComponent(item.id)}/decision`, {
          method: "POST",
          body: JSON.stringify({
            expected_revision: manifest.revision,
            action,
            candidate_id: selection.candidate_id,
            version_id: selection.version_id,
            comment: textarea.value
          })
        });
        manifest = payload.manifest;
        dirtyItems.delete(item.id);
        drafts.delete(item.id);
        showMessage(`Saved decision for ${item.id}.`);
        render();
      } catch (error) {
        showMessage(error.message, true);
      } finally {
        saveRequests = 0;
        setDecisionControlsDisabled(false);
      }
    }

    async function stageBulkDecision() {
      if (saveRequests > 0) {
        showMessage("Wait for the current item decision to finish saving.", true);
        return;
      }
      const select = document.getElementById("bulk-action");
      const action = select.value;
      if (!bulkActions.has(action)) {
        showMessage("Choose a bulk action first.", true);
        return;
      }
      const visible = visibleAttentionItems();
      const targets = bulkTargets();
      const protectedCount = visible.length - targets.length;
      if (!targets.length) {
        showMessage(
          "No visible needs-attention items are available; existing per-item decisions and drafts were preserved.",
          true
        );
        return;
      }
      const actionLabel = select.options[select.selectedIndex].textContent;
      const preservationNote = protectedCount
        ? ` ${protectedCount} existing per-item override${protectedCount === 1 ? "" : "s"} will be left unchanged.`
        : "";
      if (!window.confirm(
        `Stage “${actionLabel}” for ${targets.length} visible needs-attention item${targets.length === 1 ? "" : "s"}?${preservationNote} This only stages decisions; Apply decisions is still required.`
      )) {
        return;
      }

      saveRequests = 1;
      setDecisionControlsDisabled(true);
      let staged = 0;
      try {
        for (const item of targets) {
          const payload = await request(`api/items/${encodeURIComponent(item.id)}/decision`, {
            method: "POST",
            body: JSON.stringify({
              expected_revision: manifest.revision,
              action,
              candidate_id: null,
              version_id: null,
              comment: item.comment || ""
            })
          });
          manifest = payload.manifest;
          staged += 1;
          showMessage(`Staging bulk decisions: ${staged} of ${targets.length} saved…`);
        }
        showMessage(
          `Staged “${actionLabel}” for ${staged} item${staged === 1 ? "" : "s"}. Review or override individual items, then click Apply decisions.`
        );
      } catch (error) {
        showMessage(
          `Staged ${staged} of ${targets.length} items before saving stopped: ${error.message}. No batch action was submitted.`,
          true
        );
      } finally {
        saveRequests = 0;
        setDecisionControlsDisabled(false);
        render();
      }
    }

    function renderItem(item) {
      const kind = category(item);
      const card = node("article", null, `card ${kind}`);
      card.append(node("h2", item.requested_title));
      card.append(node("div", `${item.id} · ${item.status} · ${item.match_type}`, "meta"));
      addDetail(card, "Selection outcome", item.selection_outcome, "meta");
      addDetail(card, "Match evidence", item.match_evidence);
      const hasItemArtifactDiscovery = Object.prototype.hasOwnProperty.call(item, "artifact_discovery");
      const hasItemRouteMetrics = Object.prototype.hasOwnProperty.call(item, "route_metrics");
      renderArtifactDiscovery(card, item.artifact_discovery);
      renderRouteMetrics(card, item.route_metrics);

      if (item.status === "relevance_fallback" || item.match_type === "relevance") {
        card.append(node("div", "No exact match was verified. Any proposed source is a relevance fallback.", "notice"));
      }
      if (item.failure) {
        const message = typeof item.failure === "string" ? item.failure : item.failure.message || item.failure.code;
        const failure = node("div", message || "Retrieval failed.", "failure");
        card.append(failure);
      }
      if (item.status === "retrieved_verified" && item.result) {
        const result = node("div", null, "result");
        addLink(result, "Verified source", item.result.verified_url);
        if (item.result.local_path) result.append(node("p", `Local artifact: ${item.result.local_path}`));
        addDetail(result, "Peer-review status", item.result.peer_review_status, "meta");
        addDetail(result, "Selection outcome", item.result.selection_outcome, "meta");
        addDetail(result, "Match evidence", item.result.match_evidence);
        if (!hasItemArtifactDiscovery) {
          renderArtifactDiscovery(result, item.result.artifact_discovery);
        }
        if (!hasItemRouteMetrics) {
          renderRouteMetrics(result, item.result.route_metrics);
        }
        card.append(result);
      }
      if (item.candidates?.length) {
        card.append(node("h3", "Candidates"));
        item.candidates.forEach(candidate => card.append(renderCandidate(item, candidate)));
      }
      const reviewOptions = candidateReviewOptions(item);
      if (reviewOptions.length) {
        card.append(node("h3", "Review-only alternatives"));
        reviewOptions.forEach(option => card.append(renderCandidateReview(item, option)));
      }

      const controls = node("div", null, "decision");
      const select = document.createElement("select");
      const draft = drafts.get(item.id);
      const selectedAction = draft?.action ?? item.pending_action?.type;
      actionOptions(item).forEach(([value, label]) => {
        const option = node("option", label);
        option.value = value;
        option.selected = selectedAction === value;
        select.append(option);
      });
      const textarea = document.createElement("textarea");
      textarea.placeholder = "Optional comment or retry hint — never paste passwords, cookies, tokens, or one-time codes";
      textarea.value = draft?.comment ?? item.pending_action?.comment ?? item.comment ?? "";
      const save = node("button", item.pending_action ? "Update decision" : "Save decision");
      save.type = "button";
      save.addEventListener("click", () => saveDecision(item, select, textarea));
      controls.append(select, textarea, save);
      card.append(controls);
      const captureDraft = () => {
        const selected = card.querySelector('input[type="radio"]:checked');
        const selection = radioDecisionSelection(selected);
        drafts.set(item.id, {
          action: select.value,
          candidate_id: selection.candidate_id,
          version_id: selection.version_id,
          comment: textarea.value
        });
        dirtyItems.add(item.id);
      };
      select.addEventListener("change", captureDraft);
      textarea.addEventListener("input", captureDraft);
      card.querySelectorAll('input[type="radio"]').forEach(radio => {
        radio.addEventListener("change", () => {
          if (radio.checked && radio.dataset.reviewOption === "true") {
            select.value = "select_candidate";
          }
          captureDraft();
        });
      });
      return card;
    }

    function renderItems() {
      const target = document.getElementById("items");
      target.replaceChildren();
      const items = visibleItems();
      if (!items.length) {
        target.append(node("div", "No items in this view.", "empty"));
        return;
      }
      items.forEach(item => target.append(renderItem(item)));
    }

    function render() {
      renderSummary();
      renderTabs();
      renderItems();
      setDecisionControlsDisabled(uiBusy);
      renderBulkControls();
    }

    function showMessage(message, isError = false) {
      const target = document.getElementById("message");
      target.textContent = message;
      target.style.color = isError ? "#8a2020" : "#2d536d";
    }

    function setDecisionControlsDisabled(disabled) {
      uiBusy = disabled;
      document.querySelectorAll(
        '#tabs button, #bulk select, #bulk button, .candidate input, .decision select, .decision textarea, .decision button, #apply, #done'
      ).forEach(control => {
        control.disabled = disabled || control.dataset.permanentlyDisabled === "true";
      });
      if (manifest) renderBulkControls();
    }

    async function finish(action) {
      if (saveRequests > 0) {
        showMessage("Wait for item decisions to finish saving.", true);
        return;
      }
      if (dirtyItems.size > 0) {
        showMessage("Save every changed item decision before submitting the batch.", true);
        return;
      }
      setDecisionControlsDisabled(true);
      try {
        await request("api/batch", {
          method: "POST",
          body: JSON.stringify({action, expected_revision: manifest.revision})
        });
        showMessage(action === "apply"
          ? "Decisions submitted. The review server is stopping for the next retrieval round."
          : "Batch marked Done. The review server is stopping.");
      } catch (error) {
        showMessage(error.message, true);
        setDecisionControlsDisabled(false);
      }
    }

    document.getElementById("apply").addEventListener("click", () => finish("apply"));
    document.getElementById("done").addEventListener("click", () => finish("done"));
    document.getElementById("bulk-action").addEventListener("change", renderBulkControls);
    document.getElementById("bulk-stage").addEventListener("click", stageBulkDecision);

    request("api/manifest")
      .then(payload => { manifest = payload; render(); })
      .catch(error => showMessage(error.message, true));
  </script>
</body>
</html>
"""


def classify_item(item: dict[str, Any]) -> str:
    status = item.get("status")
    if status == "retrieved_verified":
        return "retrieved"
    if status in FAILED_STATUSES:
        return "failed"
    return "attention"


def display_value(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, list):
        values = [display_value(entry) for entry in value]
        rendered = [entry for entry in values if entry]
        return "; ".join(rendered) if rendered else None
    if isinstance(value, dict):
        try:
            return json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                allow_nan=False,
            )
        except (TypeError, ValueError):
            return None
    return str(value)


def render_detail(label: str, value: Any, class_name: str | None = None) -> str:
    rendered = display_value(value)
    if not rendered:
        return ""
    class_attribute = f' class="{html.escape(class_name, quote=True)}"' if class_name else ""
    return (
        f"<p{class_attribute}><strong>{html.escape(label)}:</strong> "
        f"{html.escape(rendered)}</p>"
    )


def render_labeled_http_link(label: str, value: Any) -> str:
    url = safe_http_url(value)
    if not url:
        return ""
    escaped_url = html.escape(url, quote=True)
    return (
        f"<p><strong>{html.escape(label)}:</strong> "
        f'<a href="{escaped_url}" rel="noopener noreferrer">{html.escape(url)}</a></p>'
    )


def render_artifact_discovery(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    method = display_value(value.get("method"))
    summary = "Artifact discovery" + (f" · {method}" if method else "")
    parts = [
        '<details class="trace">',
        f"<summary>{html.escape(summary)}</summary>",
        render_labeled_http_link("Discovered from", value.get("discovered_from")),
        render_labeled_http_link("Artifact URL", value.get("artifact_url")),
        render_detail("Evidence", value.get("evidence")),
        "</details>",
    ]
    return "".join(parts)


def render_route_metrics(value: Any) -> str:
    if not isinstance(value, list) or not value:
        return ""
    metrics = [metric for metric in value if isinstance(metric, dict)]
    if not metrics:
        return ""
    phase_label = "phase" if len(metrics) == 1 else "phases"
    parts = [
        '<details class="trace">',
        f"<summary>Route metrics · {len(metrics)} {phase_label}</summary><ol>",
    ]
    for metric in metrics:
        headline = " · ".join(
            str(entry)
            for entry in (
                metric.get("phase"),
                metric.get("method"),
                metric.get("outcome"),
            )
            if entry is not None and entry != ""
        ) or "Route phase"
        measurements = [
            f"access: {metric['access_mode']}" if metric.get("access_mode") else None,
            f"HTTP {metric['http_status']}" if "http_status" in metric else None,
            f"requests: {metric['request_count']}" if "request_count" in metric else None,
            f"redirects: {metric['redirect_count']}" if "redirect_count" in metric else None,
            f"bytes: {metric['bytes']}" if "bytes" in metric else None,
            f"elapsed: {metric['elapsed_ms']} ms" if "elapsed_ms" in metric else None,
        ]
        parts.append(f"<li><strong>{html.escape(headline)}</strong>")
        rendered_measurements = " · ".join(entry for entry in measurements if entry)
        if rendered_measurements:
            parts.append(f'<p class="meta">{html.escape(rendered_measurements)}</p>')
        parts.append(render_labeled_http_link("URL", metric.get("url")))
        parts.append("</li>")
    parts.append("</ol></details>")
    return "".join(parts)


def render_export(manifest: dict[str, Any]) -> str:
    items = manifest.get("items", [])
    counts = {"retrieved": 0, "attention": 0, "failed": 0}
    for item in items:
        counts[classify_item(item)] += 1

    sections: list[str] = []
    for item in items:
        item_class = classify_item(item)
        title = html.escape(str(item.get("requested_title", "")))
        item_id = html.escape(str(item.get("id", "")))
        status = html.escape(str(item.get("status", "")))
        match_type = html.escape(str(item.get("match_type", "")))
        parts = [
            f'<article class="card {item_class}">',
            f"<h2>{title}</h2>",
            f'<p class="meta">{item_id} · {status} · {match_type}</p>',
        ]
        parts.append(render_detail("Selection outcome", item.get("selection_outcome"), "meta"))
        parts.append(render_detail("Match evidence", item.get("match_evidence")))
        has_item_artifact_discovery = "artifact_discovery" in item
        has_item_route_metrics = "route_metrics" in item
        parts.append(render_artifact_discovery(item.get("artifact_discovery")))
        parts.append(render_route_metrics(item.get("route_metrics")))

        if item.get("match_type") == "relevance" or item.get("status") == "relevance_fallback":
            parts.append('<p class="notice">No exact match was verified; this result is a relevance fallback.</p>')

        result = item.get("result")
        if item.get("status") == "retrieved_verified" and isinstance(result, dict):
            parts.append('<div class="result">')
            verified_url = safe_http_url(result.get("verified_url"))
            if verified_url:
                escaped_url = html.escape(verified_url, quote=True)
                parts.append(
                    f'<a href="{escaped_url}" rel="noopener noreferrer">'
                    f"Verified source — {html.escape(verified_url)}</a>"
                )
            if result.get("local_path"):
                parts.append(f"<p>Local artifact: {html.escape(str(result['local_path']))}</p>")
            parts.append(
                render_detail("Peer-review status", result.get("peer_review_status"), "meta")
            )
            parts.append(render_detail("Selection outcome", result.get("selection_outcome"), "meta"))
            parts.append(render_detail("Match evidence", result.get("match_evidence")))
            if not has_item_artifact_discovery:
                parts.append(render_artifact_discovery(result.get("artifact_discovery")))
            if not has_item_route_metrics:
                parts.append(render_route_metrics(result.get("route_metrics")))
            parts.append("</div>")

        failure = item.get("failure")
        if failure:
            if isinstance(failure, dict):
                failure = failure.get("message") or failure.get("code") or "Retrieval failed"
            parts.append(f'<p class="failure">{html.escape(str(failure))}</p>')

        comment = item.get("comment")
        if comment:
            parts.append(f"<h3>Comment</h3><p>{html.escape(str(comment))}</p>")

        candidates = item.get("candidates")
        if isinstance(candidates, list) and candidates:
            parts.append("<details><summary>Candidates considered</summary><ul>")
            for candidate in candidates:
                if not isinstance(candidate, dict):
                    continue
                label = html.escape(str(candidate.get("title") or candidate.get("id") or "Candidate"))
                source_url = safe_http_url(candidate.get("source_url"))
                if source_url:
                    escaped_url = html.escape(source_url, quote=True)
                    hostname = html.escape(urlparse(source_url).hostname or "")
                    label = (
                        f'<a href="{escaped_url}" rel="noopener noreferrer">{label}</a>'
                        f' <span class="meta">({hostname})</span>'
                    )
                metadata = [
                    display_value(candidate.get("authors")),
                    display_value(candidate.get("date") or candidate.get("year")),
                    display_value(candidate.get("source_type")),
                ]
                peer_review_status = display_value(candidate.get("peer_review_status"))
                if not peer_review_status and candidate.get("peer_reviewed") is True:
                    metadata.append("peer reviewed")
                parts.append(f"<li>{label}")
                rendered_metadata = [entry for entry in metadata if entry]
                if rendered_metadata:
                    parts.append(
                        f'<p class="meta">{html.escape(" · ".join(rendered_metadata))}</p>'
                    )
                parts.append(
                    render_detail(
                        "Relationship to request",
                        candidate.get("relationship"),
                        "meta",
                    )
                )
                parts.append(
                    render_detail("Title match", candidate.get("title_match_type"), "meta")
                )
                parts.append(
                    render_detail("Peer-review status", peer_review_status, "meta")
                )
                parts.append(
                    render_detail("Selection outcome", candidate.get("selection_outcome"), "meta")
                )
                parts.append(render_detail("Match evidence", candidate.get("match_evidence")))
                parts.append("</li>")
            parts.append("</ul></details>")

        history = item.get("decision_history")
        if isinstance(history, list) and history:
            parts.append("<details><summary>Decision history</summary><ol>")
            for decision in history:
                if isinstance(decision, dict):
                    label = decision.get("type") or decision.get("action") or "decision"
                    timestamp = decision.get("recorded_at") or decision.get("applied_at") or ""
                    parts.append(
                        f"<li>{html.escape(str(label))}"
                        f"{' · ' + html.escape(str(timestamp)) if timestamp else ''}</li>"
                    )
            parts.append("</ol></details>")
        parts.append("</article>")
        sections.append("".join(parts))

    generated = html.escape(utc_now())
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Paper Finder Batch Report</title>
  <style>
    body {{ margin: 0; background: #f4f6f8; color: #18212b; font-family: ui-sans-serif, system-ui, sans-serif; }}
    header, main {{ max-width: 1000px; margin: 0 auto; padding: 22px; }}
    header {{ padding-bottom: 0; }}
    .summary {{ display: flex; gap: 8px; flex-wrap: wrap; }}
    .pill {{ background: white; border: 1px solid #d9e0e7; border-radius: 999px; padding: 7px 11px; }}
    .card {{ background: white; border: 1px solid #d9e0e7; border-left: 5px solid #c98513; border-radius: 10px; padding: 16px; margin-bottom: 14px; }}
    .card.retrieved {{ border-left-color: #27864b; }} .card.failed {{ border-left-color: #b44141; }}
    .card h2 {{ margin: 0 0 8px; font-size: 18px; }}
    .meta {{ color: #536575; }} a {{ color: #075f88; overflow-wrap: anywhere; }}
    .result {{ background: #e9f7ee; padding: 10px; border-radius: 8px; }}
    .trace {{ border: 1px solid #d5dee6; border-radius: 7px; padding: 7px 9px; margin: 8px 0; background: #f8fafb; }}
    .trace summary {{ cursor: pointer; font-weight: 600; }}
    .trace p {{ margin: 5px 0; }} .trace li {{ margin: 7px 0; }}
    .notice {{ background: #fff4d8; padding: 10px; border-radius: 8px; }}
    .failure {{ background: #fdeaea; color: #7d2525; padding: 10px; border-radius: 8px; }}
  </style>
</head>
<body>
  <header>
    <h1>Paper Finder Batch Report</h1>
    <p>Generated {generated}</p>
    <div class="summary">
      <span class="pill">Total: {len(items)}</span>
      <span class="pill">Retrieved: {counts['retrieved']}</span>
      <span class="pill">Needs attention: {counts['attention']}</span>
      <span class="pill">Failed: {counts['failed']}</span>
    </div>
  </header>
  <main>{''.join(sections)}</main>
</body>
</html>
"""


class ReviewServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        manifest_path: Path,
        manifest: dict[str, Any],
        token: str,
    ):
        super().__init__(address, ReviewHandler)
        self.manifest_path = manifest_path
        self.manifest = manifest
        self.token = token
        self.state_lock = threading.Lock()
        self.last_batch_action: str | None = None

    @property
    def route_prefix(self) -> str:
        return f"/{self.token}/"

    def require_current_revision(self, expected_revision: Any) -> None:
        current_revision = self.manifest.get("revision")
        if expected_revision != current_revision:
            raise ValueError(
                "the review data changed; reload the page before saving this decision"
            )
        disk_manifest = load_json(self.manifest_path)
        if (
            disk_manifest.get("revision") != current_revision
            or disk_manifest != self.manifest
        ):
            raise ValueError(
                "the manifest changed outside the review server; stop and reopen review"
            )


class ReviewHandler(BaseHTTPRequestHandler):
    server: ReviewServer

    def log_message(self, format_string: str, *args: Any) -> None:
        rendered = (format_string % args).replace(self.server.token, "<token>")
        print(
            f"[review] {diagnostic_text(self.address_string())} "
            f"{diagnostic_text(rendered)}"
        )

    def has_allowed_host(self) -> bool:
        return allowed_loopback_host_header(
            self.headers.get("Host"),
            int(self.server.server_address[1]),
        )

    def security_headers(self, content_type: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
            "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        )

    def send_bytes(self, status: int, content: bytes, content_type: str) -> None:
        self.send_response(status)
        self.security_headers(content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def send_json(self, status: int, payload: Any) -> None:
        content = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        self.send_bytes(status, content, "application/json; charset=utf-8")

    def route(self) -> str | None:
        parsed = urlparse(self.path)
        if not parsed.path.startswith(self.server.route_prefix):
            return None
        return parsed.path[len(self.server.route_prefix) :]

    def do_GET(self) -> None:
        if not self.has_allowed_host():
            self.send_json(421, {"error": "request host is not allowed"})
            return
        route = self.route()
        if route is None:
            self.send_json(404, {"error": "not found"})
            return
        if route in {"", "/"}:
            self.send_bytes(200, REVIEW_HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        if route == "api/manifest":
            with self.server.state_lock:
                manifest = copy.deepcopy(self.server.manifest)
            self.send_json(200, manifest)
            return
        self.send_json(404, {"error": "not found"})

    def read_request_json(self) -> dict[str, Any]:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise ValueError("Content-Type must be application/json")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid Content-Length") from exc
        if length <= 0 or length > MAX_REQUEST_BYTES:
            raise ValueError("request body size is invalid")
        origin = self.headers.get("Origin")
        if origin:
            parsed_origin = urlparse(origin)
            if parsed_origin.scheme != "http" or parsed_origin.netloc != self.headers.get("Host"):
                raise ValueError("cross-origin request rejected")
        try:
            value = json.loads(
                self.rfile.read(length),
                object_pairs_hook=reject_duplicate_json_keys,
                parse_constant=reject_nonfinite_json_constant,
            )
        except json.JSONDecodeError as exc:
            raise ValueError("request body must be valid JSON") from exc
        except RecursionError as exc:
            raise ValueError("request body JSON nesting is too deep") from exc
        if not isinstance(value, dict):
            raise ValueError("request body must be a JSON object")
        validate_json_tree(value)
        return value

    def do_POST(self) -> None:
        if not self.has_allowed_host():
            self.send_json(421, {"error": "request host is not allowed"})
            return
        route = self.route()
        if route is None:
            self.send_json(404, {"error": "not found"})
            return
        try:
            body = self.read_request_json()
            if route.startswith("api/items/") and route.endswith("/decision"):
                encoded_item_id = route[len("api/items/") : -len("/decision")]
                self.update_decision(unquote(encoded_item_id), body)
                return
            if route == "api/batch":
                self.update_batch(body)
                return
            self.send_json(404, {"error": "not found"})
        except ValueError as exc:
            self.send_json(400, {"error": str(exc)})
        except Exception as exc:
            print(
                "[review] unexpected server error: "
                f"{diagnostic_text(type(exc).__name__)}: {diagnostic_text(exc)}"
            )
            self.send_json(500, {"error": "unexpected server error"})

    def update_decision(self, item_id: str, body: dict[str, Any]) -> None:
        action = body.get("action")
        if action not in ACTIONS:
            raise ValueError("action is not supported by this review server")
        candidate_id = body.get("candidate_id")
        version_id = body.get("version_id")
        comment = body.get("comment", "")
        if candidate_id is not None and not isinstance(candidate_id, str):
            raise ValueError("candidate_id must be a string or null")
        if version_id is not None and not isinstance(version_id, str):
            raise ValueError("version_id must be a string or null")
        if not isinstance(comment, str):
            raise ValueError("comment must be a string")
        if len(comment) > 20_000:
            raise ValueError("comment exceeds 20,000 characters")
        reject_secrets({"comment": comment})

        with self.server.state_lock:
            self.server.require_current_revision(body.get("expected_revision"))
            manifest = copy.deepcopy(self.server.manifest)
            if manifest.get("done") or manifest.get("review_state") != "review_ready":
                raise ValueError("the review round is no longer accepting item decisions")
            item = next((entry for entry in manifest.get("items", []) if entry.get("id") == item_id), None)
            if item is None:
                raise ValueError(f"unknown item id: {item_id}")
            candidate_map = {
                candidate.get("id"): candidate
                for candidate in item.get("candidates", [])
                if isinstance(candidate, dict) and isinstance(candidate.get("id"), str)
            }
            candidate_ids = set(candidate_map)
            if action in {"select_candidate", "accept_fallback"}:
                if not candidate_id or candidate_id not in candidate_ids:
                    raise ValueError("this action requires a candidate from the item")
            elif candidate_id is not None and candidate_id not in candidate_ids:
                raise ValueError("candidate_id does not name a candidate on this item")
            if version_id is not None:
                if not candidate_id:
                    raise ValueError("version_id requires candidate_id")
                version_ids = {
                    version.get("id")
                    for version in candidate_map[candidate_id].get("versions", [])
                    if isinstance(version, dict)
                }
                if version_id not in version_ids:
                    raise ValueError("version_id does not name a version on this candidate")

            existing_action = item.get("pending_action")
            pending_action: dict[str, Any] = (
                dict(existing_action) if isinstance(existing_action, dict) else {}
            )
            pending_action["type"] = action
            pending_action["recorded_at"] = utc_now()
            if candidate_id is not None:
                pending_action["candidate_id"] = candidate_id
            else:
                pending_action.pop("candidate_id", None)
            if version_id is not None:
                pending_action["version_id"] = version_id
            else:
                pending_action.pop("version_id", None)
            item["comment"] = comment
            if comment:
                pending_action["comment"] = comment
            else:
                pending_action.pop("comment", None)
            item["pending_action"] = pending_action
            save_manifest(self.server.manifest_path, manifest)
            self.server.manifest = manifest
        self.send_json(200, {"manifest": manifest})

    def update_batch(self, body: dict[str, Any]) -> None:
        action = body.get("action")
        if action not in {"apply", "done"}:
            raise ValueError("batch action must be apply or done")
        with self.server.state_lock:
            self.server.require_current_revision(body.get("expected_revision"))
            manifest = copy.deepcopy(self.server.manifest)
            if manifest.get("done") or manifest.get("review_state") != "review_ready":
                raise ValueError("the review round is no longer accepting batch actions")
            if action == "apply":
                if not any(item.get("pending_action") for item in manifest.get("items", [])):
                    raise ValueError("record at least one item decision before applying")
                manifest["review_state"] = "submitted"
                manifest["done"] = False
            else:
                pending = [
                    item.get("id")
                    for item in manifest.get("items", [])
                    if item.get("pending_action")
                ]
                if pending:
                    raise ValueError(
                        "apply all pending decisions before Done: "
                        + ", ".join(str(item_id) for item_id in pending)
                    )
                unfinished = [
                    item.get("id")
                    for item in manifest.get("items", [])
                    if item.get("status") not in {"retrieved_verified", "not_found", "failed_final"}
                ]
                if unfinished:
                    raise ValueError(
                        "resolve, skip, or stop retrying all attention items before Done: "
                        + ", ".join(str(item_id) for item_id in unfinished)
                    )
                manifest["review_state"] = "done"
                manifest["done"] = True
            save_manifest(self.server.manifest_path, manifest)
            self.server.manifest = manifest
            self.server.last_batch_action = action
        self.send_json(200, {"ok": True, "action": action})
        threading.Thread(target=self.server.shutdown, daemon=True).start()


def cmd_init(args: argparse.Namespace) -> int:
    titles_path = Path(args.titles).resolve()
    manifest_path = Path(args.manifest).resolve()
    if titles_path == manifest_path:
        print_cli(
            "ERROR",
            "Title input and manifest output must be different files",
            error=True,
        )
        return 1
    if manifest_path.exists() and not args.force:
        print_cli(
            "ERROR",
            f"Refusing to overwrite existing manifest: {manifest_path}",
            error=True,
        )
        return 1
    try:
        manifest = new_manifest(read_titles(titles_path))
        save_manifest(manifest_path, manifest)
    except (OSError, ValueError) as exc:
        print_cli("ERROR", exc, error=True)
        return 1
    print_cli(
        "OK",
        f"Created {manifest_path} with {len(manifest['items'])} item(s)",
    )
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest).resolve()
    try:
        manifest = load_json(manifest_path)
        errors, warnings = validate_manifest(manifest, manifest_path)
    except (OSError, ValueError) as exc:
        print_cli("ERROR", exc, error=True)
        return 1
    print_validation(errors, warnings)
    return 1 if errors else 0


def cmd_export(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest).resolve()
    output_path = Path(args.output).resolve()
    if manifest_path == output_path:
        print_cli(
            "ERROR",
            "Manifest and HTML output must be different files",
            error=True,
        )
        return 1
    if output_path.exists() and not args.force:
        print_cli(
            "ERROR",
            f"Refusing to overwrite existing report output: {output_path}",
            error=True,
        )
        return 1
    try:
        manifest = load_json(manifest_path)
        errors, warnings = validate_manifest(manifest, manifest_path)
        print_validation(errors, warnings)
        if errors:
            return 1
        if not manifest.get("done"):
            print_cli(
                "ERROR",
                "Final HTML export requires a batch marked Done",
                error=True,
            )
            return 1
        artifact_paths = {
            resolve_local_path(manifest_path, str(item["result"]["local_path"])).resolve()
            for item in manifest.get("items", [])
            if isinstance(item, dict)
            and isinstance(item.get("result"), dict)
            and item["result"].get("local_path")
        }
        if output_path in artifact_paths:
            print_cli(
                "ERROR",
                "Refusing to overwrite a retrieved local artifact",
                error=True,
            )
            return 1
        atomic_write_text(output_path, render_export(manifest))
    except (OSError, ValueError) as exc:
        print_cli("ERROR", exc, error=True)
        return 1
    print_cli("OK", f"Exported {output_path}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest).resolve()
    if args.port < 0 or args.port > 65535:
        print_cli("ERROR", "Port must be between 0 and 65535", error=True)
        return 1
    try:
        manifest = load_json(manifest_path)
        errors, warnings = validate_manifest(manifest, manifest_path)
        print_validation(errors, warnings)
        if errors:
            return 1
        if manifest.get("done") and not args.reopen:
            print_cli(
                "ERROR",
                "Batch is already Done; pass --reopen to start another review round",
                error=True,
            )
            return 1
        unfinished = [
            item.get("id")
            for item in manifest.get("items", [])
            if item.get("status") in {"pending", "processing"}
        ]
        if unfinished:
            print_cli(
                "ERROR",
                "Finish the automated pass before review; unfinished items: "
                + ", ".join(str(item_id) for item_id in unfinished),
                error=True,
            )
            return 1
    except (OSError, ValueError) as exc:
        print_cli("ERROR", exc, error=True)
        return 1

    token = secrets.token_urlsafe(24)
    try:
        server = ReviewServer(
            ("127.0.0.1", args.port),
            manifest_path,
            manifest,
            token,
        )
    except (OSError, OverflowError) as exc:
        print_cli("ERROR", f"Could not start review server: {exc}", error=True)
        return 1
    try:
        manifest["done"] = False
        manifest["review_state"] = "review_ready"
        save_manifest(manifest_path, manifest)
    except (OSError, ValueError) as exc:
        server.server_close()
        print_cli("ERROR", f"Could not persist review state: {exc}", error=True)
        return 1
    host, port = server.server_address
    url = f"http://{host}:{port}/{token}/"
    print_cli("OK", f"Review interface: {url}", flush=True)
    print_cli(
        "INFO",
        "The server exits when the user applies decisions or clicks Done.",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print_cli(
            "INFO",
            "Review server stopped without submitting a batch action.",
        )
    finally:
        server.server_close()
    if server.last_batch_action:
        print_cli("OK", f"Batch action: {server.last_batch_action}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage paper-finder batch manifests and the consolidated review interface."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create a manifest from newline text or a JSON title list")
    init_parser.add_argument("titles", help="Input .txt or .json file containing titles")
    init_parser.add_argument("manifest", help="Output manifest.json path")
    init_parser.add_argument("--force", action="store_true", help="Overwrite an existing manifest")
    init_parser.set_defaults(function=cmd_init)

    validate_parser = subparsers.add_parser("validate", help="Validate manifest structure and artifacts")
    validate_parser.add_argument("manifest", help="Path to manifest.json")
    validate_parser.set_defaults(function=cmd_validate)

    serve_parser = subparsers.add_parser("serve", help="Run the localhost consolidated review interface")
    serve_parser.add_argument("manifest", help="Path to manifest.json")
    serve_parser.add_argument("--port", type=int, default=0, help="Local port; use 0 to choose an available port")
    serve_parser.add_argument("--reopen", action="store_true", help="Reopen a batch previously marked Done")
    serve_parser.set_defaults(function=cmd_serve)

    export_parser = subparsers.add_parser("export", help="Write a self-contained final HTML report")
    export_parser.add_argument("manifest", help="Path to manifest.json")
    export_parser.add_argument("output", help="Output .html path")
    export_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing report output (never overwrites a retrieved artifact)",
    )
    export_parser.set_defaults(function=cmd_export)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.function(args))


if __name__ == "__main__":
    raise SystemExit(main())
