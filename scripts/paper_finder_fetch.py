#!/usr/bin/env python3
"""Provider-neutral public artifact transfer and inert HTML capture.

This module deliberately starts from an evidence-declared URL.  It does not
discover, derive, or guess provider endpoints.  Network retrieval is limited to
credential-free HTTPS GET requests, and downloaded bytes remain in a caller-owned
quarantine directory until the batch validator accepts them.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import html
from html.parser import HTMLParser
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sys
import time
from typing import Any, Callable
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urldefrag, urljoin, urlparse

try:  # Imported as ``scripts.paper_finder_fetch``.
    from . import paper_finder_batch as batch
except ImportError:  # Executed directly from ``scripts/``.
    _batch_path = Path(__file__).with_name("paper_finder_batch.py")
    _batch_spec = importlib.util.spec_from_file_location(
        "_paper_finder_batch_for_fetch",
        _batch_path,
    )
    if _batch_spec is None or _batch_spec.loader is None:
        raise RuntimeError(f"Could not load {_batch_path}")
    batch = importlib.util.module_from_spec(_batch_spec)  # type: ignore[no-redef]
    _batch_spec.loader.exec_module(batch)


DEFAULT_TIMEOUT_SECONDS = 60.0
MAX_TIMEOUT_SECONDS = 300.0
DEFAULT_MAX_REDIRECTS = 5
MAX_REDIRECTS = 10
DEFAULT_MAX_DOWNLOAD_BYTES = batch.MAX_PDF_ARTIFACT_BYTES
READ_CHUNK_BYTES = 256 * 1024
SNIFF_BYTES = 8192
FIXED_REQUEST_HEADERS = {
    "Accept": "application/pdf, text/html;q=0.9, application/xhtml+xml;q=0.9",
    "Accept-Encoding": "identity",
    "User-Agent": "paper-finder-public-fetch/1",
}
REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}
DROP_WITH_CONTENT_TAGS = {
    "applet",
    "audio",
    "canvas",
    "embed",
    "iframe",
    "math",
    "noscript",
    "object",
    "picture",
    "script",
    "style",
    "svg",
    "template",
    "video",
}
HTMLISH_PREFIXES = (
    b"<!doctype html",
    b"<html",
    b"<head",
    b"<body",
    b"<main",
    b"<article",
    b"<section",
    b"<div",
    b"<p",
)
ARIA_ATTRIBUTE = re.compile(r"aria-[a-z0-9-]+\Z")


class FetchError(ValueError):
    """A bounded, non-secret public-transfer failure."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        elapsed_ms: int | None = None,
        observed_bytes: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.elapsed_ms = elapsed_ms
        self.observed_bytes = observed_bytes

    def as_result(self, operation: str = "download") -> dict[str, Any]:
        result: dict[str, Any] = {
            "ok": False,
            "operation": operation,
            "error": {"code": self.code, "message": str(self)},
        }
        if self.elapsed_ms is not None:
            result["elapsed_ms"] = self.elapsed_ms
        if self.observed_bytes is not None:
            result["observed_bytes"] = self.observed_bytes
        return result


def _elapsed_ms(started_at: float) -> int:
    return max(0, int((time.monotonic() - started_at) * 1000))


def _syntactically_safe_public_https_url(value: Any) -> str:
    """Return a safe public-hostname HTTPS URL without its client-side fragment.

    This first layer rejects credentials, signed parameters, IP literals,
    local/internal hostnames, and malformed hosts through the batch module's
    shared policy.  ``require_public_https_url`` applies the transport-aware DNS
    layer as well.
    """

    safe = batch.safe_http_url(value)
    if safe is None:
        raise FetchError(
            "unsafe_url",
            "artifact URL must be an unsigned, credential-free public-hostname HTTPS URL",
        )
    defragmented, _ = urldefrag(safe)
    if batch.safe_http_url(defragmented) is None:
        raise FetchError("unsafe_url", "artifact URL failed public HTTPS validation")
    return defragmented


def _target_uses_managed_proxy(url: str) -> bool:
    """Return whether stdlib HTTPS transport will actually proxy this target."""

    try:
        proxy = urlrequest.getproxies().get("https")
    except (AttributeError, OSError):
        return False
    if not isinstance(proxy, str) or not proxy.strip():
        return False
    candidate = proxy if "://" in proxy else "http://" + proxy
    try:
        parsed_proxy = urlparse(candidate)
        parsed_proxy.port
    except ValueError:
        raise FetchError(
            "unsafe_proxy",
            "configured HTTPS proxy is malformed or unsupported",
        ) from None
    if (
        parsed_proxy.scheme.casefold() not in {"http", "https"}
        or not parsed_proxy.hostname
        or parsed_proxy.username is not None
        or parsed_proxy.password is not None
        or parsed_proxy.query
        or parsed_proxy.fragment
        or parsed_proxy.path not in {"", "/"}
    ):
        raise FetchError(
            "unsafe_proxy",
            "configured HTTPS proxy is malformed, unsupported, or contains URL data",
        )
    hostname = urlparse(url).hostname
    if not hostname:
        return False
    try:
        return not urlrequest.proxy_bypass(hostname)
    except (OSError, ValueError):
        return False


def _resolve_global_sockaddrs(
    hostname: str,
    port: int,
) -> list[tuple[int, int, int, str, tuple[Any, ...]]]:
    """Resolve one hostname to vetted global socket addresses.

    Callers must connect to one of the returned socket addresses directly.  A
    second hostname lookup would reopen DNS-rebinding/TOCTOU risk.
    """

    try:
        answers = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except (socket.gaierror, OSError):
        raise FetchError("dns_error", "artifact hostname could not be resolved") from None
    addresses: set[str] = set()
    normalized_answers: list[tuple[int, int, int, str, tuple[Any, ...]]] = []
    for answer in answers:
        try:
            family, socktype, protocol, canonical_name, sockaddr = answer
            address = sockaddr[0].split("%", 1)[0]
        except (IndexError, TypeError, AttributeError):
            raise FetchError("dns_error", "artifact hostname resolution was malformed") from None
        addresses.add(address)
        normalized_answers.append(
            (family, socktype, protocol, canonical_name, tuple(sockaddr))
        )
    if not addresses:
        raise FetchError("dns_error", "artifact hostname returned no addresses")
    try:
        parsed_addresses = [ipaddress.ip_address(address) for address in addresses]
    except ValueError:
        raise FetchError("dns_error", "artifact hostname resolution was malformed") from None
    if any(not address.is_global for address in parsed_addresses):
        raise FetchError(
            "unsafe_target",
            "artifact hostname resolves to a non-global network target",
        )
    return normalized_answers


def _resolve_global_target(url: str) -> None:
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise FetchError("unsafe_url", "artifact URL has no valid public hostname")
    _resolve_global_sockaddrs(hostname, parsed.port or 443)


def _open_pinned_global_socket(
    hostname: str,
    port: int,
    timeout: Any,
    source_address: tuple[str, int] | None,
) -> socket.socket:
    """Connect directly to one vetted DNS answer without resolving again."""

    answers = _resolve_global_sockaddrs(hostname, port)
    last_error: OSError | None = None
    for family, socktype, protocol, _canonical_name, sockaddr in answers:
        candidate: socket.socket | None = None
        try:
            candidate = socket.socket(family, socktype, protocol)
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                candidate.settimeout(timeout)
            if source_address:
                candidate.bind(source_address)
            candidate.connect(sockaddr)
            candidate.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return candidate
        except OSError as exc:
            last_error = exc
            if candidate is not None:
                candidate.close()
    raise OSError("could not connect to a vetted public address") from last_error


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection whose direct socket uses the DNS answers just validated."""

    def connect(self) -> None:
        self.sock = _open_pinned_global_socket(
            self.host,
            self.port,
            self.timeout,
            self.source_address,
        )
        if self._tunnel_host:
            self._tunnel()
        server_hostname = self._tunnel_host or self.host
        self.sock = self._context.wrap_socket(
            self.sock,
            server_hostname=server_hostname,
        )


class PinnedHTTPSHandler(urlrequest.HTTPSHandler):
    """Pin direct HTTPS while leaving an explicitly configured proxy as transport."""

    def https_open(self, req: urlrequest.Request) -> Any:
        connection_class = (
            http.client.HTTPSConnection
            if req._tunnel_host
            else PinnedHTTPSConnection
        )
        return self.do_open(
            connection_class,
            req,
            context=self._context,
            check_hostname=self._check_hostname,
        )


def require_public_https_url(value: Any) -> str:
    """Validate an artifact URL for the transport that will fetch it.

    Direct connections resolve every target and reject any non-global answer.  If
    stdlib's configured HTTPS proxy will actually carry this target, target-side
    DNS is left to that managed transport; its synthetic proxy address is never
    treated as, or persisted as, an artifact target URL.
    """

    safe = _syntactically_safe_public_https_url(value)
    if not _target_uses_managed_proxy(safe):
        _resolve_global_target(safe)
    return safe


def _bounded_quarantine_path(quarantine_root: Path, output_relpath: str | Path) -> Path:
    root = Path(quarantine_root).expanduser()
    root.mkdir(parents=True, exist_ok=True)
    if not root.is_dir():
        raise FetchError("invalid_destination", "quarantine root is not a directory")
    root = root.resolve()

    relative = Path(output_relpath)
    if relative.is_absolute() or not relative.parts:
        raise FetchError(
            "invalid_destination",
            "artifact output must be a non-empty relative quarantine path",
        )
    if any(not batch.is_portable_path_component(part) for part in relative.parts):
        raise FetchError(
            "invalid_destination",
            "artifact output contains an unsafe or nonportable path component",
        )

    destination_name = relative.parts[-1]
    resolved_parent = root
    for component in relative.parts[:-1]:
        candidate_parent = resolved_parent / component
        try:
            # Create exactly one level. Never use parents=True here: an existing
            # symlink must be rejected before any deeper directory can be created.
            candidate_parent.mkdir(mode=0o700)
        except FileExistsError:
            pass
        except OSError:
            raise FetchError(
                "invalid_destination",
                "artifact output parent could not be created safely",
            ) from None
        try:
            if candidate_parent.is_symlink() or not candidate_parent.is_dir():
                raise FetchError(
                    "invalid_destination",
                    "artifact output parent must be a real quarantine directory",
                )
            candidate_parent = candidate_parent.resolve(strict=True)
        except (OSError, RuntimeError):
            raise FetchError(
                "invalid_destination",
                "artifact output parent could not be resolved safely",
            ) from None
        if not batch.is_relative_to(candidate_parent, root):
            raise FetchError(
                "invalid_destination",
                "artifact output must remain inside the quarantine root",
            )
        resolved_parent = candidate_parent

    destination = resolved_parent / destination_name
    if destination.is_symlink():
        raise FetchError(
            "invalid_destination",
            "artifact output must not replace a symbolic link",
        )
    if destination.exists():
        raise FetchError(
            "destination_exists",
            "artifact output already exists; choose a new quarantine path",
        )
    return destination


def _atomic_temp_path(destination: Path) -> tuple[int, Path]:
    temporary = destination.with_name(
        f".{destination.name}.{secrets.token_hex(8)}.part"
    )
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    return descriptor, temporary


def _commit_temporary(temporary: Path, destination: Path) -> None:
    """Publish one completed temporary file without replacing another entry."""

    os.chmod(temporary, 0o600)
    try:
        # The temporary file lives beside the destination, so a hard link is an
        # atomic no-replace publication on the same filesystem. A competing file
        # or symlink wins with EEXIST and remains untouched.
        os.link(temporary, destination, follow_symlinks=False)
    except FileExistsError:
        raise FetchError(
            "destination_exists",
            "artifact output already exists; choose a new quarantine path",
        ) from None
    except OSError:
        raise FetchError(
            "output_error",
            "artifact output could not be published safely",
        ) from None
    temporary.unlink()
    try:
        directory_fd = os.open(destination.parent, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _sniff_artifact(sample: bytes) -> str | None:
    if sample.startswith(b"%PDF-"):
        return "pdf"
    lowered = sample.lstrip(b"\xef\xbb\xbf\x00\x09\x0a\x0c\x0d\x20").lower()
    if lowered.startswith(HTMLISH_PREFIXES):
        return "html"
    # XML declarations and harmless leading prose occur in some rendered captures.
    if b"<html" in lowered[:SNIFF_BYTES] or b"<!doctype html" in lowered[:SNIFF_BYTES]:
        return "html"
    return None


def _safe_media_type(headers: Any) -> str | None:
    candidate = str(headers.get("Content-Type", "")).split(";", 1)[0]
    candidate = candidate.strip().casefold()
    if re.fullmatch(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+", candidate):
        return candidate[:128]
    return None


def _expected_format(expected_format: str, destination: Path) -> str | None:
    normalized = expected_format.strip().lower()
    if normalized not in {"auto", "pdf", "html"}:
        raise FetchError(
            "invalid_expected_format",
            "expected format must be auto, pdf, or html",
        )
    if normalized != "auto":
        return normalized
    if destination.suffix.casefold() == ".pdf":
        return "pdf"
    if destination.suffix.casefold() in {".html", ".htm"}:
        return "html"
    return None


class PublicRedirectHandler(urlrequest.HTTPRedirectHandler):
    """Follow only a bounded chain of validated public HTTPS redirects."""

    def __init__(self, max_redirects: int = DEFAULT_MAX_REDIRECTS) -> None:
        super().__init__()
        if not isinstance(max_redirects, int) or isinstance(max_redirects, bool):
            raise FetchError("invalid_redirect_limit", "redirect limit must be an integer")
        if not 0 <= max_redirects <= MAX_REDIRECTS:
            raise FetchError(
                "invalid_redirect_limit",
                f"redirect limit must be between 0 and {MAX_REDIRECTS}",
            )
        self.max_redirects = max_redirects
        self.redirect_count = 0

    def redirect_request(
        self,
        req: urlrequest.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urlrequest.Request | None:
        if code not in REDIRECT_STATUS_CODES:
            return None
        if self.redirect_count >= self.max_redirects:
            raise FetchError("redirect_limit", "public artifact redirect limit exceeded")
        target = require_public_https_url(urljoin(req.full_url, newurl))
        self.redirect_count += 1
        # Rebuild the request from fixed public headers.  In particular, do not
        # forward Cookie, Authorization, Referer, or caller-controlled headers.
        return urlrequest.Request(
            target,
            headers=FIXED_REQUEST_HEADERS,
            method="GET",
        )


OpenerFactory = Callable[[PublicRedirectHandler], Any]


def _default_opener_factory(redirect_handler: PublicRedirectHandler) -> Any:
    # ProxyHandler honors managed egress configuration.  No cookie jar or
    # authentication handler is installed, and response headers are never saved.
    return urlrequest.build_opener(
        urlrequest.ProxyHandler(),
        redirect_handler,
        PinnedHTTPSHandler(),
    )


def download_public_artifact(
    evidence_url: str,
    quarantine_root: str | Path,
    output_relpath: str | Path,
    *,
    expected_format: str = "auto",
    max_bytes: int = DEFAULT_MAX_DOWNLOAD_BYTES,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    opener_factory: OpenerFactory | None = None,
) -> dict[str, Any]:
    """Download one declared public artifact into a bounded quarantine path.

    The returned JSON-compatible measurement records only non-secret facts.  It
    is transfer evidence, not artifact identity/full-text verification.  In
    particular, downloaded HTML is a raw quarantined capture and must pass through
    ``sanitize_html_snapshot`` or ``sanitize_html_file`` before batch validation.
    """

    started_at = time.monotonic()
    url = require_public_https_url(evidence_url)
    if (
        not isinstance(max_bytes, int)
        or isinstance(max_bytes, bool)
        or not 1 <= max_bytes <= DEFAULT_MAX_DOWNLOAD_BYTES
    ):
        raise FetchError(
            "invalid_size_limit",
            f"download limit must be between 1 and {DEFAULT_MAX_DOWNLOAD_BYTES} bytes",
        )
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0 < float(timeout_seconds) <= MAX_TIMEOUT_SECONDS
    ):
        raise FetchError(
            "invalid_timeout",
            f"timeout must be greater than 0 and no more than {MAX_TIMEOUT_SECONDS} seconds",
        )

    destination = _bounded_quarantine_path(Path(quarantine_root), output_relpath)
    required_format = _expected_format(expected_format, destination)
    redirect_handler = PublicRedirectHandler(max_redirects)
    opener = (opener_factory or _default_opener_factory)(redirect_handler)
    request = urlrequest.Request(url, headers=FIXED_REQUEST_HEADERS, method="GET")
    temporary: Path | None = None
    observed_bytes = 0
    digest = hashlib.sha256()
    sample = bytearray()
    deadline = started_at + float(timeout_seconds)

    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FetchError("timeout", "public artifact transfer timed out")
        try:
            response_context = opener.open(request, timeout=remaining)
        except FetchError:
            raise
        except urlerror.HTTPError as exc:
            raise FetchError(
                "http_error",
                f"public artifact server returned HTTP {exc.code}",
                elapsed_ms=_elapsed_ms(started_at),
            ) from None
        except (urlerror.URLError, TimeoutError, OSError):
            raise FetchError(
                "network_error",
                "public artifact request failed",
                elapsed_ms=_elapsed_ms(started_at),
            ) from None

        with contextlib.closing(response_context) as response:
            status = getattr(response, "status", None)
            if status is None and hasattr(response, "getcode"):
                status = response.getcode()
            if status != 200:
                raise FetchError(
                    "http_status",
                    "public artifact response must be a complete HTTP 200 response",
                    elapsed_ms=_elapsed_ms(started_at),
                )

            final_url = require_public_https_url(response.geturl())
            headers = getattr(response, "headers", {})
            content_encoding = str(headers.get("Content-Encoding", "")).strip().casefold()
            if content_encoding and content_encoding != "identity":
                raise FetchError(
                    "encoded_response",
                    "public artifact response ignored the required identity encoding",
                    elapsed_ms=_elapsed_ms(started_at),
                )
            content_length = str(headers.get("Content-Length", "")).strip()
            if content_length:
                try:
                    declared_length = int(content_length, 10)
                except ValueError:
                    declared_length = None
                if declared_length is not None and declared_length > max_bytes:
                    raise FetchError(
                        "size_limit",
                        "public artifact exceeds the configured transfer limit",
                        elapsed_ms=_elapsed_ms(started_at),
                        observed_bytes=0,
                    )

            descriptor, temporary = _atomic_temp_path(destination)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    while True:
                        if time.monotonic() >= deadline:
                            raise FetchError(
                                "timeout",
                                "public artifact transfer timed out",
                                elapsed_ms=_elapsed_ms(started_at),
                                observed_bytes=observed_bytes,
                            )
                        chunk = response.read(
                            min(READ_CHUNK_BYTES, max_bytes - observed_bytes + 1)
                        )
                        if not chunk:
                            break
                        observed_bytes += len(chunk)
                        if observed_bytes > max_bytes:
                            raise FetchError(
                                "size_limit",
                                "public artifact exceeds the configured transfer limit",
                                elapsed_ms=_elapsed_ms(started_at),
                                observed_bytes=observed_bytes,
                            )
                        if len(sample) < SNIFF_BYTES:
                            sample.extend(chunk[: SNIFF_BYTES - len(sample)])
                        handle.write(chunk)
                        digest.update(chunk)
                    handle.flush()
                    os.fsync(handle.fileno())
            except Exception:
                # os.fdopen owns the descriptor once constructed.
                raise

            if observed_bytes == 0:
                raise FetchError(
                    "empty_response",
                    "public artifact response was empty",
                    elapsed_ms=_elapsed_ms(started_at),
                    observed_bytes=0,
                )
            sniffed_format = _sniff_artifact(bytes(sample))
            if sniffed_format is None:
                raise FetchError(
                    "unsupported_content",
                    "response bytes are not recognizable PDF or HTML",
                    elapsed_ms=_elapsed_ms(started_at),
                    observed_bytes=observed_bytes,
                )
            if required_format is not None and sniffed_format != required_format:
                raise FetchError(
                    "format_mismatch",
                    "response bytes do not match the expected artifact format",
                    elapsed_ms=_elapsed_ms(started_at),
                    observed_bytes=observed_bytes,
                )
            if sniffed_format == "html" and observed_bytes > batch.MAX_HTML_ARTIFACT_BYTES:
                raise FetchError(
                    "size_limit",
                    "HTML artifact exceeds the batch HTML limit",
                    elapsed_ms=_elapsed_ms(started_at),
                    observed_bytes=observed_bytes,
                )

        _commit_temporary(temporary, destination)
        temporary = None
        media_type = _safe_media_type(headers)
        return {
            "ok": True,
            "operation": "download",
            "requested_url": url,
            "final_url": final_url,
            "redirect_count": redirect_handler.redirect_count,
            "http_status": 200,
            "response_media_type": media_type,
            "format": sniffed_format,
            "bytes": observed_bytes,
            "sha256": digest.hexdigest(),
            "elapsed_ms": _elapsed_ms(started_at),
            "local_path": str(destination),
            "quarantined": True,
            "artifact_state": "raw_quarantine",
            "requires_sanitize_html": sniffed_format == "html",
            "verified": False,
        }
    finally:
        if temporary is not None:
            with contextlib.suppress(FileNotFoundError):
                temporary.unlink()


def _clean_text(value: str, *, fallback: str) -> str:
    cleaned = " ".join(value.replace("\x00", " ").split())
    return cleaned[: batch.MAX_HTML_ATTRIBUTE_CHARACTERS] or fallback


def _safe_body_attributes(
    tag: str,
    attrs: list[tuple[str, str | None]],
) -> list[tuple[str, str]]:
    allowed = batch.SAFE_GLOBAL_HTML_ATTRIBUTES | batch.SAFE_TAG_HTML_ATTRIBUTES.get(
        tag,
        set(),
    )
    safe: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw_name, raw_value in attrs[: batch.MAX_HTML_ATTRIBUTES_PER_ELEMENT]:
        name = raw_name.casefold()
        value = (raw_value or "").replace("\x00", "")
        if name in seen:
            continue
        seen.add(name)
        if len(name) > batch.MAX_HTML_ATTRIBUTE_CHARACTERS:
            continue
        if len(value) > batch.MAX_HTML_ATTRIBUTE_CHARACTERS:
            value = value[: batch.MAX_HTML_ATTRIBUTE_CHARACTERS]
        if name.startswith("on") or name == "style" or name in batch.RESOURCE_ATTRIBUTES:
            continue
        if name.endswith(":href") or "javascript:" in value.casefold():
            continue
        if name not in allowed and ARIA_ATTRIBUTE.fullmatch(name) is None:
            continue
        if tag == "a" and name == "href" and not value.startswith("#"):
            continue
        if tag != "a" and name in {"href", "rel"}:
            continue
        safe.append((name, value))
    return safe


class _InertHTMLSanitizer(HTMLParser):
    def __init__(self, supplied_title: str | None) -> None:
        super().__init__(convert_charrefs=True)
        self.supplied_title = supplied_title
        self.title_fragments: list[str] = []
        self.body_parts: list[str] = []
        self.frames: list[tuple[str, bool]] = []
        self.drop_stack: list[str] = []
        self.in_head = False
        self.in_title = False
        self.node_count = 0
        self.text_characters = 0

    def _bounded_node(self) -> None:
        self.node_count += 1
        if self.node_count > batch.MAX_HTML_NODES:
            raise ValueError(
                f"HTML source exceeds the {batch.MAX_HTML_NODES}-node limit"
            )

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self.handle_starttag(tag, attrs)
        if tag.casefold() not in batch.VOID_HTML_TAGS:
            self.handle_endtag(tag)

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self._bounded_node()
        normalized = tag.casefold()
        if self.drop_stack:
            if normalized in DROP_WITH_CONTENT_TAGS:
                self.drop_stack.append(normalized)
            return
        if normalized in DROP_WITH_CONTENT_TAGS:
            self.drop_stack.append(normalized)
            return
        if normalized == "head":
            self.in_head = True
            return
        if normalized == "body":
            self.in_head = False
            self.in_title = False
            return
        if normalized == "title":
            self.in_title = True
            return
        if normalized in {"html", "meta", "link", "base"} or self.in_head:
            return
        if normalized not in batch.INERT_HTML_TAGS:
            return
        if normalized in batch.VOID_HTML_TAGS:
            if normalized != "meta":
                self.body_parts.append(f"<{normalized}>")
            return

        emitted = sum(1 for _, is_emitted in self.frames if is_emitted)
        should_emit = emitted < batch.MAX_HTML_NESTING_DEPTH - 2
        self.frames.append((normalized, should_emit))
        if not should_emit:
            return
        safe_attrs = _safe_body_attributes(normalized, attrs)
        rendered_attrs = "".join(
            f' {name}="{html.escape(value, quote=True)}"'
            for name, value in safe_attrs
        )
        self.body_parts.append(f"<{normalized}{rendered_attrs}>")

    def handle_endtag(self, tag: str) -> None:
        normalized = tag.casefold()
        if self.drop_stack:
            if normalized in self.drop_stack:
                while self.drop_stack:
                    opened = self.drop_stack.pop()
                    if opened == normalized:
                        break
            return
        if normalized == "head":
            self.in_head = False
            return
        if normalized == "title":
            self.in_title = False
            return
        if normalized in {"html", "body", "meta", "link", "base"}:
            return
        matching_index = next(
            (
                index
                for index in range(len(self.frames) - 1, -1, -1)
                if self.frames[index][0] == normalized
            ),
            None,
        )
        if matching_index is None:
            return
        closing = self.frames[matching_index:]
        del self.frames[matching_index:]
        for opened, emitted in reversed(closing):
            if emitted:
                self.body_parts.append(f"</{opened}>")

    def handle_data(self, data: str) -> None:
        if self.drop_stack:
            return
        if self.in_title:
            self.title_fragments.append(data)
            return
        if self.in_head:
            return
        self.text_characters += len(data)
        if self.text_characters > batch.MAX_INERT_TEXT_CHARACTERS:
            raise ValueError(
                "HTML source exceeds the "
                f"{batch.MAX_INERT_TEXT_CHARACTERS}-character text limit"
            )
        self.body_parts.append(html.escape(data, quote=False))

    def finish(self) -> str:
        for opened, emitted in reversed(self.frames):
            if emitted:
                self.body_parts.append(f"</{opened}>")
        self.frames.clear()
        raw_title = self.supplied_title or "".join(self.title_fragments)
        title = _clean_text(raw_title, fallback="Captured source")
        csp = html.escape(batch.REQUIRED_INERT_CSP, quote=True)
        document = (
            "<!doctype html>\n"
            "<html><head>"
            '<meta charset="utf-8">'
            '<meta http-equiv="Content-Security-Policy" '
            f'content="{csp}">'
            f"<title>{html.escape(title, quote=False)}</title>"
            "</head><body>"
            + "".join(self.body_parts)
            + "</body></html>\n"
        )
        validator = batch.InertHTMLValidator()
        validator.feed(document)
        validator.close()
        validator.finish()
        if validator.violations:
            raise RuntimeError(
                "sanitizer produced an invalid inert snapshot: "
                + "; ".join(validator.violations[:5])
            )
        return document


def sanitize_html_snapshot(
    source: str | bytes,
    *,
    title: str | None = None,
    max_input_bytes: int = batch.MAX_HTML_ARTIFACT_BYTES,
) -> str:
    """Convert supplied raw or rendered-DOM HTML to the exact inert snapshot form."""

    if (
        not isinstance(max_input_bytes, int)
        or isinstance(max_input_bytes, bool)
        or not 1 <= max_input_bytes <= batch.MAX_HTML_ARTIFACT_BYTES
    ):
        raise ValueError(
            f"HTML input limit must be between 1 and {batch.MAX_HTML_ARTIFACT_BYTES} bytes"
        )
    if isinstance(source, bytes):
        if len(source) > max_input_bytes:
            raise ValueError("HTML input exceeds the configured byte limit")
        try:
            source_text = source.decode("utf-8-sig", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError("HTML input bytes must be UTF-8") from exc
    elif isinstance(source, str):
        if len(source.encode("utf-8")) > max_input_bytes:
            raise ValueError("HTML input exceeds the configured byte limit")
        source_text = source
    else:
        raise TypeError("HTML source must be str or bytes")
    if title is not None and not isinstance(title, str):
        raise TypeError("HTML title must be a string")

    sanitizer = _InertHTMLSanitizer(title)
    sanitizer.feed(source_text)
    sanitizer.close()
    document = sanitizer.finish()
    if len(document.encode("utf-8")) > batch.MAX_HTML_ARTIFACT_BYTES:
        raise ValueError("sanitized HTML exceeds the batch HTML artifact limit")
    return document


def sanitize_html_file(
    input_path: str | Path,
    quarantine_root: str | Path,
    output_relpath: str | Path,
    *,
    title: str | None = None,
    max_input_bytes: int = batch.MAX_HTML_ARTIFACT_BYTES,
) -> dict[str, Any]:
    """Sanitize a bounded local HTML capture and atomically quarantine the result."""

    started_at = time.monotonic()
    if (
        not isinstance(max_input_bytes, int)
        or isinstance(max_input_bytes, bool)
        or not 1 <= max_input_bytes <= batch.MAX_HTML_ARTIFACT_BYTES
    ):
        raise FetchError(
            "invalid_size_limit",
            "HTML input limit is outside the batch HTML artifact limit",
        )
    source_path = Path(input_path)
    try:
        with source_path.open("rb") as handle:
            source = handle.read(max_input_bytes + 1)
    except OSError as exc:
        raise FetchError("input_error", "could not read supplied HTML input") from exc
    if len(source) > max_input_bytes:
        raise FetchError("size_limit", "HTML input exceeds the configured byte limit")
    document = sanitize_html_snapshot(
        source,
        title=title,
        max_input_bytes=max_input_bytes,
    )
    encoded = document.encode("utf-8")
    destination = _bounded_quarantine_path(Path(quarantine_root), output_relpath)
    descriptor, temporary = _atomic_temp_path(destination)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        _commit_temporary(temporary, destination)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()
    return {
        "ok": True,
        "operation": "sanitize_html",
        "format": "html",
        "bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "elapsed_ms": _elapsed_ms(started_at),
        "local_path": str(destination),
        "quarantined": True,
        "sanitized_inert_snapshot": True,
        "verified": False,
    }


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Transfer declared public artifacts and sanitize HTML captures",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    download = subparsers.add_parser(
        "download",
        help="download one evidence-declared public HTTPS artifact",
    )
    download.add_argument("--url", required=True)
    download.add_argument("--quarantine-root", type=Path, required=True)
    download.add_argument("--output", required=True, help="relative quarantine path")
    download.add_argument(
        "--expected-format",
        choices=("auto", "pdf", "html"),
        default="auto",
    )
    download.add_argument(
        "--max-bytes",
        type=_positive_int,
        default=DEFAULT_MAX_DOWNLOAD_BYTES,
    )
    download.add_argument(
        "--timeout-seconds",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
    )
    download.add_argument(
        "--max-redirects",
        type=int,
        default=DEFAULT_MAX_REDIRECTS,
    )

    sanitize = subparsers.add_parser(
        "sanitize-html",
        help="sanitize supplied raw or rendered-DOM HTML",
    )
    sanitize.add_argument("--input", type=Path, required=True)
    sanitize.add_argument("--quarantine-root", type=Path, required=True)
    sanitize.add_argument("--output", required=True, help="relative quarantine path")
    sanitize.add_argument("--title")
    sanitize.add_argument(
        "--max-input-bytes",
        type=_positive_int,
        default=batch.MAX_HTML_ARTIFACT_BYTES,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "download":
            result = download_public_artifact(
                args.url,
                args.quarantine_root,
                args.output,
                expected_format=args.expected_format,
                max_bytes=args.max_bytes,
                timeout_seconds=args.timeout_seconds,
                max_redirects=args.max_redirects,
            )
        else:
            result = sanitize_html_file(
                args.input,
                args.quarantine_root,
                args.output,
                title=args.title,
                max_input_bytes=args.max_input_bytes,
            )
    except FetchError as exc:
        result = exc.as_result(args.command)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 2
    except (TypeError, ValueError) as exc:
        result = {
            "ok": False,
            "operation": args.command,
            "error": {"code": "invalid_input", "message": str(exc)},
        }
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 2
    except Exception:
        # Malicious parser input or an unexpected local I/O failure must not turn
        # into a traceback (which can disclose paths or untrusted source text).
        result = {
            "ok": False,
            "operation": args.command,
            "error": {
                "code": "internal_error",
                "message": "operation failed without producing an artifact",
            },
        }
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
