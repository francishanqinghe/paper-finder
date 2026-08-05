from __future__ import annotations

import copy
import contextlib
import hashlib
import http.client
import importlib.util
import io
import json
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "paper_finder_batch.py"


def load_batch_module():
    spec = importlib.util.spec_from_file_location(
        "paper_finder_batch_security",
        SCRIPT_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load {SCRIPT_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SecurityBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.batch = load_batch_module()

    def verified_fixture(
        self,
        directory: Path,
        *,
        artifact_name: str = "example.html",
    ) -> tuple[dict, Path, Path]:
        manifest_path = directory / "manifest.json"
        papers = directory / "papers"
        papers.mkdir(parents=True)
        artifact_path = papers / artifact_name
        artifact = (
            "<!doctype html>\n"
            '<html lang="en"><head>'
            '<meta charset="utf-8">'
            '<meta http-equiv="Content-Security-Policy" '
            'content="default-src \'none\'; base-uri \'none\'; form-action \'none\'">'
            "<title>Example research title</title>"
            "</head><body><article><h1>Example research title</h1>"
            "<p>Complete selected source text for the verified work. This sanitized "
            "snapshot preserves the full abstract or article body needed for review, "
            "including its methods, results, conclusions, and bibliographic context. "
            "It contains enough independently inspectable text to distinguish a real "
            "source from a citation-only, login, challenge, or error page.</p>"
            "</article></body></html>\n"
        ).encode("utf-8")
        artifact_path.write_bytes(artifact)
        digest = hashlib.sha256(artifact).hexdigest()

        manifest = self.batch.new_manifest(["Example research title"])
        item = manifest["items"][0]
        item.update(
            {
                "status": "retrieved_verified",
                "match_type": "exact",
                "selected_candidate_id": "candidate-1",
                "candidates": [
                    {
                        "id": "candidate-1",
                        "title": "Example research title",
                        "source_url": "https://publisher.example/article",
                        "relationship": "title_match",
                        "title_match_type": "verbatim",
                    }
                ],
                "artifact_discovery": {
                    "method": "download_link",
                    "discovered_from": "https://publisher.example/article",
                    "artifact_url": "https://publisher.example/article.html",
                    "evidence": "Observed publisher download link.",
                },
                "route_metrics": [
                    {
                        "phase": "verification",
                        "method": "local_integrity_check",
                        "outcome": "passed",
                        "bytes": len(artifact),
                    }
                ],
                "result": {
                    "selected_candidate_id": "candidate-1",
                    "format": "html",
                    "verified_url": "https://publisher.example/article",
                    "retrieval_url": "https://publisher.example/article.html",
                    "local_path": f"papers/{artifact_name}",
                    "verification_summary": {
                        "bytes": len(artifact),
                        "sha256": digest,
                        "identity_verified": True,
                        "full_text_verified": True,
                        "artifact_integrity_verified": True,
                        "observed_title": "Example research title",
                        "verification_method": "title_and_source_inspection",
                        "identity_evidence": "The saved heading and publisher record agree.",
                        "full_text_evidence": "The complete selected source is present.",
                        "verified_at": "2026-08-05T00:00:00Z",
                        "sanitized_inert_snapshot": True,
                    },
                    "provenance": {
                        "method": "publisher_download_link",
                        "source_role": "publisher",
                    },
                },
            }
        )
        state = manifest["operations_v2"]
        request = state["requests"][0]
        work = state["works"][0]
        artifact_id = "artifact-000001"
        state["artifacts"] = [
            {
                "id": artifact_id,
                "work_id": work["id"],
                "version_id": work["version_ids"][0],
                "provider_origin": "https://publisher.example",
                "format": "html",
                "verified_url": item["result"]["verified_url"],
                "local_relpath": item["result"]["local_path"],
                "bytes": len(artifact),
                "sha256": digest,
                "status": "verified",
            }
        ]
        request.update(
            status="retrieved",
            artifact_id=artifact_id,
            selected_candidate_id="candidate-1",
        )
        work["status"] = "retrieved"
        return manifest, manifest_path, artifact_path

    def mark_v2_failed(self, manifest: dict, *, review_status: str | None = None) -> None:
        state = manifest["operations_v2"]
        state["requests"][0].update(status="failed", artifact_id=None)
        state["works"][0]["status"] = "failed"
        if review_status is not None:
            state["status"] = review_status

    def review_ready_failure_manifest(self) -> dict:
        manifest = self.batch.new_manifest(["Unavailable source"])
        manifest["items"][0].update(
            status="failed_final",
            failure={
                "code": "not_found",
                "message": "No legitimate source was found.",
                "retryable": False,
            },
        )
        manifest["review_state"] = "review_ready"
        self.mark_v2_failed(manifest, review_status="review")
        return manifest

    def post_review_action(
        self,
        manifest: dict,
        manifest_path: Path,
        route: str,
        body: dict,
    ) -> tuple[int, dict]:
        server = self.batch.ReviewServer(
            ("127.0.0.1", 0),
            manifest_path,
            manifest,
            "test-route-token",
        )
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.start()
        try:
            port = int(server.server_address[1])
            request_body = dict(body)
            request_body["expected_revision"] = manifest["revision"]
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                connection.request(
                    "POST",
                    f"/test-route-token/{route}",
                    body=json.dumps(request_body),
                    headers={
                        "Host": f"127.0.0.1:{port}",
                        "Content-Type": "application/json",
                    },
                )
                response = connection.getresponse()
                payload = json.loads(response.read().decode("utf-8"))
                return response.status, payload
            finally:
                connection.close()
        finally:
            server.shutdown()
            server_thread.join(timeout=5)
            server.server_close()

    def post_batch_action(
        self,
        manifest: dict,
        manifest_path: Path,
        action: str,
    ) -> tuple[int, dict]:
        return self.post_review_action(
            manifest,
            manifest_path,
            "api/batch",
            {"action": action},
        )

    def make_test_pdf(self, title: str) -> bytes:
        lines = [
            title,
            "This complete test source contains methods, results, and conclusions.",
            "It also preserves bibliographic context and independently inspectable text.",
            "The bounded extraction check can distinguish it from an error or login page.",
            "It is not a citation, access challenge, or fabricated boundary-byte placeholder.",
        ]
        commands = ["BT /F1 12 Tf 72 720 Td"]
        for index, line in enumerate(lines):
            escaped = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            if index:
                commands.append("0 -18 Td")
            commands.append(f"({escaped}) Tj")
        commands.append("ET")
        stream = (" ".join(commands) + "\n").encode("latin-1")
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            (
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"
            ),
            b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n"
            + stream
            + b"endstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        ]
        document = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for index, value in enumerate(objects, start=1):
            offsets.append(len(document))
            document.extend(f"{index} 0 obj\n".encode("ascii"))
            document.extend(value)
            document.extend(b"\nendobj\n")
        if len(document) < 1100:
            document.extend(b" " * (1100 - len(document)))
        xref_offset = len(document)
        document.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
        document.extend(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            document.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
        document.extend(
            (
                f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
                f"startxref\n{xref_offset}\n%%EOF\n"
            ).encode("ascii")
        )
        return bytes(document)

    def make_incremental_test_pdf(
        self,
        title: str,
        *,
        inter_revision_payload: bytes = b"",
    ) -> bytes:
        original = self.make_test_pdf(title)
        previous = re.search(rb"startxref\s+([0-9]+)\s+%%EOF\s*\Z", original)
        self.assertIsNotNone(previous)
        object_offset = len(original) + len(inter_revision_payload)
        update_object = b"6 0 obj\n<< /Producer (bounded test update) >>\nendobj\n"
        xref_offset = object_offset + len(update_object)
        return (
            original
            + inter_revision_payload
            + update_object
            + b"xref\n6 1\n"
            + f"{object_offset:010d} 00000 n \n".encode("ascii")
            + b"trailer\n<< /Size 7 /Root 1 0 R /Prev "
            + previous.group(1)
            + b" >>\nstartxref\n"
            + str(xref_offset).encode("ascii")
            + b"\n%%EOF\n"
        )

    def make_xref_stream_test_pdf(
        self,
        title: str,
        *,
        first_object_offset_delta: int = 0,
    ) -> bytes:
        traditional = self.make_test_pdf(title)
        terminal = re.search(
            rb"startxref\s+([0-9]+)\s+%%EOF\s*\Z",
            traditional,
        )
        self.assertIsNotNone(terminal)
        xref_offset = int(terminal.group(1))
        prefix = traditional[:xref_offset]
        offsets = [0]
        for object_number in range(1, 6):
            offset = prefix.find(f"{object_number} 0 obj\n".encode("ascii"))
            self.assertGreater(offset, 0)
            offsets.append(offset)
        offsets[1] += first_object_offset_delta
        entries = [b"\x00" + (0).to_bytes(4, "big") + (65_535).to_bytes(2, "big")]
        entries.extend(
            b"\x01" + offset.to_bytes(4, "big") + (0).to_bytes(2, "big")
            for offset in offsets[1:]
        )
        entries.append(
            b"\x01" + xref_offset.to_bytes(4, "big") + (0).to_bytes(2, "big")
        )
        stream = b"".join(entries)
        return (
            prefix
            + b"6 0 obj\n<< /Type /XRef /Size 7 /Root 1 0 R "
            + b"/W [1 4 2] /Index [0 7] /Length "
            + str(len(stream)).encode("ascii")
            + b" >>\nstream\n"
            + stream
            + b"\nendstream\nendobj\nstartxref\n"
            + str(xref_offset).encode("ascii")
            + b"\n%%EOF\n"
        )

    def test_valid_verified_artifact_passes_strict_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest, manifest_path, _ = self.verified_fixture(Path(temporary))
            errors, warnings = self.batch.validate_manifest(manifest, manifest_path)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])

    def test_verified_artifact_rejects_traversal_and_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest, manifest_path, _ = self.verified_fixture(Path(temporary))
            manifest["items"][0]["result"]["local_path"] = "../outside.html"
            errors, _ = self.batch.validate_manifest(manifest, manifest_path)
            self.assertTrue(any("under papers/" in error for error in errors))

            manifest, manifest_path, _ = self.verified_fixture(
                Path(temporary) / "second"
            )
            manifest["items"][0]["result"]["verification_summary"]["sha256"] = "0" * 64
            errors, _ = self.batch.validate_manifest(manifest, manifest_path)
            self.assertTrue(any("SHA-256 differs" in error for error in errors))

    def test_verified_artifact_rejects_symbolic_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest, manifest_path, artifact_path = self.verified_fixture(directory)
            target = directory / "outside.html"
            artifact_path.replace(target)
            try:
                artifact_path.symlink_to(target)
            except OSError as exc:
                self.skipTest(f"Symbolic links are unavailable: {exc}")
            errors, _ = self.batch.validate_manifest(manifest, manifest_path)
        self.assertTrue(any("symbolic link" in error for error in errors))

    def test_secret_material_is_rejected_before_persistence(self) -> None:
        manifest = self.batch.new_manifest(["Example title"])
        manifest["items"][0]["comment"] = (
            "Authorization: Bearer " + "github" + "_pat_" + "a" * 32
        )
        errors, _ = self.batch.validate_manifest(
            manifest,
            Path("/tmp/paper-finder-test/manifest.json"),
        )
        self.assertTrue(any("credential- or token-like" in error for error in errors))
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "Refusing to store"):
                self.batch.save_manifest(Path(temporary) / "manifest.json", manifest)

    def test_secret_scanner_catches_common_key_and_url_variants(self) -> None:
        secret_values = [
            {"authToken": "abcdefghijk"},
            {"clientSecret": "abcdefghijk"},
            {"id_token": "abcdefghijk"},
            {"one_time_code": "12345678"},
            {"session_id": "abcdefghijk"},
            {"x-api-key": "abcdefghijk"},
            {
                "comment": "Bearer "
                + "eyJ"
                + "abcdefgh.eyJijklmnop.qrstuvwxyz"
            },
            {"comment": "xox" + "b-1234567890-abcdefghijklmnop"},
            {"comment": "sk_" + "live_abcdefghijklmnop"},
            {
                "url": "https://publisher.example/file?"
                + "X-Amz-"
                + "Credential=abc&X-Amz-"
                + "Signature=def"
            },
            {"url": "https://publisher.example/callback?code=abcdefghijk"},
            {"url": "https://publisher.example/file?sig=abcdefghijk"},
            {
                "url": "https://publisher.example/file?hdnea="
                + "exp=1999999999~acl=/*~hmac="
                + "c" * 64
            },
            {
                "url": "https://publisher.example/file?hdnts="
                + "st=1700000000~exp=1999999999~hmac="
                + "d" * 64
            },
        ]
        for value in secret_values:
            with self.subTest(value=value):
                self.assertTrue(self.batch.secret_locations(value))
        self.assertEqual(
            self.batch.secret_locations({"failure": {"code": "not_found"}}),
            [],
        )

    def test_browser_and_header_state_keys_are_rejected_without_echoing(self) -> None:
        secret_keys = (
            "session",
            "sid",
            "jsessionid",
            "phpsessid",
            "ASP.NET_SessionId",
            "publisher_cookie",
            "provider_authorization",
            "browser_session_id",
            "browser_id",
            "browser_profile_id",
            "profile_id",
            "browser_state",
            "session_state",
            "session_url",
            "headers",
            "raw_headers",
            "request_headers",
            "response_headers",
            "browserSessionId",
            "browserRuntimeIdentifier",
            "profileRuntimeState",
            "sessionRedirectUrl",
            "publisherBrowserIdentifier",
            "providerProfileUrl",
            "originSessionState",
        )
        secret_value = "opaque-private-state"
        for key in secret_keys:
            with self.subTest(key=key):
                manifest = self.batch.new_manifest(["Example title"])
                manifest[key] = secret_value
                locations = self.batch.secret_locations(manifest)
                self.assertTrue(locations)
                self.assertNotIn(key, "\n".join(locations))
                errors, _ = self.batch.validate_manifest(
                    manifest,
                    Path("/tmp/paper-finder-test/manifest.json"),
                )
                rendered_errors = "\n".join(errors)
                self.assertIn("credential- or token-like", rendered_errors)
                self.assertNotIn(key, rendered_errors)
                self.assertNotIn(secret_value, rendered_errors)
                with tempfile.TemporaryDirectory() as temporary:
                    with self.assertRaises(ValueError) as raised:
                        self.batch.save_manifest(
                            Path(temporary) / "manifest.json",
                            manifest,
                        )
                rendered_exception = str(raised.exception)
                self.assertNotIn(key, rendered_exception)
                self.assertNotIn(secret_value, rendered_exception)

    def test_secret_key_text_is_rejected_even_with_a_null_value(self) -> None:
        secret_markers = (
            "headers",
            "Authorization: Bearer " + "private-token-material",
            "https://publisher.example/callback?code=private-token-material",
        )
        for secret_key in secret_markers:
            with self.subTest(secret_key=secret_key):
                manifest = self.batch.new_manifest(["Example title"])
                manifest[secret_key] = None
                locations = self.batch.secret_locations(manifest)
                self.assertTrue(locations)
                self.assertNotIn(secret_key, "\n".join(locations))
                errors, _ = self.batch.validate_manifest(
                    manifest,
                    Path("/tmp/paper-finder-test/manifest.json"),
                )
                rendered = "\n".join(errors)
                self.assertIn("credential- or token-like", rendered)
                self.assertNotIn(secret_key, rendered)

    def test_session_and_semicolon_url_secrets_are_rejected_without_echoing(self) -> None:
        marker = "private-session-marker"
        secret_urls = {
            "path-jsessionid": (
                f"https://publisher.example/article;jsessionid={marker}"
            ),
            "semicolon-signature": (
                f"https://publisher.example/article?ok=1;sig={marker}"
            ),
            "jsessionid": f"https://publisher.example/article?JSESSIONID={marker}",
            "phpsessid": f"https://publisher.example/article?PHPSESSID={marker}",
            "aspnet-session": (
                f"https://publisher.example/article?ASP.NET_SessionId={marker}"
            ),
            "sid": f"https://publisher.example/article?sid={marker}",
            "session": f"https://publisher.example/article?session={marker}",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for label, secret_url in secret_urls.items():
                with self.subTest(label=label):
                    directory = root / label
                    directory.mkdir()
                    manifest, manifest_path, _ = self.verified_fixture(directory)
                    item = manifest["items"][0]
                    item["candidates"][0]["source_url"] = secret_url
                    item["artifact_discovery"].update(
                        discovered_from=secret_url,
                        artifact_url=secret_url,
                    )
                    item["result"].update(
                        verified_url=secret_url,
                        retrieval_url=secret_url,
                    )
                    manifest["operations_v2"]["artifacts"][0][
                        "verified_url"
                    ] = secret_url

                    locations = self.batch.secret_locations(manifest)
                    self.assertTrue(locations)
                    rendered_locations = "\n".join(locations)
                    self.assertNotIn(secret_url, rendered_locations)
                    self.assertNotIn(marker, rendered_locations)
                    errors, _ = self.batch.validate_manifest(manifest, manifest_path)
                    rendered_errors = "\n".join(errors)
                    self.assertIn("credential- or token-like", rendered_errors)
                    self.assertNotIn(secret_url, rendered_errors)
                    self.assertNotIn(marker, rendered_errors)
                    with self.assertRaises(ValueError) as raised:
                        self.batch.save_manifest(manifest_path, manifest)
                    rendered_exception = str(raised.exception)
                    self.assertNotIn(secret_url, rendered_exception)
                    self.assertNotIn(marker, rendered_exception)

    def test_unknown_and_overlong_mapping_keys_are_not_echoed(self) -> None:
        unknown_key = "unexpected_private_marker_field"
        manifest = self.batch.new_manifest(["Example title"])
        manifest["operations_v2"][unknown_key] = "benign"
        errors, _ = self.batch.validate_manifest(
            manifest,
            Path("/tmp/paper-finder-test/manifest.json"),
        )
        rendered = "\n".join(errors)
        self.assertIn("unknown fields", rendered)
        self.assertNotIn(unknown_key, rendered)

        overlong_marker = "OVERLONG_PRIVATE_MARKER"
        overlong_key = overlong_marker + "x" * self.batch.MAX_JSON_KEY_CHARACTERS
        manifest = self.batch.new_manifest(["Example title"])
        manifest[overlong_key] = "benign"
        errors, _ = self.batch.validate_manifest(
            manifest,
            Path("/tmp/paper-finder-test/manifest.json"),
        )
        rendered = "\n".join(errors)
        self.assertTrue(errors)
        self.assertNotIn(overlong_marker, rendered)

    def test_wrong_json_value_types_fail_closed_in_api_and_cli(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest, manifest_path, _ = self.verified_fixture(directory)
            paths = {
                "root review_state": ("review_state",),
                "item status": ("items", 0, "status"),
                "item match_type": ("items", 0, "match_type"),
                "selected candidate": ("items", 0, "selected_candidate_id"),
                "candidate relationship": (
                    "items",
                    0,
                    "candidates",
                    0,
                    "relationship",
                ),
                "candidate title match": (
                    "items",
                    0,
                    "candidates",
                    0,
                    "title_match_type",
                ),
                "artifact discovery method": (
                    "items",
                    0,
                    "artifact_discovery",
                    "method",
                ),
                "result format": ("items", 0, "result", "format"),
            }
            for label, path_parts in paths.items():
                with self.subTest(label=label):
                    malformed = copy.deepcopy(manifest)
                    target = malformed
                    for part in path_parts[:-1]:
                        target = target[part]
                    target[path_parts[-1]] = {}
                    errors, _ = self.batch.validate_manifest(
                        malformed,
                        manifest_path,
                    )
                    self.assertTrue(errors)

                    manifest_path.write_text(
                        json.dumps(malformed),
                        encoding="utf-8",
                    )
                    completed = subprocess.run(
                        [
                            sys.executable,
                            str(SCRIPT_PATH),
                            "validate",
                            str(manifest_path),
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(completed.returncode, 1)
                    combined_output = completed.stdout + completed.stderr
                    self.assertNotIn("Traceback", combined_output)
                    self.assertNotIn("unhashable type", combined_output)

    def test_json_loader_rejects_duplicate_keys_and_nonfinite_numbers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            duplicate = directory / "duplicate.json"
            duplicate.write_text(
                '{"authorization":"Bearer secretvalue","authorization":""}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                self.batch.load_json(duplicate)

            nonfinite = directory / "nonfinite.json"
            nonfinite.write_text('{"value": NaN}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "non-finite JSON number"):
                self.batch.load_json(nonfinite)

    def test_cli_diagnostics_escape_terminal_and_line_controls(self) -> None:
        malicious = "bad\x1b[2J\r\n[OK] forged\u202e"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.batch.print_validation(
                [f"duplicate candidate id: {malicious}"],
                [],
            )
        rendered = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\r", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertEqual(len(rendered.splitlines()), 1)
        self.assertIn(r"\u001b", rendered)
        self.assertIn(r"\u000d\u000a[OK] forged\u202e", rendered)

    def test_url_and_loopback_host_guards(self) -> None:
        unsafe_urls = [
            "https://user:password@example.org/article",
            "http://publisher.example/article",
            "https://127.0.0.1/private",
            "https://localhost/private",
            "https://2130706433/private",
            "https://0x7f000001/private",
            "https://0177.0.0.1/private",
            "https://127.1/private",
            "https://localhost%2e/private",
            "https://127%2e0%2e0%2e1/private",
            "https://0/private",
            "https://00/private",
            "https://localhost。/private",
            "https://127。0。0。1/private",
            "https://ⓛocalhost/private",
            "https://metadata.google.internal/private",
            "https://router.local/private",
            "https://127.0.0.1\\example.com/private",
            "https://localhost\\evil.example/private",
        ]
        for url in unsafe_urls:
            with self.subTest(url=url):
                self.assertIsNone(self.batch.safe_http_url(url))
        secret_urls = [
            "https://publisher.example/article;jsessionid=private-session-marker",
            "https://publisher.example/article?ok=1;sig=private-session-marker",
            "https://publisher.example/article?session=private-session-marker",
        ]
        for url in secret_urls:
            with self.subTest(url=url):
                self.assertIsNone(self.batch.safe_http_url(url))
        self.assertEqual(
            self.batch.safe_http_url("https://publisher.example/article"),
            "https://publisher.example/article",
        )
        self.assertTrue(
            self.batch.allowed_loopback_host_header("127.0.0.1:8123", 8123)
        )
        self.assertTrue(
            self.batch.allowed_loopback_host_header("localhost:8123", 8123)
        )
        self.assertFalse(
            self.batch.allowed_loopback_host_header("attacker.example:8123", 8123)
        )

    def test_review_page_url_guard_rejects_browser_parser_bypasses(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is unavailable")
        match = re.search(
            r"function allowedUrl\(value\) \{.*?\n    \}",
            self.batch.REVIEW_HTML,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        program = f"""
{match.group(0)}
const unsafe = [
  "http://publisher.example/article",
  "https://127.0.0.1/private",
  "https://publisher.example:0/private",
  "https://2130706433/private",
  "https://localhost%2e/private",
  "https://metadata.google.internal/private",
  "https://localhost\\\\evil.example/private"
];
console.log(JSON.stringify({{
  unsafe: unsafe.map(allowedUrl),
  safe: allowedUrl("https://publisher.example/article")
}}));
"""
        result = subprocess.run(
            [node, "-e", program],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["unsafe"], [None] * 7)
        self.assertEqual(payload["safe"], "https://publisher.example/article")

    def test_html_artifact_must_be_inert(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            safe = directory / "safe.html"
            safe.write_text(
                "<!doctype html><html><head><meta charset=\"utf-8\">"
                "<meta http-equiv=\"Content-Security-Policy\" "
                "content=\"default-src 'none'; base-uri 'none'; form-action 'none'\">"
                "<title>Full text title</title></head>"
                "<body><p>Full text title. This is a sanitized complete-source "
                "snapshot containing enough body text for deterministic identity and "
                "content checks. It includes methods, results, conclusions, provenance, "
                "and the surrounding publication context rather than only a citation, "
                "login page, access challenge, or short placeholder.</p></body></html>",
                encoding="utf-8",
            )
            safe_bytes = safe.stat().st_size
            safe_hash = hashlib.sha256(safe.read_bytes()).hexdigest()
            self.assertIsNone(
                self.batch.verify_local_artifact(
                    safe,
                    "html",
                    expected_bytes=safe_bytes,
                    expected_sha256=safe_hash,
                )
            )

            unsafe = directory / "unsafe.html"
            unsafe.write_text(
                "<!doctype html><html><head><meta charset=\"utf-8\">"
                "<meta http-equiv=\"Content-Security-Policy\" "
                "content=\"default-src 'none'; base-uri 'none'; form-action 'none'\">"
                "</head><body><script>alert(1)</script></body></html>",
                encoding="utf-8",
            )
            error = self.batch.verify_local_artifact(
                unsafe,
                "html",
                expected_bytes=unsafe.stat().st_size,
                expected_sha256=hashlib.sha256(unsafe.read_bytes()).hexdigest(),
            )
            self.assertIn("active content", error or "")

            browser_differential = directory / "duplicate.html"
            browser_differential.write_text(
                "<!doctype html><html><head><meta charset=\"utf-8\">"
                "<meta http-equiv=\"refresh\" "
                "http-equiv=\"Content-Security-Policy\" "
                "content=\"default-src 'none'; base-uri 'none'; form-action 'none'\">"
                "</head><body><a href=\"javascript:alert(1)\" "
                "href=\"#safe\">x</a></body></html>",
                encoding="utf-8",
            )
            error = self.batch.verify_local_artifact(
                browser_differential,
                "html",
                expected_bytes=browser_differential.stat().st_size,
                expected_sha256=hashlib.sha256(
                    browser_differential.read_bytes()
                ).hexdigest(),
            )
            self.assertIn("active content", error or "")

            remote_load = directory / "remote-load.html"
            remote_load.write_text(
                "<!doctype html><!-- content-security-policy default-src 'none' -->"
                "<html><head><link rel=stylesheet href=https://attacker.example/x.css>"
                "<style>@import 'https://attacker.example/y.css';</style></head>"
                "<body><img src=https://attacker.example/beacon></body></html>",
                encoding="utf-8",
            )
            error = self.batch.verify_local_artifact(
                remote_load,
                "html",
                expected_bytes=remote_load.stat().st_size,
                expected_sha256=hashlib.sha256(remote_load.read_bytes()).hexdigest(),
            )
            self.assertIn("active content", error or "")

            signed_anchor = directory / "signed-anchor.html"
            signed_url = (
                "https://publisher.example/download?" + "token=" + "SUPERSECRET123"
            )
            signed_anchor.write_text(
                "<!doctype html><html><head><meta charset=\"utf-8\">"
                "<meta http-equiv=\"Content-Security-Policy\" "
                "content=\"default-src 'none'; base-uri 'none'; form-action 'none'\">"
                "<title>Full source</title></head><body><p>Full source. This "
                "sanitized body contains sufficient publication text, methods, results, "
                "conclusions, and bibliographic context to satisfy the bounded body-text "
                "check while exercising removal of a private authenticated link from the "
                "saved snapshot.</p><a href=\""
                + signed_url
                + "\" rel=\"noopener noreferrer\">download</a></body></html>",
                encoding="utf-8",
            )
            error = self.batch.verify_local_artifact(
                signed_anchor,
                "html",
                expected_bytes=signed_anchor.stat().st_size,
                expected_sha256=hashlib.sha256(
                    signed_anchor.read_bytes()
                ).hexdigest(),
            )
            self.assertIn("external links are not allowed", error or "")

            for punctuation_title in ("---", "!!!", "😀😀"):
                with self.subTest(punctuation_title=punctuation_title):
                    error = self.batch.verify_local_artifact(
                        safe,
                        "html",
                        expected_bytes=safe_bytes,
                        expected_sha256=safe_hash,
                        expected_title=punctuation_title,
                    )
                    self.assertIn("searchable text", error or "")

    def test_relevance_success_requires_acceptance_history(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest, manifest_path, _ = self.verified_fixture(Path(temporary))
            item = manifest["items"][0]
            item["match_type"] = "relevance"
            item["candidates"][0]["relationship"] = "relevance_fallback"
            errors, _ = self.batch.validate_manifest(manifest, manifest_path)
            self.assertTrue(any("accept_fallback decision" in error for error in errors))
            item["decision_history"].append(
                {
                    "type": "accept_fallback",
                    "candidate_id": "candidate-1",
                    "version_id": None,
                    "outcome": "accepted",
                    "applied_at": "2026-08-05T00:00:00Z",
                }
            )
            manifest["operations_v2"]["requests"][0]["decision_history"].append(
                {
                    "action": "accept_fallback",
                    "candidate_id": "candidate-1",
                    "version_id": None,
                    "comment": "",
                    "outcome": "succeeded",
                }
            )
            errors, _ = self.batch.validate_manifest(manifest, manifest_path)
            self.assertFalse(any("accept_fallback" in error for error in errors))

    def test_success_requires_consistent_candidate_and_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest, manifest_path, _ = self.verified_fixture(Path(temporary))
            item = manifest["items"][0]
            item["match_type"] = "none"
            item["candidates"][0]["title"] = "Totally unrelated"
            item["candidates"][0].pop("relationship")
            errors, _ = self.batch.validate_manifest(manifest, manifest_path)
            self.assertTrue(any("must be exact or relevance" in error for error in errors))

            item["match_type"] = "exact"
            item["candidates"][0].update(
                title="Example research title",
                relationship="title_match",
                title_match_type="verbatim",
            )
            item["artifact_discovery"]["method"] = "other"
            errors, _ = self.batch.validate_manifest(manifest, manifest_path)
            self.assertTrue(
                any("other is review-only" in error for error in errors)
            )
            item["artifact_discovery"]["method"] = "download_link"

            item["candidates"][0].update(
                {
                    "title": "Example research title",
                    "relationship": "title_match",
                }
            )
            item["result"]["verified_url"] = "https://unrelated.example/work"
            item["route_metrics"][0]["outcome"] = "failed"
            errors, _ = self.batch.validate_manifest(manifest, manifest_path)
            self.assertTrue(any("must match the selected candidate" in error for error in errors))
            self.assertTrue(any("outcome passed" in error for error in errors))

    def test_declaring_page_may_differ_from_canonical_source_for_evidence_methods(self) -> None:
        declaring_urls = {
            "registry_metadata": "https://registry.example/records/example-work",
            "structured_data": "https://catalog.example/works/example-work",
            "embedded_document": "https://viewer.example/works/example-work",
            "download_link": "https://archive.example/works/example-work",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for method, declaring_url in declaring_urls.items():
                with self.subTest(method=method):
                    manifest, manifest_path, _ = self.verified_fixture(root / method)
                    item = manifest["items"][0]
                    item["artifact_discovery"].update(
                        method=method,
                        discovered_from=declaring_url,
                    )
                    errors, warnings = self.batch.validate_manifest(
                        manifest,
                        manifest_path,
                    )
                    self.assertEqual(errors, [])
                    self.assertEqual(warnings, [])

    def test_distinct_declaring_page_does_not_relax_success_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            manifest, manifest_path, _ = self.verified_fixture(root / "unsafe")
            item = manifest["items"][0]
            item["artifact_discovery"].update(
                method="structured_data",
                discovered_from="http://catalog.example/works/example-work",
            )
            errors, _ = self.batch.validate_manifest(manifest, manifest_path)
            self.assertTrue(
                any(
                    "artifact_discovery.discovered_from must be a safe public HTTPS URL"
                    in error
                    for error in errors
                )
            )

            manifest, manifest_path, _ = self.verified_fixture(root / "identity")
            item = manifest["items"][0]
            item["artifact_discovery"].update(
                method="registry_metadata",
                discovered_from="https://registry.example/records/example-work",
            )
            item["result"]["verified_url"] = "https://unrelated.example/work"
            errors, _ = self.batch.validate_manifest(manifest, manifest_path)
            self.assertTrue(
                any("verified_url must match the selected candidate" in error for error in errors)
            )

            manifest, manifest_path, _ = self.verified_fixture(root / "artifact")
            item = manifest["items"][0]
            item["artifact_discovery"].update(
                method="download_link",
                discovered_from="https://archive.example/works/example-work",
            )
            item["result"]["retrieval_url"] = "https://other.example/file.html"
            errors, _ = self.batch.validate_manifest(manifest, manifest_path)
            self.assertTrue(
                any(
                    "retrieval_url must match artifact_discovery.artifact_url" in error
                    for error in errors
                )
            )

            manifest, manifest_path, _ = self.verified_fixture(root / "provenance")
            item = manifest["items"][0]
            item["artifact_discovery"].update(
                method="embedded_document",
                discovered_from="https://viewer.example/works/example-work",
            )
            item["result"]["provenance"]["source_role"] = "search_result"
            errors, _ = self.batch.validate_manifest(manifest, manifest_path)
            self.assertTrue(
                any("provenance.source_role must be one of" in error for error in errors)
            )

    def test_html_metadata_still_requires_the_canonical_declaring_page(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest, manifest_path, _ = self.verified_fixture(Path(temporary))
            item = manifest["items"][0]
            item["artifact_discovery"].update(
                method="html_metadata",
                discovered_from="https://mirror.example/record/example-work",
            )
            errors, _ = self.batch.validate_manifest(manifest, manifest_path)
            self.assertTrue(
                any("discovered_from must match the verified canonical URL" in error for error in errors)
            )

    def test_selected_version_cannot_escape_exact_title_family(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest, manifest_path, _ = self.verified_fixture(Path(temporary))
            item = manifest["items"][0]
            version_id = manifest["operations_v2"]["works"][0]["version_ids"][0]
            item["candidates"][0]["versions"] = [
                {
                    "id": version_id,
                    "title": "Totally unrelated malware",
                    "source_url": "https://evil.example/unrelated",
                    "relationship": "version_of_title_match",
                    "title_match_type": "expanded",
                }
            ]
            item["result"].update(
                {
                    "selected_version_id": version_id,
                    "verified_url": "https://evil.example/unrelated",
                    "retrieval_url": "https://evil.example/unrelated.html",
                }
            )
            item["selected_version_id"] = version_id
            manifest["operations_v2"]["requests"][0][
                "selected_version_id"
            ] = version_id
            item["result"]["verification_summary"]["observed_title"] = (
                "Totally unrelated malware"
            )
            item["artifact_discovery"].update(
                {
                    "discovered_from": "https://evil.example/unrelated",
                    "artifact_url": "https://evil.example/unrelated.html",
                }
            )
            errors, _ = self.batch.validate_manifest(manifest, manifest_path)
            self.assertTrue(
                any("selected version title is not in the requested title family" in error for error in errors)
            )

    def test_applied_version_selection_survives_failed_retrieval(self) -> None:
        manifest = self.review_ready_failure_manifest()
        item = manifest["items"][0]
        state = manifest["operations_v2"]
        request = state["requests"][0]
        work = state["works"][0]
        version_id = work["version_ids"][0]
        candidate_id = "candidate-selected-version"
        item.update(
            selected_candidate_id=candidate_id,
            selected_version_id=version_id,
            candidates=[
                {
                    "id": candidate_id,
                    "title": "Unavailable source",
                    "source_url": "https://publisher.example/unavailable",
                    "relationship": "title_match",
                    "title_match_type": "verbatim",
                    "versions": [
                        {
                            "id": version_id,
                            "title": "Unavailable source",
                            "source_url": "https://publisher.example/unavailable",
                            "relationship": "version_of_title_match",
                            "title_match_type": "verbatim",
                        }
                    ],
                }
            ],
            decision_history=[
                {
                    "type": "select_candidate",
                    "candidate_id": candidate_id,
                    "version_id": version_id,
                    "comment": "Use the selected version.",
                    "outcome": "applied",
                }
            ],
        )
        request.update(
            selected_candidate_id=candidate_id,
            selected_version_id=version_id,
            decision_history=[
                {
                    "action": "select_candidate",
                    "candidate_id": candidate_id,
                    "version_id": version_id,
                    "comment": "Use the selected version.",
                    "outcome": "applied",
                }
            ],
        )
        state["handoffs"] = [
            {
                "id": "handoff-selected-version",
                "kind": "candidate_selection",
                "request_ids": [request["id"]],
                "work_ids": [work["id"]],
                "access_group_ids": [],
                "access_generation": None,
                "version_ids": [version_id],
                "expected_filenames": [],
                "status": "resolved",
                "resolution": "selected",
            }
        ]
        errors, warnings = self.batch.validate_manifest(
            manifest,
            Path("/tmp/paper-finder-test/manifest.json"),
        )
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])

    def test_minimal_fake_pdf_is_not_accepted_as_a_document(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fake.pdf"
            path.write_bytes(
                b"%PDF-1.7\n" + b"A" * 1100 + b"\nstartxref\n0\n%%EOF\n"
            )
            error = self.batch.verify_local_artifact(
                path,
                "pdf",
                expected_bytes=path.stat().st_size,
                expected_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            )
            self.assertIsNotNone(error)

    def test_pdf_decimal_fields_reject_unbounded_integers_without_crashing(self) -> None:
        oversized_decimal = b"9" * 5_000
        xref_entry = b"0000000000 65535 f \n"
        trailer = b"trailer\n<</Size 1 /Root 1 0 R>>\n"
        self.assertFalse(
            self.batch._valid_traditional_xref_span(
                b"xref\n" + oversized_decimal + b" 1\n" + xref_entry + trailer
            )
        )
        self.assertFalse(
            self.batch._valid_traditional_xref_span(
                b"xref\n0 " + oversized_decimal + b"\n" + trailer
            )
        )
        self.assertFalse(
            self.batch._valid_xref_stream_span(
                b"1 0 obj\n<</Type /XRef /Size 1 /W [1 1 1] /Length "
                + oversized_decimal
                + b">>\nstream\nendstream\nendobj\n"
            )
        )

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "oversized-startxref.pdf"
            path.write_bytes(
                b"%PDF-1.7\n"
                + b"A" * 1_100
                + b"\nstartxref\n"
                + oversized_decimal
                + b"\n%%EOF\n"
            )
            error = self.batch.verify_local_artifact(
                path,
                "pdf",
                expected_bytes=path.stat().st_size,
                expected_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            )
        self.assertIn("invalid final cross-reference offset", error or "")

    def test_pdf_xref_expansion_and_revision_retention_are_cumulatively_bounded(self) -> None:
        self.assertIsNone(
            self.batch._pdf_direct_decimal_array(
                b"[" + b"0 " * 10_000 + b"]",
                maximum=self.batch.MAX_PDF_OBJECT_NUMBER,
                maximum_items=20,
            )
        )
        oversized_stream = (
            b"1 0 obj\n"
            b"<< /Type /XRef /Size 100000 /W [1 1 1] "
            b"/Index [0 100000] /Length 0 >>\n"
            b"stream\n\nendstream\nendobj\n"
        )
        self.assertIsNone(
            self.batch._parse_xref_stream_section(
                oversized_stream,
                maximum_entries=1_000,
            )
        )
        invalid_explicit_index = (
            b"1 0 obj\n"
            b"<< /Type /XRef /Size 1 /W [1 1 1] "
            b"/Index [0 1 0 1] /Length 3 >>\n"
            b"stream\n\x00\x00\x00\nendstream\nendobj\n"
        )
        self.assertIsNone(
            self.batch._parse_xref_stream_section(
                invalid_explicit_index,
                maximum_entries=1,
            )
        )

        observed_entry_budgets: list[int] = []

        def fake_section(_data, offset, _maximum_bytes, maximum_entries):
            observed_entry_budgets.append(maximum_entries)
            if offset == 1:
                return {
                    "consumed": 1,
                    "entries": {
                        0: (0, 0, 65_535),
                        1: (1, 1, 0),
                    },
                    "prev": 2,
                }
            return None

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bounded-xref-chain.pdf"
            content = b"%PDF-1.7\nplaceholder\nstartxref\n1\n%%EOF\n"
            path.write_bytes(content)
            with mock.patch.object(
                self.batch,
                "MAX_PDF_RETAINED_XREF_ENTRIES",
                3,
            ), mock.patch.object(
                self.batch,
                "_parse_pdf_cross_reference_section",
                side_effect=fake_section,
            ):
                error = self.batch.inspect_pdf_terminal_structure(
                    path,
                    observed_bytes=len(content),
                    trailer=b"startxref\n1\n%%EOF\n",
                )
        self.assertIn("cross-reference", error or "")
        self.assertEqual(observed_entry_budgets, [3, 1])

    def test_pdfinfo_rejects_encryption_and_unbounded_page_counts(self) -> None:
        parser_outputs = {
            "encrypted": b"Pages: 1\nEncrypted: yes (print:yes)\n",
            "unbounded-pages": (
                b"Pages: " + b"9" * 5_000 + b"\nEncrypted: no\n"
            ),
        }
        for label, parser_output in parser_outputs.items():
            with self.subTest(label=label):
                with mock.patch.object(
                    self.batch.shutil,
                    "which",
                    return_value="/usr/bin/poppler-tool",
                ), mock.patch.object(
                    self.batch,
                    "run_bounded_subprocess",
                    return_value=(0, parser_output, None),
                ) as bounded_parser:
                    error = self.batch.inspect_pdf_with_poppler(
                        Path("/tmp/untrusted.pdf"),
                        expected_page_count=1,
                        expected_title="Example research title",
                    )
                self.assertIsNotNone(error)
                self.assertEqual(bounded_parser.call_count, 1)
                if label == "encrypted":
                    self.assertIn("encrypted", (error or "").casefold())
                else:
                    self.assertIn("invalid page count", error or "")

    def test_pdf_rejects_overlapping_incomplete_and_hybrid_xref_tables(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            prefix = bytearray(b"%PDF-1.4\n")
            object_offset = len(prefix)
            prefix.extend(b"1 0 obj\n<< /Type /Catalog >>\nendobj\n")
            while len(prefix) < 1_100:
                prefix.extend(b"% bounded parser fixture padding\n")
            xref_offset = len(prefix)
            valid_entries = (
                b"xref\n0 2\n"
                b"0000000000 65535 f \n"
                + f"{object_offset:010d} 00000 n \n".encode("ascii")
            )
            variants = {
                "overlap-n-then-f": (
                    valid_entries + b"1 1\n0000000000 00001 f \n",
                    b" /Size 2 /Root 1 0 R",
                ),
                "missing-object-zero": (
                    b"xref\n1 1\n"
                    + f"{object_offset:010d} 00000 n \n".encode("ascii"),
                    b" /Size 2 /Root 1 0 R",
                ),
                "object-zero-wrong-generation": (
                    b"xref\n0 2\n"
                    b"0000000000 65534 f \n"
                    + f"{object_offset:010d} 00000 n \n".encode("ascii"),
                    b" /Size 2 /Root 1 0 R",
                ),
                "free-pointer-to-in-use": (
                    b"xref\n0 2\n"
                    b"0000000001 65535 f \n"
                    + f"{object_offset:010d} 00000 n \n".encode("ascii"),
                    b" /Size 2 /Root 1 0 R",
                ),
                "nonzero-free-generation-overflow": (
                    b"xref\n0 3\n"
                    b"0000000002 65535 f \n"
                    + f"{object_offset:010d} 00000 n \n".encode("ascii")
                    + b"0000000000 99999 f \n",
                    b" /Size 3 /Root 1 0 R",
                ),
                "unlinked-nonzero-free-entry": (
                    b"xref\n0 3\n"
                    b"0000000000 65535 f \n"
                    + f"{object_offset:010d} 00000 n \n".encode("ascii")
                    + b"0000000000 00001 f \n",
                    b" /Size 3 /Root 1 0 R",
                ),
                "declared-size-gap": (
                    valid_entries,
                    b" /Size 3 /Root 1 0 R",
                ),
                "malformed-prev-target": (
                    valid_entries,
                    b" /Size 2 /Root 1 0 R /Prev 1",
                ),
                "hybrid-xrefstm": (
                    valid_entries,
                    b" /Size 2 /Root 1 0 R /XRefStm 1",
                ),
                "escaped-xrefstm-leading": (
                    valid_entries,
                    b" /Size 2 /Root 1 0 R /#58RefStm 1",
                ),
                "escaped-xrefstm-middle": (
                    valid_entries,
                    b" /Size 2 /Root 1 0 R /X#52efStm 1",
                ),
                "escaped-xrefstm-tail": (
                    valid_entries,
                    b" /Size 2 /Root 1 0 R /XRef#53tm 1",
                ),
                "escaped-prev-leading": (
                    valid_entries,
                    b" /Size 2 /Root 1 0 R /#50rev 1",
                ),
                "escaped-prev-middle": (
                    valid_entries,
                    b" /Size 2 /Root 1 0 R /P#72ev 1",
                ),
                "escaped-prev-tail": (
                    valid_entries,
                    b" /Size 2 /Root 1 0 R /Pr#65v 1",
                ),
                "duplicate-size": (
                    valid_entries,
                    b" /Size 2 /Size 2 /Root 1 0 R",
                ),
                "duplicate-root": (
                    valid_entries,
                    b" /Size 2 /Root 1 0 R /Root 1 0 R",
                ),
                "duplicate-prev": (
                    valid_entries,
                    b" /Size 2 /Root 1 0 R /Prev 1 /Prev 1",
                ),
                "duplicate-xrefstm": (
                    valid_entries,
                    b" /Size 2 /Root 1 0 R /XRefStm 1 /XRefStm 1",
                ),
                "duplicate-encrypt": (
                    valid_entries,
                    b" /Size 2 /Root 1 0 R /Encrypt 1 0 R /Encrypt 1 0 R",
                ),
                "duplicate-size-decoded": (
                    valid_entries,
                    b" /Size 2 /#53ize 2 /Root 1 0 R",
                ),
                "duplicate-root-decoded": (
                    valid_entries,
                    b" /Size 2 /Root 1 0 R /#52oot 1 0 R",
                ),
                "duplicate-encrypt-decoded": (
                    valid_entries,
                    b" /Size 2 /Root 1 0 R /Encrypt 1 0 R /#45ncrypt 1 0 R",
                ),
            }
            for label, (xref_table, trailer_fields) in variants.items():
                with self.subTest(label=label):
                    content = (
                        bytes(prefix)
                        + xref_table
                        + b"trailer\n<<"
                        + trailer_fields
                        + b" >>\nstartxref\n"
                        + str(xref_offset).encode("ascii")
                        + b"\n%%EOF\n"
                    )
                    path = directory / f"{label}.pdf"
                    path.write_bytes(content)
                    error = self.batch.verify_local_artifact(
                        path,
                        "pdf",
                        expected_bytes=len(content),
                        expected_sha256=hashlib.sha256(content).hexdigest(),
                        expected_title="Example research title",
                        expected_page_count=1,
                    )
                    self.assertIsNotNone(error)
                    self.assertIn("cross-reference", error or "")

    def test_pdf_rejects_comment_shaped_payload_before_final_xref(self) -> None:
        original = self.make_test_pdf("Example research title")
        original_xref = original.index(b"xref\n")
        self.assertIn(
            b"startxref\n" + str(original_xref).encode("ascii") + b"\n",
            original,
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for label, payload in (
                ("zip", b"%PK appended payload\n"),
                ("executable", b"%MZ appended payload\n"),
            ):
                with self.subTest(label=label):
                    forged_xref = original_xref + len(payload)
                    content = original[:original_xref] + payload + original[original_xref:]
                    content = content.replace(
                        b"startxref\n" + str(original_xref).encode("ascii") + b"\n",
                        b"startxref\n" + str(forged_xref).encode("ascii") + b"\n",
                        1,
                    )
                    path = directory / f"comment-shaped-{label}.pdf"
                    path.write_bytes(content)
                    error = self.batch.verify_local_artifact(
                        path,
                        "pdf",
                        expected_bytes=len(content),
                        expected_sha256=hashlib.sha256(content).hexdigest(),
                        expected_title="Example research title",
                        expected_page_count=1,
                    )
                    self.assertIsNotNone(error)
                    self.assertIn("cross-reference", error or "")

    def test_real_pdf_requires_parser_page_count_and_title_evidence(self) -> None:
        if not shutil.which("pdfinfo") or not shutil.which("pdftotext"):
            self.skipTest("Poppler is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "verified.pdf"
            path.write_bytes(self.make_test_pdf("Example research title"))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertIsNone(
                self.batch.verify_local_artifact(
                    path,
                    "pdf",
                    expected_bytes=path.stat().st_size,
                    expected_sha256=digest,
                    expected_title="Example research title",
                    expected_page_count=1,
                )
            )
            wrong_title = self.batch.verify_local_artifact(
                path,
                "pdf",
                expected_bytes=path.stat().st_size,
                expected_sha256=digest,
                expected_title="Unrelated title",
                expected_page_count=1,
            )
            self.assertIn("does not contain", wrong_title or "")
            punctuation_title = self.batch.verify_local_artifact(
                path,
                "pdf",
                expected_bytes=path.stat().st_size,
                expected_sha256=digest,
                expected_title="---",
                expected_page_count=1,
            )
            self.assertIn("searchable text", punctuation_title or "")

    def test_pdf_rejects_non_whitespace_payload_after_final_eof(self) -> None:
        if not shutil.which("pdfinfo") or not shutil.which("pdftotext"):
            self.skipTest("Poppler is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "appended.pdf"
            path.write_bytes(
                self.make_test_pdf("Example research title")
                + b"PK\x03\x04APPENDED-PAYLOAD"
            )
            error = self.batch.verify_local_artifact(
                path,
                "pdf",
                expected_bytes=path.stat().st_size,
                expected_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                expected_title="Example research title",
                expected_page_count=1,
            )
        self.assertIn("valid final startxref/EOF sequence", error or "")

    def test_pdf_rejects_appended_payload_hidden_behind_fake_eof(self) -> None:
        if not shutil.which("pdfinfo") or not shutil.which("pdftotext"):
            self.skipTest("Poppler is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "appended-fake-eof.pdf"
            path.write_bytes(
                self.make_test_pdf("Example research title")
                + b"PK\x03\x04APPENDED-PAYLOAD\n%%EOF\n"
            )
            error = self.batch.verify_local_artifact(
                path,
                "pdf",
                expected_bytes=path.stat().st_size,
                expected_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                expected_title="Example research title",
                expected_page_count=1,
            )
        self.assertIn("valid final startxref/EOF sequence", error or "")

    def test_pdf_rejects_appended_payload_with_forged_complete_terminal(self) -> None:
        if not shutil.which("pdfinfo") or not shutil.which("pdftotext"):
            self.skipTest("Poppler is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            original = self.make_test_pdf("Example research title")
            offset_match = re.search(rb"startxref\s+([0-9]+)", original)
            self.assertIsNotNone(offset_match)
            for label, forged_offset in (
                ("zero", 0),
                ("reused", int(offset_match.group(1))),
            ):
                with self.subTest(label=label):
                    path = Path(temporary) / f"appended-{label}.pdf"
                    path.write_bytes(
                        original
                        + b"PK\x03\x04APPENDED-PAYLOAD\nstartxref\n"
                        + str(forged_offset).encode("ascii")
                        + b"\n%%EOF\n"
                    )
                    error = self.batch.verify_local_artifact(
                        path,
                        "pdf",
                        expected_bytes=path.stat().st_size,
                        expected_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                        expected_title="Example research title",
                        expected_page_count=1,
                    )
                    self.assertIsNotNone(error)
                    self.assertTrue(
                        "invalid final cross-reference offset" in (error or "")
                        or "valid final startxref/EOF sequence" in (error or ""),
                        error,
                    )

    def test_pdf_rejects_payload_after_original_terminal_is_removed(self) -> None:
        if not shutil.which("pdfinfo") or not shutil.which("pdftotext"):
            self.skipTest("Poppler is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            original = self.make_test_pdf("Example research title")
            terminal = re.search(
                rb"startxref\s+([0-9]+)\s+%%EOF\s*\Z",
                original,
            )
            self.assertIsNotNone(terminal)
            xref_offset = int(terminal.group(1))
            variants = {
                "eof-only": original[: original.rfind(b"%%EOF")],
                "whole-terminal": original[: terminal.start()],
            }
            for label, prefix in variants.items():
                with self.subTest(label=label):
                    path = Path(temporary) / f"replaced-terminal-{label}.pdf"
                    path.write_bytes(
                        prefix
                        + b"PK\x03\x04APPENDED-PAYLOAD\nstartxref\n"
                        + str(xref_offset).encode("ascii")
                        + b"\n%%EOF\n"
                    )
                    error = self.batch.verify_local_artifact(
                        path,
                        "pdf",
                        expected_bytes=path.stat().st_size,
                        expected_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                        expected_title="Example research title",
                        expected_page_count=1,
                    )
                    self.assertIn("malformed or unlinked", error or "")

    def test_pdf_rejects_payload_before_a_forged_valid_xref_table(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original = self.make_test_pdf("Example research title")
            terminal = re.search(
                rb"startxref\s+([0-9]+)\s+%%EOF\s*\Z",
                original,
            )
            self.assertIsNotNone(terminal)
            original_xref_offset = int(terminal.group(1))
            copied_xref = original[original_xref_offset : terminal.start()]
            prefix = original[:original_xref_offset]
            payload = b"PK\x03\x04APPENDED-PAYLOAD\n"
            forged_xref_offset = len(prefix) + len(payload)
            forged = (
                prefix
                + payload
                + copied_xref
                + b"startxref\n"
                + str(forged_xref_offset).encode("ascii")
                + b"\n%%EOF\n"
            )
            path = Path(temporary) / "forged-valid-xref.pdf"
            path.write_bytes(forged)
            error = self.batch.verify_local_artifact(
                path,
                "pdf",
                expected_bytes=path.stat().st_size,
                expected_sha256=hashlib.sha256(forged).hexdigest(),
                expected_title="Example research title",
                expected_page_count=1,
            )
        self.assertIn(
            "data outside its complete cross-reference/revision structure",
            error or "",
        )

    def test_pdf_accepts_complete_incremental_and_xref_stream_structures(self) -> None:
        if not shutil.which("pdfinfo") or not shutil.which("pdftotext"):
            self.skipTest("Poppler is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fixtures = {
                "incremental": self.make_incremental_test_pdf(
                    "Example research title"
                ),
                "xref-stream": self.make_xref_stream_test_pdf(
                    "Example research title"
                ),
            }
            for label, content in fixtures.items():
                with self.subTest(label=label):
                    path = directory / f"{label}.pdf"
                    path.write_bytes(content)
                    self.assertIsNone(
                        self.batch.verify_local_artifact(
                            path,
                            "pdf",
                            expected_bytes=len(content),
                            expected_sha256=hashlib.sha256(content).hexdigest(),
                            expected_title="Example research title",
                            expected_page_count=1,
                        )
                    )

    def test_pdf_rejects_tampered_incremental_and_xref_stream_structures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            incremental = self.make_incremental_test_pdf(
                "Example research title",
                inter_revision_payload=b"PK\x03\x04APPENDED-PAYLOAD\n",
            )
            malformed_prev = self.make_incremental_test_pdf(
                "Example research title"
            )
            final_xref = re.search(
                rb"startxref\s+([0-9]+)\s+%%EOF\s*\Z",
                malformed_prev,
            )
            self.assertIsNotNone(final_xref)
            malformed_prev = re.sub(
                rb"/Prev\s+[0-9]+",
                b"/Prev " + final_xref.group(1),
                malformed_prev,
                count=1,
            )
            fixtures = {
                "incremental-payload": incremental,
                "prev-cycle": malformed_prev,
                "xref-stream-bad-object-offset": self.make_xref_stream_test_pdf(
                    "Example research title",
                    first_object_offset_delta=1,
                ),
            }
            for label, content in fixtures.items():
                with self.subTest(label=label):
                    path = directory / f"{label}.pdf"
                    path.write_bytes(content)
                    error = self.batch.inspect_pdf_terminal_structure(
                        path,
                        observed_bytes=len(content),
                        trailer=content[-8192:],
                    )
                    self.assertIsNotNone(error)
                    self.assertTrue(
                        any(
                            expected in (error or "")
                            for expected in (
                                "outside its complete cross-reference/revision structure",
                                "cyclic or excessive Prev chain",
                            )
                        ),
                        error,
                    )

    def test_review_page_does_not_offer_unverified_sign_in_links(self) -> None:
        self.assertNotIn("Open sign-in page", self.batch.REVIEW_HTML)
        self.assertIn("never paste passwords, cookies, tokens", self.batch.REVIEW_HTML)

    def test_review_server_detects_stale_and_external_manifest_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "manifest.json"
            manifest = self.batch.new_manifest(["Example title"])
            self.batch.save_manifest(manifest_path, manifest)
            server = self.batch.ReviewServer(
                ("127.0.0.1", 0),
                manifest_path,
                manifest,
                "test-route-token",
            )
            try:
                server.require_current_revision(manifest["revision"])
                with self.assertRaisesRegex(ValueError, "reload the page"):
                    server.require_current_revision(manifest["revision"] - 1)

                external = self.batch.load_json(manifest_path)
                external["review_state"] = "submitted"
                self.batch.save_manifest(manifest_path, external)
                with self.assertRaisesRegex(ValueError, "changed outside"):
                    server.require_current_revision(manifest["revision"])
            finally:
                server.server_close()

    def test_new_manifest_embeds_authoritative_operations_v2_projection(self) -> None:
        manifest = self.batch.new_manifest(["First title", "Second title"])
        self.assertIn("operations_v2", manifest)
        self.assertEqual(
            [request["title"] for request in manifest["operations_v2"]["requests"]],
            ["First title", "Second title"],
        )
        errors, warnings = self.batch.validate_manifest(
            manifest,
            Path("/tmp/paper-finder-test/manifest.json"),
        )
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])

        missing_selected_version = self.batch.new_manifest(["Example title"])
        missing_selected_version["items"][0].pop("selected_version_id")
        errors, _ = self.batch.validate_manifest(
            missing_selected_version,
            Path("/tmp/paper-finder-test/manifest.json"),
        )
        self.assertTrue(any("missing field: selected_version_id" in error for error in errors))
        missing_selected_version["schema_version"] = self.batch.LEGACY_SCHEMA_VERSION
        errors, _ = self.batch.validate_manifest(
            missing_selected_version,
            Path("/tmp/paper-finder-test/manifest.json"),
        )
        self.assertFalse(any("missing field: selected_version_id" in error for error in errors))

        manifest["operations_v2"]["requests"][0]["title"] = "Changed title"
        errors, _ = self.batch.validate_manifest(
            manifest,
            Path("/tmp/paper-finder-test/manifest.json"),
        )
        self.assertTrue(
            any("does not match its bound work" in error for error in errors)
        )

        manifest["operations_v2"]["requests"][0]["title"] = "First title"
        manifest["items"][0]["comment"] = "projection drift"
        errors, _ = self.batch.validate_manifest(
            manifest,
            Path("/tmp/paper-finder-test/manifest.json"),
        )
        self.assertTrue(any("request comment does not match" in error for error in errors))

    def test_submitted_round_allows_review_or_active_v2_status_only(self) -> None:
        manifest = self.review_ready_failure_manifest()
        manifest["review_state"] = "submitted"
        manifest["operations_v2"]["status"] = "active"
        errors, _ = self.batch.validate_manifest(
            manifest,
            Path("/tmp/paper-finder-test/manifest.json"),
        )
        self.assertFalse(any("operations_v2.status" in error for error in errors))

        manifest["operations_v2"]["status"] = "done"
        errors, _ = self.batch.validate_manifest(
            manifest,
            Path("/tmp/paper-finder-test/manifest.json"),
        )
        self.assertTrue(any("operations_v2.status" in error for error in errors))

    def test_review_decision_updates_authoritative_request_projection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "manifest.json"
            manifest = self.review_ready_failure_manifest()
            item = manifest["items"][0]
            item["candidates"] = [
                {
                    "id": "candidate-stale",
                    "title": "Unavailable source",
                    "source_url": "https://publisher.example/unavailable",
                    "relationship": "title_match",
                    "title_match_type": "verbatim",
                }
            ]
            item["selected_candidate_id"] = "candidate-stale"
            manifest["operations_v2"]["requests"][0][
                "selected_candidate_id"
            ] = "candidate-stale"
            self.batch.save_manifest(manifest_path, manifest)
            status, payload = self.post_review_action(
                manifest,
                manifest_path,
                "api/items/item-0001/decision",
                {
                    "action": "retry",
                    "candidate_id": "candidate-stale",
                    "comment": "Try again without carrying a candidate.",
                },
            )
            self.assertEqual(status, 400, payload)

            self.assertIn("only allowed for candidate actions", payload.get("error", ""))

            status, payload = self.post_review_action(
                manifest,
                manifest_path,
                "api/items/item-0001/decision",
                {
                    "action": "retry",
                    "comment": "x" * (self.batch.MAX_COMMENT_CHARACTERS + 1),
                },
            )
            self.assertEqual(status, 400, payload)
            self.assertIn("10,000", payload.get("error", ""))

            status, payload = self.post_review_action(
                manifest,
                manifest_path,
                "api/items/item-0001/decision",
                {"action": "stop_retrying", "comment": "No further routes."},
            )
            self.assertEqual(status, 200, payload)
            saved = self.batch.load_json(manifest_path)
            request = saved["operations_v2"]["requests"][0]
            self.assertEqual(request["comment"], "No further routes.")
            self.assertEqual(
                request["pending_action"],
                {
                    "action": "stop_retrying",
                    "candidate_id": None,
                    "version_id": None,
                    "comment": "No further routes.",
                    "outcome": "queued",
                },
            )
            errors, _ = self.batch.validate_manifest(saved, manifest_path)
            self.assertEqual(errors, [])

    def test_manifest_error_diagnostics_are_globally_bounded(self) -> None:
        manifest = self.batch.new_manifest(["First title", "Second title"])
        for item in manifest["items"]:
            item["candidates"] = [None] * self.batch.MAX_CANDIDATES_PER_ITEM
        errors, warnings = self.batch.validate_manifest(
            manifest,
            Path("/tmp/paper-finder-test/manifest.json"),
        )
        self.assertEqual(warnings, [])
        self.assertLessEqual(len(errors), self.batch.MAX_MANIFEST_ERRORS + 1)
        self.assertIn("additional manifest errors omitted", errors[-1])

    def test_legacy_manifest_without_operations_v2_is_readable_but_not_mutable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "manifest.json"
            manifest = self.review_ready_failure_manifest()
            manifest.pop("operations_v2")
            manifest["schema_version"] = self.batch.LEGACY_SCHEMA_VERSION
            self.batch.save_manifest(manifest_path, manifest)
            errors, warnings = self.batch.validate_manifest(manifest, manifest_path)
            self.assertEqual(errors, [])
            self.assertTrue(any("legacy manifest" in warning for warning in warnings))

            status, payload = self.post_batch_action(manifest, manifest_path, "done")
            self.assertEqual(status, 400, payload)
            self.assertIn("operations_v2", payload.get("error", ""))
            saved = self.batch.load_json(manifest_path)
            self.assertFalse(saved["done"])

    def test_stripping_v2_state_cannot_downgrade_a_new_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest_path = directory / "manifest.json"
            output_path = directory / "report.html"
            manifest = self.review_ready_failure_manifest()
            manifest.pop("operations_v2")
            errors, _ = self.batch.validate_manifest(manifest, manifest_path)
            self.assertTrue(
                any("requires an embedded operations_v2" in error for error in errors)
            )

            self.batch.save_manifest(manifest_path, manifest)
            status, payload = self.post_batch_action(manifest, manifest_path, "done")
            self.assertEqual(status, 400, payload)
            self.assertIn("operations_v2", payload.get("error", ""))

            manifest["review_state"] = "done"
            manifest["done"] = True
            self.batch.save_manifest(manifest_path, manifest)
            exported = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "export",
                    str(manifest_path),
                    str(output_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(exported.returncode, 0)
            self.assertFalse(output_path.exists())
            self.assertIn("operations_v2", exported.stderr)

    def test_embedded_v2_schema_version_must_be_an_integer(self) -> None:
        manifest = self.batch.new_manifest(["Example title"])
        manifest["operations_v2"]["schema_version"] = 2.0
        errors, _ = self.batch.validate_manifest(
            manifest,
            Path("/tmp/paper-finder-test/manifest.json"),
        )
        self.assertTrue(
            any("schema_version must be integer 2" in error for error in errors)
        )

    def test_finish_blocks_unfinished_v2_handoffs_and_closes_resolved_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "manifest.json"
            for handoff_status, resolution in (
                ("open", None),
                ("submitted", "stop"),
                ("applied", "stop"),
            ):
                with self.subTest(handoff_status=handoff_status):
                    manifest = self.review_ready_failure_manifest()
                    state = manifest["operations_v2"]
                    state["handoffs"] = [
                        {
                            "id": "handoff-failure-review",
                            "kind": "failure_review",
                            "request_ids": [state["requests"][0]["id"]],
                            "work_ids": [state["works"][0]["id"]],
                            "access_group_ids": [],
                            "access_generation": None,
                            "version_ids": [],
                            "expected_filenames": [],
                            "status": handoff_status,
                            "resolution": resolution,
                        }
                    ]
                    self.batch.save_manifest(manifest_path, manifest)

                    status, payload = self.post_batch_action(
                        manifest, manifest_path, "done"
                    )
                    self.assertEqual(status, 400, payload)
                    self.assertIn("resolve or cancel", payload.get("error", ""))
                    self.assertFalse(self.batch.load_json(manifest_path)["done"])

            manifest = self.review_ready_failure_manifest()
            state = manifest["operations_v2"]
            state["handoffs"] = [
                {
                    "id": "handoff-failure-review",
                    "kind": "failure_review",
                    "request_ids": [state["requests"][0]["id"]],
                    "work_ids": [state["works"][0]["id"]],
                    "access_group_ids": [],
                    "access_generation": None,
                    "version_ids": [],
                    "expected_filenames": [],
                    "status": "resolved",
                    "resolution": "stop",
                }
            ]
            self.batch.save_manifest(manifest_path, manifest)
            status, payload = self.post_batch_action(manifest, manifest_path, "done")
            self.assertEqual(status, 200, payload)
            saved = self.batch.load_json(manifest_path)
            self.assertTrue(saved["done"])
            self.assertEqual(saved["operations_v2"]["status"], "done")

    def test_finish_revalidates_artifact_before_persisting_done_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest, manifest_path, artifact_path = self.verified_fixture(directory)
            manifest["review_state"] = "review_ready"
            manifest["operations_v2"]["status"] = "review"
            self.batch.save_manifest(manifest_path, manifest)

            artifact_path.unlink()
            status, payload = self.post_batch_action(manifest, manifest_path, "done")

            self.assertEqual(status, 400, payload)
            self.assertIn("cannot finish invalid batch", payload.get("error", ""))
            saved = self.batch.load_json(manifest_path)
            self.assertFalse(saved["done"])
            self.assertEqual(saved["review_state"], "review_ready")
            self.assertEqual(saved["operations_v2"]["status"], "review")

    def test_export_refuses_manifest_with_open_v2_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest_path = directory / "manifest.json"
            output_path = directory / "report.html"
            manifest = self.review_ready_failure_manifest()
            state = manifest["operations_v2"]
            state["handoffs"] = [
                {
                    "id": "handoff-open",
                    "kind": "failure_review",
                    "request_ids": [state["requests"][0]["id"]],
                    "work_ids": [state["works"][0]["id"]],
                    "access_group_ids": [],
                    "access_generation": None,
                    "version_ids": [],
                    "expected_filenames": [],
                    "status": "open",
                    "resolution": None,
                }
            ]
            manifest["review_state"] = "done"
            manifest["done"] = True
            state["status"] = "done"
            self.batch.save_manifest(manifest_path, manifest)
            exported = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "export",
                    str(manifest_path),
                    str(output_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(exported.returncode, 0)
            self.assertFalse(output_path.exists())
            self.assertIn("handoff", exported.stderr)

    def test_init_and_validate_smoke_flow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            titles = directory / "titles.txt"
            manifest = directory / "manifest.json"
            titles.write_text("  First title  \n\tSecond title\t\n", encoding="utf-8")
            initialized = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "init",
                    str(titles),
                    str(manifest),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            validated = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "validate",
                    str(manifest),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(validated.returncode, 0, validated.stderr)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual([item["status"] for item in payload["items"]], ["pending", "pending"])
            self.assertEqual(
                [item["requested_title"] for item in payload["items"]],
                ["First title", "Second title"],
            )
            self.assertEqual(
                [request["title"] for request in payload["operations_v2"]["requests"]],
                ["First title", "Second title"],
            )

            json_titles = directory / "titles.json"
            json_titles.write_text(
                json.dumps({"titles": ["  First title  ", "\tSecond title\t"]}),
                encoding="utf-8",
            )
            self.assertEqual(
                self.batch.read_titles(json_titles),
                ["First title", "Second title"],
            )

    def test_export_refuses_existing_output_without_explicit_force(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest_path = directory / "manifest.json"
            output_path = directory / "valuable.txt"
            manifest = self.batch.new_manifest(["Unavailable source"])
            item = manifest["items"][0]
            item.update(
                {
                    "status": "failed_final",
                    "failure": {
                        "code": "not_found",
                        "message": "No legitimate source was found.",
                        "retryable": False,
                    },
                }
            )
            manifest["review_state"] = "done"
            manifest["done"] = True
            self.mark_v2_failed(manifest, review_status="done")
            self.batch.save_manifest(manifest_path, manifest)
            output_path.write_text("valuable sentinel", encoding="utf-8")

            refused = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "export",
                    str(manifest_path),
                    str(output_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(output_path.read_text(encoding="utf-8"), "valuable sentinel")

            forced = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "export",
                    str(manifest_path),
                    str(output_path),
                    "--force",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(forced.returncode, 0, forced.stderr)
            self.assertIn(
                "Paper Finder Batch Report",
                output_path.read_text(encoding="utf-8"),
            )

    def test_non_success_result_cannot_leak_paths_or_phishing_links(self) -> None:
        manifest = self.batch.new_manifest(["Unavailable source"])
        item = manifest["items"][0]
        item.update(
            {
                "status": "not_found",
                "result": {
                    "local_path": "/private/location/paper.pdf",
                    "verified_url": "https://attacker.example/phish",
                },
            }
        )
        self.mark_v2_failed(manifest)
        errors, _ = self.batch.validate_manifest(
            manifest,
            Path("/tmp/paper-finder-test/manifest.json"),
        )
        self.assertTrue(any("result is allowed only" in error for error in errors))
        exported = self.batch.render_export(manifest)
        self.assertNotIn("/private/location/paper.pdf", exported)
        self.assertNotIn("https://attacker.example/phish", exported)
        self.assertIn(
            'item.status === "retrieved_verified" && item.result',
            self.batch.REVIEW_HTML,
        )


if __name__ == "__main__":
    unittest.main()
