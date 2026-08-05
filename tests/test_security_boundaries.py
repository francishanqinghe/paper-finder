from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


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
        return manifest, manifest_path, artifact_path

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
        while len(document) < 1100:
            document.extend(b"% bounded parser fixture padding\n")
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
        ]
        for value in secret_values:
            with self.subTest(value=value):
                self.assertTrue(self.batch.secret_locations(value))
        self.assertEqual(
            self.batch.secret_locations({"failure": {"code": "not_found"}}),
            [],
        )

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

    def test_selected_version_cannot_escape_exact_title_family(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest, manifest_path, _ = self.verified_fixture(Path(temporary))
            item = manifest["items"][0]
            item["candidates"][0]["versions"] = [
                {
                    "id": "v1",
                    "title": "Totally unrelated malware",
                    "source_url": "https://evil.example/unrelated",
                    "relationship": "version_of_title_match",
                    "title_match_type": "expanded",
                }
            ]
            item["result"].update(
                {
                    "selected_version_id": "v1",
                    "verified_url": "https://evil.example/unrelated",
                    "retrieval_url": "https://evil.example/unrelated.html",
                }
            )
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

    def test_init_and_validate_smoke_flow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            titles = directory / "titles.txt"
            manifest = directory / "manifest.json"
            titles.write_text("First title\nSecond title\n", encoding="utf-8")
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
