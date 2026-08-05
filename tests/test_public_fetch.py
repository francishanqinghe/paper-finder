from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from urllib import request as urlrequest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
FETCH_SCRIPT = ROOT / "scripts" / "paper_finder_fetch.py"


def load_fetch_module():
    spec = importlib.util.spec_from_file_location("paper_finder_fetch_test", FETCH_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load {FETCH_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeResponse:
    def __init__(
        self,
        body: bytes,
        *,
        url: str = "https://publisher.example/paper.pdf",
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._stream = io.BytesIO(body)
        self._url = url
        self.status = status
        self.headers = headers or {}
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def geturl(self) -> str:
        return self._url

    def getcode(self) -> int:
        return self.status

    def close(self) -> None:
        self.closed = True


class FakeOpener:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.requests: list[tuple[urlrequest.Request, float]] = []

    def open(self, request: urlrequest.Request, timeout: float) -> FakeResponse:
        self.requests.append((request, timeout))
        return self.response


class PublicFetchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fetch = load_fetch_module()

    def test_managed_proxy_target_validation_does_not_resolve_synthetic_egress(self) -> None:
        with (
            mock.patch.object(
                self.fetch.urlrequest,
                "getproxies",
                return_value={"https": "http://managed-proxy.invalid:8080"},
            ),
            mock.patch.object(
                self.fetch.urlrequest,
                "proxy_bypass",
                return_value=False,
            ),
            mock.patch.object(
                self.fetch.socket,
                "getaddrinfo",
                side_effect=AssertionError("proxied target must not resolve locally"),
            ),
        ):
            self.assertEqual(
                self.fetch.require_public_https_url(
                    "https://publisher.example/papers/item.pdf#viewer"
                ),
                "https://publisher.example/papers/item.pdf",
            )

    def test_direct_target_validation_requires_only_global_dns_answers(self) -> None:
        global_answer = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", 443),
            )
        ]
        private_answer = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("10.0.0.8", 443),
            )
        ]
        with (
            mock.patch.object(self.fetch.urlrequest, "getproxies", return_value={}),
            mock.patch.object(
                self.fetch.socket,
                "getaddrinfo",
                return_value=global_answer,
            ) as resolver,
        ):
            self.assertEqual(
                self.fetch.require_public_https_url(
                    "https://publisher.example/papers/item.pdf"
                ),
                "https://publisher.example/papers/item.pdf",
            )
            resolver.assert_called_once()

        with (
            mock.patch.object(self.fetch.urlrequest, "getproxies", return_value={}),
            mock.patch.object(
                self.fetch.socket,
                "getaddrinfo",
                return_value=private_answer,
            ),
            self.assertRaises(self.fetch.FetchError) as caught,
        ):
            self.fetch.require_public_https_url(
                "https://publisher.example/papers/item.pdf"
            )
        self.assertEqual(caught.exception.code, "unsafe_target")

    def test_direct_https_connection_pins_the_vetted_socket_address(self) -> None:
        vetted_answer = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", 443),
            )
        ]
        fake_socket = mock.Mock()
        tls_socket = mock.Mock()
        context = mock.Mock()
        context.wrap_socket.return_value = tls_socket
        connection = self.fetch.PinnedHTTPSConnection(
            "publisher.example",
            context=context,
        )

        with (
            mock.patch.object(
                self.fetch,
                "_resolve_global_sockaddrs",
                return_value=vetted_answer,
            ) as resolver,
            mock.patch.object(
                self.fetch.socket,
                "socket",
                return_value=fake_socket,
            ) as socket_factory,
        ):
            connection.connect()

        resolver.assert_called_once_with("publisher.example", 443)
        socket_factory.assert_called_once_with(
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
        )
        fake_socket.connect.assert_called_once_with(("93.184.216.34", 443))
        context.wrap_socket.assert_called_once_with(
            fake_socket,
            server_hostname="publisher.example",
        )
        self.assertIs(connection.sock, tls_socket)

    def test_rebinding_answer_is_rejected_before_direct_socket_connect(self) -> None:
        global_answer = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", 443),
            )
        ]
        private_answer = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("127.0.0.1", 443),
            )
        ]
        context = mock.Mock()
        with (
            mock.patch.object(self.fetch.urlrequest, "getproxies", return_value={}),
            mock.patch.object(
                self.fetch.socket,
                "getaddrinfo",
                side_effect=[global_answer, private_answer],
            ),
            mock.patch.object(self.fetch.socket, "socket") as socket_factory,
        ):
            self.fetch.require_public_https_url(
                "https://publisher.example/paper.pdf"
            )
            connection = self.fetch.PinnedHTTPSConnection(
                "publisher.example",
                context=context,
            )
            with self.assertRaises(self.fetch.FetchError) as caught:
                connection.connect()
        self.assertEqual(caught.exception.code, "unsafe_target")
        socket_factory.assert_not_called()

    def test_credentialed_https_proxy_is_rejected_without_echo(self) -> None:
        proxy_secret = "DO_NOT_FORWARD_PROXY_PASSWORD"
        proxies = (
            f"http://proxy-user:{proxy_secret}@127.0.0.1:8080",
            f"socks5://proxy-user:{proxy_secret}@proxy.example:1080",
        )
        for proxy in proxies:
            with (
                self.subTest(proxy_scheme=proxy.split(":", 1)[0]),
                mock.patch.object(
                    self.fetch.urlrequest,
                    "getproxies",
                    return_value={"https": proxy},
                ),
                mock.patch.object(
                    self.fetch.urlrequest,
                    "proxy_bypass",
                    return_value=False,
                ),
                self.assertRaises(self.fetch.FetchError) as caught,
            ):
                self.fetch.require_public_https_url(
                    "https://publisher.example/paper.pdf"
                )
            self.assertEqual(caught.exception.code, "unsafe_proxy")
            self.assertNotIn(proxy_secret, json.dumps(caught.exception.as_result()))

    def test_unsupported_https_proxy_is_rejected_before_transport(self) -> None:
        for proxy in (
            "socks5://proxy.example:1080",
            "http://proxy.example:99999",
        ):
            with (
                self.subTest(proxy=proxy),
                mock.patch.object(
                    self.fetch.urlrequest,
                    "getproxies",
                    return_value={"https": proxy},
                ),
                mock.patch.object(
                    self.fetch.urlrequest,
                    "proxy_bypass",
                    return_value=False,
                ) as proxy_bypass,
                self.assertRaises(self.fetch.FetchError) as caught,
            ):
                self.fetch.require_public_https_url(
                    "https://publisher.example/paper.pdf"
                )
            self.assertEqual(caught.exception.code, "unsafe_proxy")
            proxy_bypass.assert_not_called()

    def test_public_url_validation_rejects_private_or_malformed_targets(self) -> None:

        rejected = (
            "http://publisher.example/paper.pdf",
            "https://127.0.0.1/paper.pdf",
            "https://[::1]/paper.pdf",
            "https://metadata.google.internal/item",
            "https://localhost/item",
            "https://user:password@publisher.example/item",
        )
        for url in rejected:
            with self.subTest(url=url), self.assertRaises(self.fetch.FetchError):
                self.fetch.require_public_https_url(url)

    def test_signed_and_secret_bearing_urls_are_rejected_without_echo(self) -> None:
        secret = "DO_NOT_PERSIST_SIGNATURE"
        signed_url = (
            "https://publisher.example/paper.pdf?"
            f"X-Amz-Signature={secret}&X-Amz-Expires=300"
        )
        with self.assertRaises(self.fetch.FetchError) as caught:
            self.fetch.require_public_https_url(signed_url)
        rendered = json.dumps(caught.exception.as_result())
        self.assertNotIn(secret, rendered)
        self.assertNotIn(signed_url, rendered)

    def test_redirects_are_revalidated_bounded_and_drop_request_secrets(self) -> None:
        handler = self.fetch.PublicRedirectHandler(max_redirects=1)
        original = urlrequest.Request(
            "https://publisher.example/article",
            headers={
                "Authorization": "Bearer should-not-forward",
                "Cookie": "session=should-not-forward",
                "X-Custom": "should-not-forward",
            },
        )
        with mock.patch.object(
            self.fetch,
            "_target_uses_managed_proxy",
            return_value=True,
        ):
            redirected = handler.redirect_request(
                original,
                None,
                302,
                "Found",
                {},
                "/downloads/paper.pdf",
            )
        self.assertIsNotNone(redirected)
        self.assertEqual(
            redirected.full_url,
            "https://publisher.example/downloads/paper.pdf",
        )
        redirected_headers = dict(redirected.header_items())
        self.assertNotIn("Authorization", redirected_headers)
        self.assertNotIn("Cookie", redirected_headers)
        self.assertNotIn("X-custom", redirected_headers)
        self.assertEqual(handler.redirect_count, 1)

        with (
            mock.patch.object(
                self.fetch,
                "_target_uses_managed_proxy",
                return_value=True,
            ),
            self.assertRaises(self.fetch.FetchError) as caught,
        ):
            handler.redirect_request(
                redirected,
                None,
                302,
                "Found",
                {},
                "https://publisher.example/again.pdf",
            )
        self.assertEqual(caught.exception.code, "redirect_limit")

        private_handler = self.fetch.PublicRedirectHandler(max_redirects=2)
        with self.assertRaises(self.fetch.FetchError) as private:
            private_handler.redirect_request(
                original,
                None,
                302,
                "Found",
                {},
                "https://127.0.0.1/private.pdf",
            )
        self.assertEqual(private.exception.code, "unsafe_url")

    def test_download_writes_atomically_and_returns_nonsecret_measurements(self) -> None:
        body = b"%PDF-1.7\n" + b"public fixture bytes\n" * 20
        response = FakeResponse(
            body,
            headers={
                "Content-Length": str(len(body)),
                "Content-Type": "application/pdf; charset=binary",
                "Set-Cookie": "session=DO_NOT_PERSIST_RESPONSE_COOKIE",
            },
        )
        opener = FakeOpener(response)
        seen_handler = None

        def factory(handler):
            nonlocal seen_handler
            seen_handler = handler
            return opener

        with tempfile.TemporaryDirectory() as temporary:
            quarantine = Path(temporary) / "quarantine"
            with mock.patch.object(
                self.fetch,
                "_target_uses_managed_proxy",
                return_value=True,
            ):
                result = self.fetch.download_public_artifact(
                    "https://publisher.example/paper.pdf",
                    quarantine,
                    "work-1/paper.pdf",
                    expected_format="pdf",
                    max_bytes=len(body),
                    opener_factory=factory,
                )
            destination = quarantine / "work-1" / "paper.pdf"
            self.assertEqual(destination.read_bytes(), body)
            self.assertEqual(result["bytes"], len(body))
            self.assertEqual(result["sha256"], hashlib.sha256(body).hexdigest())
            self.assertEqual(result["format"], "pdf")
            self.assertFalse(result["verified"])
            self.assertTrue(result["quarantined"])
            self.assertEqual(result["artifact_state"], "raw_quarantine")
            self.assertFalse(result["requires_sanitize_html"])
            self.assertEqual(result["redirect_count"], 0)
            self.assertIsNotNone(seen_handler)
            self.assertTrue(response.closed)
            self.assertFalse(list(destination.parent.glob(".*.part")))

            sent_headers = dict(opener.requests[0][0].header_items())
            self.assertNotIn("Authorization", sent_headers)
            self.assertNotIn("Cookie", sent_headers)
            rendered = json.dumps(result)
            self.assertNotIn("DO_NOT_PERSIST_RESPONSE_COOKIE", rendered)
            self.assertNotIn("Set-Cookie", rendered)

    def test_downloaded_html_is_explicitly_raw_and_requires_sanitization(self) -> None:
        body = b"<!doctype html><html><body><article>Public text</article></body></html>"
        opener = FakeOpener(
            FakeResponse(
                body,
                url="https://publisher.example/article",
                headers={"Content-Type": "text/html"},
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(
                self.fetch,
                "_target_uses_managed_proxy",
                return_value=True,
            ):
                result = self.fetch.download_public_artifact(
                    "https://publisher.example/article",
                    Path(temporary) / "quarantine",
                    "article.html",
                    expected_format="html",
                    max_bytes=len(body),
                    opener_factory=lambda _handler: opener,
                )
        self.assertEqual(result["artifact_state"], "raw_quarantine")
        self.assertTrue(result["requires_sanitize_html"])
        self.assertFalse(result["verified"])

    def test_download_refuses_existing_destination_before_network(self) -> None:
        response = FakeResponse(b"%PDF-1.7\n" + b"x" * 100)
        opener = FakeOpener(response)
        with tempfile.TemporaryDirectory() as temporary:
            quarantine = Path(temporary) / "quarantine"
            destination = quarantine / "paper.pdf"
            destination.parent.mkdir(parents=True)
            destination.write_bytes(b"previous accepted bytes")

            with (
                mock.patch.object(
                    self.fetch,
                    "_target_uses_managed_proxy",
                    return_value=True,
                ),
                self.assertRaises(self.fetch.FetchError) as caught,
            ):
                self.fetch.download_public_artifact(
                    "https://publisher.example/paper.pdf",
                    quarantine,
                    "paper.pdf",
                    expected_format="pdf",
                    max_bytes=16,
                    opener_factory=lambda _handler: opener,
                )
            self.assertEqual(caught.exception.code, "destination_exists")
            self.assertEqual(destination.read_bytes(), b"previous accepted bytes")
            self.assertFalse(list(quarantine.glob(".*.part")))
            self.assertEqual(opener.requests, [])

    def test_streaming_size_failure_leaves_no_destination_and_removes_temp(self) -> None:
        response = FakeResponse(b"%PDF-1.7\n" + b"x" * 100)
        opener = FakeOpener(response)
        with tempfile.TemporaryDirectory() as temporary:
            quarantine = Path(temporary) / "quarantine"
            destination = quarantine / "paper.pdf"
            with (
                mock.patch.object(
                    self.fetch,
                    "_target_uses_managed_proxy",
                    return_value=True,
                ),
                self.assertRaises(self.fetch.FetchError) as caught,
            ):
                self.fetch.download_public_artifact(
                    "https://publisher.example/paper.pdf",
                    quarantine,
                    "paper.pdf",
                    expected_format="pdf",
                    max_bytes=16,
                    opener_factory=lambda _handler: opener,
                )
            self.assertEqual(caught.exception.code, "size_limit")
            self.assertFalse(destination.exists())
            self.assertFalse(list(quarantine.glob(".*.part")))

    def test_atomic_publish_loses_race_without_overwriting_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "paper.pdf"
            descriptor, staged = self.fetch._atomic_temp_path(destination)
            with self.fetch.os.fdopen(descriptor, "wb") as handle:
                handle.write(b"staged artifact")
                handle.flush()
                self.fetch.os.fsync(handle.fileno())
            destination.write_bytes(b"competing artifact")
            try:
                with self.assertRaises(self.fetch.FetchError) as caught:
                    self.fetch._commit_temporary(staged, destination)
                self.assertEqual(caught.exception.code, "destination_exists")
                self.assertEqual(destination.read_bytes(), b"competing artifact")
            finally:
                staged.unlink(missing_ok=True)

    def test_final_response_target_is_revalidated_even_with_custom_transport(self) -> None:
        response = FakeResponse(
            b"%PDF-1.7\nfixture",
            url="https://127.0.0.1/private.pdf",
        )
        with tempfile.TemporaryDirectory() as temporary:
            quarantine = Path(temporary) / "quarantine"
            with (
                mock.patch.object(
                    self.fetch,
                    "_target_uses_managed_proxy",
                    return_value=True,
                ),
                self.assertRaises(self.fetch.FetchError) as caught,
            ):
                self.fetch.download_public_artifact(
                    "https://publisher.example/paper.pdf",
                    quarantine,
                    "paper.pdf",
                    opener_factory=lambda _handler: FakeOpener(response),
                )
            self.assertEqual(caught.exception.code, "unsafe_url")
            self.assertFalse((quarantine / "paper.pdf").exists())

    def test_quarantine_path_cannot_escape_or_follow_output_symlink(self) -> None:
        body = b"%PDF-1.7\nfixture"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "quarantine"
            outside = Path(temporary) / "outside.pdf"
            outside_directory = Path(temporary) / "outside-directory"
            outside.write_bytes(b"outside")
            root.mkdir()
            outside_directory.mkdir()
            try:
                (root / "linked.pdf").symlink_to(outside)
                (root / "escape").symlink_to(outside_directory, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"Symbolic links are unavailable: {exc}")
            opener = FakeOpener(FakeResponse(body))
            for output in (
                "../outside.pdf",
                "linked.pdf",
                "bad:name.pdf",
                "escape/created/paper.pdf",
            ):
                with (
                    self.subTest(output=output),
                    mock.patch.object(
                        self.fetch,
                        "_target_uses_managed_proxy",
                        return_value=True,
                    ),
                    self.assertRaises(self.fetch.FetchError),
                ):
                    self.fetch.download_public_artifact(
                        "https://publisher.example/paper.pdf",
                        root,
                        output,
                        opener_factory=lambda _handler: opener,
                    )
            self.assertEqual(outside.read_bytes(), b"outside")
            self.assertFalse((outside_directory / "created").exists())
            self.assertEqual(opener.requests, [])

    def test_html_sanitizer_strips_active_remote_content_and_preserves_structure(self) -> None:
        source = """<!doctype html>
        <html lang="en"><head>
          <title>Evidence &amp; Results</title>
          <script>evil_script_should_disappear()</script>
          <style>body { background: url(https://tracker.example/pixel) }</style>
        </head><body onload="steal()">
          <main id="paper"><h1 style="color:red">Evidence &amp; Results</h1>
          <p>The substantive methods and results remain available for inspection.</p>
          <a href="https://tracker.example/out" ping="https://tracker.example/ping">External label</a>
          <a href="#methods" onclick="steal()">Methods</a>
          <img src="https://tracker.example/pixel" onerror="steal()">
          <iframe src="https://tracker.example/frame">evil_frame_text</iframe>
          <section id="methods"><h2>Methods</h2><p>Randomized comparison.</p></section>
          </main>
        </body></html>"""
        document = self.fetch.sanitize_html_snapshot(source)
        lowered = document.casefold()
        self.assertIn("Evidence &amp; Results", document)
        self.assertIn("substantive methods and results", document)
        self.assertIn('<a href="#methods">Methods</a>', document)
        self.assertIn('<section id="methods">', document)
        self.assertNotIn("tracker.example", lowered)
        self.assertNotIn("evil_script", lowered)
        self.assertNotIn("evil_frame", lowered)
        self.assertNotIn("<script", lowered)
        self.assertNotIn("<iframe", lowered)
        self.assertNotIn("<img", lowered)
        self.assertNotIn(" style=", lowered)
        self.assertNotIn(" onload=", lowered)
        self.assertNotIn(" onclick=", lowered)

        validator = self.fetch.batch.InertHTMLValidator()
        validator.feed(document)
        validator.close()
        validator.finish()
        self.assertEqual(validator.violations, [])

    def test_sanitize_file_atomically_writes_validator_compatible_html(self) -> None:
        raw = b"<article><h1>Declared title</h1><p>Complete public text.</p></article>"
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "rendered-dom.html"
            source.write_bytes(raw)
            result = self.fetch.sanitize_html_file(
                source,
                directory / "quarantine",
                "work/source.html",
                title="Declared title",
            )
            destination = Path(result["local_path"])
            saved = destination.read_bytes()
            self.assertEqual(result["sha256"], hashlib.sha256(saved).hexdigest())
            self.assertTrue(result["sanitized_inert_snapshot"])
            self.assertFalse(result["verified"])
            self.assertFalse(list(destination.parent.glob(".*.part")))

            source.write_bytes(
                b"<article><h1>Replacement</h1><p>Must not overwrite.</p></article>"
            )
            with self.assertRaises(self.fetch.FetchError) as caught:
                self.fetch.sanitize_html_file(
                    source,
                    directory / "quarantine",
                    "work/source.html",
                    title="Replacement",
                )
            self.assertEqual(caught.exception.code, "destination_exists")
            self.assertEqual(destination.read_bytes(), saved)
            self.assertFalse(list(destination.parent.glob(".*.part")))

    def test_cli_contains_unexpected_sanitizer_failure_without_traceback_or_source(self) -> None:
        marker = "MALICIOUS_SOURCE_TEXT_MUST_NOT_LEAK"
        output = io.StringIO()
        with (
            mock.patch.object(
                self.fetch,
                "sanitize_html_file",
                side_effect=RuntimeError(marker),
            ),
            contextlib.redirect_stdout(output),
        ):
            status = self.fetch.main(
                [
                    "sanitize-html",
                    "--input",
                    "untrusted.html",
                    "--quarantine-root",
                    "quarantine",
                    "--output",
                    "capture.html",
                ]
            )
        self.assertEqual(status, 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result["error"]["code"], "internal_error")
        self.assertNotIn(marker, output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())


if __name__ == "__main__":
    unittest.main()
