from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "paper_finder_batch.py"


def load_batch_module():
    spec = importlib.util.spec_from_file_location("paper_finder_batch", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load {SCRIPT_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def review_script(review_html: str) -> str:
    match = re.search(r"<script>\s*(.*?)\s*</script>", review_html, re.DOTALL)
    if not match:
        raise AssertionError("Review page has no inline script")
    return match.group(1)


def function_source(script: str, start: str, end: str) -> str:
    start_index = script.index(start)
    end_index = script.index(end, start_index)
    return script[start_index:end_index]


class BulkReviewUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.review_html = load_batch_module().REVIEW_HTML
        cls.script = review_script(cls.review_html)

    def test_bulk_actions_are_safe_non_candidate_actions(self) -> None:
        match = re.search(
            r"const bulkActions = new Set\(\[(.*?)\]\);",
            self.script,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        self.assertEqual(
            re.findall(r'"([^"]+)"', match.group(1)),
            [
                "retry",
                "retry_authenticated",
                "retry_public",
                "skip",
                "stop_retrying",
            ],
        )

    def test_bulk_targets_only_visible_attention_without_overrides(self) -> None:
        self.assertIn(
            'return visibleItems().filter(item => category(item) === "attention");',
            self.script,
        )
        bulk_targets = function_source(
            self.script,
            "function bulkTargets()",
            "function renderBulkControls()",
        )
        self.assertIn("!item.pending_action", bulk_targets)
        self.assertIn("!dirtyItems.has(item.id)", bulk_targets)

    def test_bulk_stages_item_decisions_but_does_not_submit_batch(self) -> None:
        stage = function_source(
            self.script,
            "async function stageBulkDecision()",
            "function renderItem(item)",
        )
        finish = function_source(
            self.script,
            "async function finish(action)",
            'document.getElementById("apply")',
        )
        self.assertIn("window.confirm(", stage)
        self.assertIn("api/items/", stage)
        self.assertIn("/decision", stage)
        self.assertNotIn("api/batch", stage)
        self.assertIn("Apply decisions is still required", stage)
        self.assertIn('request("api/batch"', finish)

    def test_review_javascript_is_syntactically_valid(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is unavailable")
        result = subprocess.run(
            [node, "--check", "-"],
            input=self.script,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
