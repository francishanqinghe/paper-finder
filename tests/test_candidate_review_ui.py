from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "paper_finder_batch.py"


def load_batch_module():
    spec = importlib.util.spec_from_file_location(
        "paper_finder_batch_candidate_review_ui",
        SCRIPT_PATH,
    )
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


class CandidateReviewUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = review_script(load_batch_module().REVIEW_HTML)

    def test_optional_review_alternatives_are_labeled_with_reason_and_relationship(
        self,
    ) -> None:
        render = function_source(
            self.script,
            "function renderCandidateReview(item, option)",
            "function actionOptions(item)",
        )
        self.assertIn('"Review-only alternative"', render)
        self.assertIn('"Relationship to request"', render)
        self.assertIn('"Why review is required"', render)
        self.assertIn("option.review_reason", render)
        self.assertIn("option.relationship || candidate?.relationship", render)
        self.assertIn("version?.label || option.version_id", render)
        self.assertIn('radio.dataset.reviewOption = "true"', render)

        item_render = function_source(
            self.script,
            "function renderItem(item)",
            "function renderItems()",
        )
        self.assertIn("const reviewOptions = candidateReviewOptions(item);", item_render)
        self.assertIn('"Review-only alternatives"', item_render)
        self.assertIn("renderCandidateReview(item, option)", item_render)

    def test_review_radio_carries_candidate_and_version_into_select_candidate(
        self,
    ) -> None:
        render = function_source(
            self.script,
            "function renderCandidateReview(item, option)",
            "function actionOptions(item)",
        )
        self.assertIn("radio.dataset.candidateId = option.candidate_id;", render)
        self.assertIn("radio.dataset.versionId = option.version_id;", render)

        save = function_source(
            self.script,
            "async function saveDecision(item, select, textarea)",
            "async function stageBulkDecision()",
        )
        self.assertIn("const selection = radioDecisionSelection(candidate);", save)
        self.assertIn("candidate_id: selection.candidate_id", save)
        self.assertIn("version_id: selection.version_id", save)

        item_render = function_source(
            self.script,
            "function renderItem(item)",
            "function renderItems()",
        )
        self.assertIn('select.value = "select_candidate";', item_render)
        self.assertIn("version_id: selection.version_id", item_render)

    def test_default_candidate_stays_selected_until_review_option_is_chosen(
        self,
    ) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is unavailable")
        helpers = function_source(
            self.script,
            "function currentDecisionSelection(item)",
            "function renderCandidate(item, candidate)",
        )
        program = f"""
const drafts = new Map();
{helpers}
const option = {{
  id: "review-option",
  candidate_id: "existing-candidate",
  version_id: "review-version"
}};
const item = {{
  id: "item-0011",
  selected_candidate_id: "existing-candidate",
  pending_action: {{type: "retry_authenticated"}},
  candidate_review: [option]
}};
const candidate = {{id: "existing-candidate"}};
const states = [];
states.push({{
  candidate: isCandidateSelected(item, candidate),
  review: isReviewOptionSelected(item, option)
}});
drafts.set(item.id, {{
  action: "select_candidate",
  candidate_id: option.candidate_id,
  version_id: option.version_id
}});
states.push({{
  candidate: isCandidateSelected(item, candidate),
  review: isReviewOptionSelected(item, option)
}});
item.pending_action = {{
  type: "select_candidate",
  candidate_id: option.candidate_id,
  version_id: option.version_id
}};
drafts.set(item.id, {{
  action: "select_candidate",
  candidate_id: option.candidate_id,
  version_id: null
}});
states.push({{
  candidate: isCandidateSelected(item, candidate),
  review: isReviewOptionSelected(item, option)
}});
const reviewRadio = {{
  value: option.id,
  dataset: {{
    candidateId: option.candidate_id,
    versionId: option.version_id
  }}
}};
const ordinaryRadio = {{
  value: candidate.id,
  dataset: {{candidateId: candidate.id}}
}};
console.log(JSON.stringify({{
  states,
  reviewSelection: radioDecisionSelection(reviewRadio),
  ordinarySelection: radioDecisionSelection(ordinaryRadio)
}}));
"""
        result = subprocess.run(
            [node, "-e", program],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = json.loads(result.stdout)
        self.assertEqual(
            observed["states"],
            [
                {"candidate": True, "review": False},
                {"candidate": False, "review": True},
                {"candidate": True, "review": False},
            ],
        )
        self.assertEqual(
            observed["reviewSelection"],
            {
                "candidate_id": "existing-candidate",
                "version_id": "review-version",
            },
        )
        self.assertEqual(
            observed["ordinarySelection"],
            {
                "candidate_id": "existing-candidate",
                "version_id": None,
            },
        )


if __name__ == "__main__":
    unittest.main()
