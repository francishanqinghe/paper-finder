from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
CALENDAR_DATE = re.compile(
    r"(?:\b20\d{2}-\d{2}-\d{2}\b|"
    r"\b(?:January|February|March|April|May|June|July|August|September|"
    r"October|November|December)\s+\d{1,2}\b)"
)
LOCAL_HOME = re.compile(
    r"(?:/Users/[^/\s]+|/home/[^/\s]+|[A-Za-z]:\\Users\\[^\\\s]+)"
)
NARROW_NAME = re.compile(
    r"(?:^|_)(?:current|round\d+|item\d+|r\d{3})(?:_|$)",
    re.IGNORECASE,
)
FIXED_ITEM_ID = re.compile(r"\b(?:item-\d{4}|R\d{3})\b", re.IGNORECASE)
FIXED_EXPECTED_COUNT = re.compile(
    r"\b(?:DEFAULT_)?EXPECTED_[A-Z_]*COUNT\s*=\s*\d+\b"
)
NUMBERED_ROUND = re.compile(r"\b(?:retry[_ -]?)?round[_ -]?\d+\b", re.IGNORECASE)


class SkillRepositoryHygieneTests(unittest.TestCase):
    def script_paths(self) -> list[Path]:
        return sorted(SCRIPTS.glob("*.py"))

    def test_script_names_are_not_bound_to_one_run(self) -> None:
        offenders = [
            path.name for path in self.script_paths() if NARROW_NAME.search(path.stem)
        ]
        self.assertEqual(offenders, [])

    def test_scripts_do_not_embed_run_specific_dates(self) -> None:
        offenders = [
            path.name
            for path in self.script_paths()
            if CALENDAR_DATE.search(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [])

    def test_scripts_do_not_embed_fixed_item_ids(self) -> None:
        offenders = [
            path.name
            for path in self.script_paths()
            if FIXED_ITEM_ID.search(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [])

    def test_scripts_do_not_embed_fixed_expected_batch_counts(self) -> None:
        offenders = [
            path.name
            for path in self.script_paths()
            if FIXED_EXPECTED_COUNT.search(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [])

    def test_scripts_do_not_embed_numbered_retry_rounds(self) -> None:
        offenders = [
            path.name
            for path in self.script_paths()
            if NUMBERED_ROUND.search(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [])

    def test_scripts_do_not_embed_local_user_home_paths(self) -> None:
        offenders = [
            path.name
            for path in self.script_paths()
            if LOCAL_HOME.search(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
