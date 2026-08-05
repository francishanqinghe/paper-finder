from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "paper_finder_state.py"


def load_state_module():
    spec = importlib.util.spec_from_file_location("paper_finder_state_v2", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StateV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.state_module = load_state_module()

    def access_plan(
        self,
        work_id: str,
        *,
        provider_origin: str = "https://publisher.example",
        access_mode: str = "public",
        access_generation: int = 0,
    ) -> dict:
        return {
            "work_id": work_id,
            "provider_origin": provider_origin,
            "access_mode": access_mode,
            "access_generation": access_generation,
        }

    def add_access_group(
        self,
        state: dict,
        *,
        provider_origin: str = "https://publisher.example",
        access_mode: str = "public",
        access_generation: int = 0,
    ) -> dict:
        group = self.state_module.plan_access_groups(
            [
                self.access_plan(
                    state["works"][0]["id"],
                    provider_origin=provider_origin,
                    access_mode=access_mode,
                    access_generation=access_generation,
                )
            ],
            access_policy=state["access_policy"],
        )[0]
        state["access_groups"].append(group)
        return group

    def make_attempt(
        self,
        state: dict,
        group: dict,
        attempt_id: str,
        *,
        evidence_revision: int = 0,
        status: str = "completed",
        trigger: str = "initial",
        outcome: str | None = None,
    ) -> dict:
        work = state["works"][0]
        context = {
            "work_id": work["id"],
            "version_id": work["version_ids"][0],
            "route_kind": "publisher_page",
            "provider_origin": group["provider_origin"],
            "access_mode": group["access_mode"],
            "access_generation": group["access_generation"],
            "evidence_revision": evidence_revision,
        }
        return {
            "id": attempt_id,
            **context,
            "evidence_codes": list(group["evidence_codes"][:evidence_revision]),
            "retry_fingerprint": self.state_module.retry_fingerprint(**context),
            "access_group_id": group["id"],
            "trigger": trigger,
            "suppressed_by_attempt_id": None,
            "status": status,
            "outcome": (
                outcome
                if outcome is not None
                else ("no_result" if status == "completed" else None)
            ),
        }

    def add_verified_artifact(self, state: dict) -> dict:
        work = state["works"][0]
        artifact = {
            "id": "artifact-primary",
            "work_id": work["id"],
            "version_id": work["version_ids"][0],
            "provider_origin": "https://publisher.example",
            "format": "pdf",
            "verified_url": "https://publisher.example/doi/10.1000/shared",
            "local_relpath": "papers/shared.pdf",
            "bytes": 4096,
            "sha256": "a" * 64,
            "status": "verified",
        }
        state["artifacts"].append(artifact)
        return artifact

    def test_initializer_keeps_one_request_and_work_per_input_title(self) -> None:
        state = self.state_module.new_state(["Same title", "Same title"])
        self.assertEqual(len(state["requests"]), 2)
        self.assertEqual(len(state["works"]), 2)
        self.assertNotEqual(state["requests"][0]["id"], state["requests"][1]["id"])
        self.assertNotEqual(
            state["requests"][0]["work_id"], state["requests"][1]["work_id"]
        )
        self.assertEqual(self.state_module.validate_state(state), [])

    def test_same_title_with_different_dois_does_not_merge(self) -> None:
        state = self.state_module.new_state(["Same title", "Same title"])
        first_work, second_work = [work["id"] for work in state["works"]]
        state, first_owner = self.state_module.bind_work_identity(
            state, work_id=first_work, kind="doi", value="10.1000/alpha"
        )
        state, second_owner = self.state_module.bind_work_identity(
            state, work_id=second_work, kind="doi", value="10.1000/beta"
        )
        self.assertEqual(first_owner, first_work)
        self.assertEqual(second_owner, second_work)
        self.assertEqual(len(state["works"]), 2)
        self.assertEqual(self.state_module.validate_state(state), [])

    def test_same_doi_collision_is_detected_and_binding_deduplicates(self) -> None:
        colliding = self.state_module.new_state(["Title A", "Title B"])
        for work in colliding["works"]:
            work["identity_keys"] = [{"kind": "doi", "value": "10.1000/shared"}]
        self.assertTrue(
            any("collides with another work" in error for error in self.state_module.validate_state(colliding))
        )

        state = self.state_module.new_state(["Same title", "Same title"])
        first_work, second_work = [work["id"] for work in state["works"]]
        state, owner = self.state_module.bind_work_identity(
            state, work_id=first_work, kind="doi", value="https://doi.org/10.1000/SHARED"
        )
        state, deduplicated_owner = self.state_module.bind_work_identity(
            state, work_id=second_work, kind="doi", value="doi:10.1000/shared"
        )
        self.assertEqual(owner, first_work)
        self.assertEqual(deduplicated_owner, first_work)
        self.assertEqual(len(state["works"]), 1)
        self.assertEqual(
            [request["work_id"] for request in state["requests"]],
            [first_work, first_work],
        )
        self.assertEqual(self.state_module.validate_state(state), [])

        punctuation = self.state_module.new_state(["---", "!!!"])
        punctuation_work_ids = [work["id"] for work in punctuation["works"]]
        punctuation, _ = self.state_module.bind_work_identity(
            punctuation,
            work_id=punctuation_work_ids[0],
            kind="doi",
            value="10.1000/punctuation",
        )
        with self.assertRaisesRegex(ValueError, "conflicts with the works"):
            self.state_module.bind_work_identity(
                punctuation,
                work_id=punctuation_work_ids[1],
                kind="doi",
                value="10.1000/punctuation",
            )

    def test_doi_urls_reject_credentials_queries_and_fragments_before_binding(self) -> None:
        unsafe_urls = [
            "https://reader:password@doi.org/10.1000/shared",
            "https://doi.org/10.1000/shared?source=catalog",
            "https://dx.doi.org/10.1000/shared#abstract",
        ]
        for value in unsafe_urls:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self.state_module.normalize_identity_key("doi", value)

                state = self.state_module.new_state(["Same title"])
                work_id = state["works"][0]["id"]
                with self.assertRaises(ValueError):
                    self.state_module.bind_work_identity(
                        state, work_id=work_id, kind="doi", value=value
                    )
                self.assertEqual(state["works"][0]["identity_keys"], [])

        self.assertEqual(
            self.state_module.normalize_identity_key(
                "doi", "https://doi.org/10.1000/SHARED"
            ),
            ("doi", "10.1000/shared"),
        )

    def test_duplicate_requests_can_share_one_verified_artifact(self) -> None:
        state = self.state_module.new_state(["Same title", "Same title"])
        first_work, second_work = [work["id"] for work in state["works"]]
        state, _ = self.state_module.bind_work_identity(
            state, work_id=first_work, kind="doi", value="10.1000/shared"
        )
        state, _ = self.state_module.bind_work_identity(
            state, work_id=second_work, kind="doi", value="10.1000/shared"
        )
        artifact = self.add_verified_artifact(state)
        state["works"][0]["status"] = "retrieved"
        for request in state["requests"]:
            request["status"] = "retrieved"
            request["artifact_id"] = artifact["id"]
        state["status"] = "done"
        self.assertEqual(self.state_module.validate_state(state), [])
        self.assertEqual(len(state["artifacts"]), 1)
        self.assertEqual(
            {request["work_id"] for request in state["requests"]},
            {state["artifacts"][0]["work_id"]},
        )

    def test_done_merged_work_requires_consistent_request_outcomes_and_artifacts(self) -> None:
        state = self.state_module.new_state(["Same title", "Same title"])
        first_work, second_work = [work["id"] for work in state["works"]]
        state, owner_id = self.state_module.bind_work_identity(
            state, work_id=first_work, kind="doi", value="10.1000/shared"
        )
        state, _ = self.state_module.bind_work_identity(
            state, work_id=second_work, kind="doi", value="10.1000/shared"
        )
        artifact = self.add_verified_artifact(state)
        work = state["works"][0]
        self.assertEqual(work["id"], owner_id)
        work["status"] = "retrieved"
        state["requests"][0].update(
            status="retrieved", artifact_id=artifact["id"]
        )
        state["requests"][1]["status"] = "failed"
        state["status"] = "done"

        errors = self.state_module.validate_state(state)
        self.assertTrue(
            any(
                "every request bound to a retrieved work to be retrieved" in error
                for error in errors
            )
        )

        state["requests"][1]["status"] = "retrieved"
        errors = self.state_module.validate_state(state)
        self.assertTrue(
            any("artifact_id must reference a verified artifact" in error for error in errors)
        )
        self.assertTrue(
            any(
                "reference its verified artifact" in error
                for error in errors
            )
        )

        state["requests"][1]["artifact_id"] = artifact["id"]
        self.assertEqual(self.state_module.validate_state(state), [])

        work["status"] = "failed"
        errors = self.state_module.validate_state(state)
        self.assertTrue(
            any("failed work despite a retrieved request" in error for error in errors)
        )

    def test_shared_identifier_with_conflicting_titles_requires_review(self) -> None:
        state = self.state_module.new_state(["Title A", "Title B"])
        first_work, second_work = [work["id"] for work in state["works"]]
        state, _ = self.state_module.bind_work_identity(
            state, work_id=first_work, kind="doi", value="10.1000/shared"
        )
        with self.assertRaisesRegex(ValueError, "canonical titles; review required"):
            self.state_module.bind_work_identity(
                state, work_id=second_work, kind="doi", value="10.1000/shared"
            )

    def test_strong_identity_values_must_be_unique_and_canonical(self) -> None:
        state = self.state_module.new_state(["A title"])
        state["works"][0]["identity_keys"] = [
            {"kind": "doi", "value": "10.1000/UPPER"},
            {"kind": "doi", "value": "10.1000/UPPER"},
        ]
        errors = self.state_module.validate_state(state)
        self.assertTrue(any("canonical form" in error for error in errors))
        self.assertTrue(any("duplicates an identity" in error for error in errors))

    def test_fingerprint_is_deterministic_nonsecret_and_changes_with_context(self) -> None:
        base = {
            "work_id": "work-a",
            "version_id": "version-a",
            "route_kind": "publisher_page",
            "provider_origin": "https://PUBLISHER.example/",
            "access_mode": "public",
            "access_generation": 0,
            "evidence_revision": 0,
        }
        fingerprint = self.state_module.retry_fingerprint(**base)
        canonical = self.state_module.retry_fingerprint(
            **{**base, "provider_origin": "https://publisher.example"}
        )
        self.assertEqual(fingerprint, canonical)
        self.assertRegex(fingerprint, r"^retry-sha256:[0-9a-f]{64}$")
        self.assertNotIn("work-a", fingerprint)

        changes = [
            {"work_id": "work-b"},
            {"version_id": "version-b"},
            {"route_kind": "direct_download"},
            {"provider_origin": "https://repository.example"},
            {"access_mode": "authenticated", "access_generation": 1},
            {"evidence_revision": 1},
        ]
        for change in changes:
            with self.subTest(change=change):
                self.assertNotEqual(
                    fingerprint,
                    self.state_module.retry_fingerprint(**{**base, **change}),
                )

    def test_retry_trigger_cannot_be_the_first_attempt_in_a_context(self) -> None:
        state = self.state_module.new_state(["A title"])
        group = self.add_access_group(state)
        context = {
            "work_id": state["works"][0]["id"],
            "version_id": state["works"][0]["version_ids"][0],
            "route_kind": "publisher_page",
            "provider_origin": group["provider_origin"],
            "access_mode": group["access_mode"],
            "access_generation": group["access_generation"],
            "evidence_revision": group["evidence_revision"],
        }
        with self.assertRaisesRegex(
            self.state_module.RetryCircuitOpen, "cannot reserve the first attempt"
        ):
            self.state_module.assert_retry_allowed(
                state, **context, trigger="user_retry"
            )
        self.assertEqual(
            self.state_module.assert_retry_allowed(
                state, **context, trigger="initial"
            ),
            self.state_module.retry_fingerprint(**context),
        )

    def test_retry_circuit_allows_one_unchanged_retry_then_requires_change(self) -> None:
        state = self.state_module.new_state(["A title"])
        group = self.add_access_group(state)
        context = {
            "work_id": state["works"][0]["id"],
            "version_id": state["works"][0]["version_ids"][0],
            "route_kind": "publisher_page",
            "provider_origin": group["provider_origin"],
            "access_mode": group["access_mode"],
            "access_generation": group["access_generation"],
            "evidence_revision": 0,
        }
        state["attempts"].append(self.make_attempt(state, group, "attempt-initial"))
        self.assertEqual(
            self.state_module.assert_retry_allowed(state, **context),
            self.state_module.retry_fingerprint(**context),
        )
        state["attempts"].append(
            self.make_attempt(
                state, group, "attempt-retry", trigger="user_retry"
            )
        )
        self.assertEqual(self.state_module.validate_state(state), [])
        with self.assertRaises(self.state_module.RetryCircuitOpen):
            self.state_module.assert_retry_allowed(state, **context)
        group["evidence_codes"] = ["provider_probe"]
        group["evidence_revision"] = 1
        changed = {**context, "evidence_revision": 1}
        self.assertEqual(
            self.state_module.assert_retry_allowed(
                state, **changed, trigger="initial"
            ),
            self.state_module.retry_fingerprint(**changed),
        )
        state["attempts"].append(
            self.make_attempt(
                state, group, "attempt-too-many", trigger="user_retry"
            )
        )
        self.assertTrue(
            any("retry limit" in error for error in self.state_module.validate_state(state))
        )

    def test_access_planner_groups_one_prompt_per_exact_origin_generation(self) -> None:
        state = self.state_module.new_state(["Title A", "Title B", "Title C"])
        work_ids = [work["id"] for work in state["works"]]
        groups = self.state_module.plan_access_groups(
            [
                self.access_plan(
                    work_ids[1],
                    provider_origin="https://PUBLISHER.example/",
                    access_mode="authenticated",
                    access_generation=3,
                ),
                self.access_plan(
                    work_ids[0],
                    access_mode="authenticated",
                    access_generation=3,
                ),
                self.access_plan(
                    work_ids[2],
                    provider_origin="https://sub.publisher.example",
                    access_mode="authenticated",
                    access_generation=3,
                ),
            ],
            access_policy="prompt_if_needed",
        )
        self.assertEqual(len(groups), 2)
        parent = next(group for group in groups if group["provider_origin"] == "https://publisher.example")
        self.assertEqual(parent["work_ids"], sorted(work_ids[:2]))
        self.assertEqual(parent["prompt_status"], "not_needed")
        self.assertNotEqual(groups[0]["id"], groups[1]["id"])

    def test_duplicate_access_generation_is_rejected(self) -> None:
        state = self.state_module.new_state(["A title"])
        group = self.add_access_group(
            state, access_mode="authenticated", access_generation=1
        )
        duplicate = copy.deepcopy(group)
        duplicate["id"] = "access-manual-duplicate"
        state["access_groups"].append(duplicate)
        errors = self.state_module.validate_state(state)
        self.assertTrue(any("duplicates a provider access generation" in error for error in errors))
        self.assertTrue(any("not deterministic" in error for error in errors))

    def test_public_only_policy_rejects_authenticated_cross_state(self) -> None:
        state = self.state_module.new_state(["A title"], access_policy="public_only")
        authenticated_group = self.state_module.plan_access_groups(
            [
                self.access_plan(
                    state["works"][0]["id"],
                    access_mode="authenticated",
                    access_generation=1,
                )
            ],
            access_policy="prompt_if_needed",
        )[0]
        state["access_groups"].append(authenticated_group)
        state["attempts"].append(
            self.make_attempt(state, authenticated_group, "attempt-authenticated")
        )
        errors = self.state_module.validate_state(state)
        self.assertGreaterEqual(sum("violates public_only" in error for error in errors), 2)
        with self.assertRaises(ValueError):
            self.state_module.plan_access_groups(
                [
                    self.access_plan(
                        state["works"][0]["id"],
                        access_mode="authenticated",
                        access_generation=1,
                    )
                ],
                access_policy="public_only",
            )

    def test_public_access_never_prompts_and_has_generation_zero(self) -> None:
        state = self.state_module.new_state(["A title"], access_policy="public_only")
        groups = self.state_module.plan_access_groups(
            [self.access_plan(state["works"][0]["id"])],
            access_policy="public_only",
        )
        self.assertEqual(groups[0]["prompt_status"], "not_needed")
        state["access_groups"] = groups
        self.assertEqual(self.state_module.validate_state(state), [])
        with self.assertRaises(ValueError):
            self.state_module.plan_access_groups(
                [
                    self.access_plan(
                        state["works"][0]["id"], access_generation=1
                    )
                ],
                access_policy="public_only",
            )

    def test_typed_access_state_distinguishes_login_entitlement_and_capture(self) -> None:
        state = self.state_module.new_state(["A title"])
        group = self.add_access_group(
            state, access_mode="authenticated", access_generation=1
        )
        group.update(
            authentication="signed_out",
            prompt_status="pending",
            challenge="none",
            entitlement="unknown",
            capture="unknown",
            download="not_attempted",
            next_action="sign_in",
        )
        self.assertEqual(self.state_module.validate_state(state), [])

        group.update(
            authentication="signed_in",
            entitlement="not_entitled",
            prompt_status="acknowledged",
        )
        self.assertTrue(
            any(
                "missing entitlement cannot request another sign-in" in error
                for error in self.state_module.validate_state(state)
            )
        )

        group.update(
            entitlement="entitled",
            challenge="passed",
            capture="browser_save_required",
            download="awaiting_user",
            next_action="manual_download",
        )
        self.assertEqual(self.state_module.validate_state(state), [])

    def test_public_group_cannot_claim_a_persisted_authenticated_state(self) -> None:
        state = self.state_module.new_state(["A title"], access_policy="public_only")
        group = self.add_access_group(state)
        group["authentication"] = "signed_in"
        errors = self.state_module.validate_state(state)
        self.assertTrue(any("must not carry authentication" in error for error in errors))

    def test_open_handoff_blocks_done_until_aggregated_decision_is_resolved(self) -> None:
        state = self.state_module.new_state(["A title"])
        state["requests"][0]["status"] = "failed"
        state["works"][0]["status"] = "failed"
        state["handoffs"] = [
            {
                "id": "handoff-failures",
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
        state["status"] = "done"
        self.assertTrue(
            any("handoff is unfinished" in error for error in self.state_module.validate_state(state))
        )
        state["handoffs"][0].update(status="resolved", resolution="stop")
        self.assertEqual(self.state_module.validate_state(state), [])

    def test_referential_integrity_and_globally_unique_ids_are_strict(self) -> None:
        state = self.state_module.new_state(["A title"])
        state["requests"][0]["work_id"] = "work-missing"
        state["requests"][0]["id"] = state["works"][0]["id"]
        errors = self.state_module.validate_state(state)
        self.assertTrue(any("does not reference a work" in error for error in errors))
        self.assertTrue(any("duplicates" in error for error in errors))

    def test_verified_artifact_requires_matching_origin_relative_path_and_digest(self) -> None:
        state = self.state_module.new_state(["A title"])
        artifact = self.add_verified_artifact(state)
        state["works"][0]["status"] = "retrieved"
        state["requests"][0]["status"] = "retrieved"
        state["requests"][0]["artifact_id"] = artifact["id"]
        self.assertEqual(self.state_module.validate_state(state), [])

        artifact["provider_origin"] = "https://repository.example"
        artifact["local_relpath"] = "/private/paper.pdf"
        artifact["sha256"] = "not-a-digest"
        errors = self.state_module.validate_state(state)
        self.assertTrue(any("origin must equal" in error for error in errors))
        self.assertTrue(any("relative POSIX path" in error for error in errors))
        self.assertTrue(any("SHA-256" in error for error in errors))

    def test_retrieved_request_must_reference_its_exact_verified_artifact(self) -> None:
        state = self.state_module.new_state(["Title A", "Title B"])
        artifact = self.add_verified_artifact(state)
        second_request = state["requests"][1]
        second_request.update(status="retrieved", artifact_id=artifact["id"])
        errors = self.state_module.validate_state(state)
        self.assertTrue(any("belongs to another work" in error for error in errors))

    def test_same_digest_cannot_be_bound_to_different_works(self) -> None:
        state = self.state_module.new_state(["Title A", "Title B"])
        first = self.add_verified_artifact(state)
        second_work = state["works"][1]
        state["artifacts"].append(
            {
                **first,
                "id": "artifact-conflict",
                "work_id": second_work["id"],
                "version_id": second_work["version_ids"][0],
                "local_relpath": "papers/conflict.pdf",
            }
        )
        errors = self.state_module.validate_state(state)
        self.assertTrue(any("already identifies another artifact" in error for error in errors))

    def test_signed_urls_and_credentials_are_never_accepted(self) -> None:
        state = self.state_module.new_state(["A title"])
        artifact = self.add_verified_artifact(state)
        artifact["verified_url"] = (
            "https://publisher.example/paper.pdf?X-Amz-Signature=supersecretvalue"
        )
        errors = self.state_module.validate_state(state)
        self.assertTrue(any("secret" in error for error in errors))
        self.assertTrue(any("stable safe HTTPS" in error for error in errors))
        rendered = "\n".join(errors)
        self.assertNotIn("supersecretvalue", rendered)

        with self.assertRaises(ValueError):
            self.state_module.new_state(
                ["Authorization: Bearer abcdefghijklmnopqrstuvwxyz"]
            )

    def test_unsafe_or_nonorigin_providers_are_rejected(self) -> None:
        unsafe = [
            "http://publisher.example",
            "https://localhost",
            "https://127.0.0.1",
            "https://2130706433",
            "https://metadata.google.internal",
            "https://publisher.example/path",
            "https://publisher.example?token=value",
            "https://user:password@publisher.example",
            "file:///tmp/paper.pdf",
            "https://singlelabel",
            "https://faß.de",
        ]
        for origin in unsafe:
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                self.state_module.canonical_provider_origin(origin)
        self.assertEqual(
            self.state_module.canonical_provider_origin("https://PUBLISHER.example:443/"),
            "https://publisher.example",
        )

        state = self.state_module.new_state(["A title"])
        artifact = self.add_verified_artifact(state)
        artifact["provider_origin"] = "https://fass.de"
        artifact["verified_url"] = "https://faß.de/paper"
        errors = self.state_module.validate_state(state)
        self.assertTrue(any("stable safe HTTPS" in error for error in errors))

    def test_access_attempt_and_handoff_structs_reject_unknown_sensitive_fields(self) -> None:
        state = self.state_module.new_state(["A title"])
        group = self.add_access_group(state)
        attempt = self.make_attempt(state, group, "attempt-one")
        state["attempts"].append(attempt)
        state["handoffs"].append(
            {
                "id": "handoff-one",
                "kind": "retry_review",
                "request_ids": [state["requests"][0]["id"]],
                "work_ids": [state["works"][0]["id"]],
                "access_group_ids": [group["id"]],
                "access_generation": group["access_generation"],
                "version_ids": [],
                "expected_filenames": [],
                "status": "open",
                "resolution": None,
            }
        )
        group["browser_session_id"] = "browser-secret"
        attempt["response_headers"] = {"Set-Cookie": "credential"}
        state["handoffs"][0]["page_evidence"] = "raw page contents"
        errors = self.state_module.validate_state(state)
        self.assertTrue(any("secret, session, header" in error for error in errors))
        self.assertTrue(any("unknown fields" in error for error in errors))
        rendered = "\n".join(errors)
        self.assertNotIn("browser-secret", rendered)
        self.assertNotIn("credential", rendered)
        self.assertNotIn("raw page contents", rendered)

    def test_access_plans_use_a_closed_nonsecret_schema(self) -> None:
        state = self.state_module.new_state(["A title"])
        plan = self.access_plan(state["works"][0]["id"])
        plan["cookie"] = "secret"
        with self.assertRaises(ValueError):
            self.state_module.plan_access_groups(
                [plan], access_policy="prompt_if_needed"
            )

    def test_attempt_context_must_match_fingerprint_and_access_group(self) -> None:
        state = self.state_module.new_state(["A title"])
        group = self.add_access_group(state)
        attempt = self.make_attempt(state, group, "attempt-one")
        attempt["evidence_revision"] = 1
        attempt["provider_origin"] = "https://repository.example"
        state["attempts"].append(attempt)
        errors = self.state_module.validate_state(state)
        self.assertTrue(any("fingerprint does not match" in error for error in errors))
        self.assertTrue(any("disagrees with its access group" in error for error in errors))

    def test_retrieved_attempt_cannot_be_retried_in_the_same_context(self) -> None:
        state = self.state_module.new_state(["A title"])
        group = self.add_access_group(state)
        attempt = self.make_attempt(state, group, "attempt-success")
        attempt["outcome"] = "retrieved"
        state["attempts"].append(attempt)
        work = state["works"][0]
        with self.assertRaisesRegex(self.state_module.RetryCircuitOpen, "already retrieved"):
            self.state_module.assert_retry_allowed(
                state,
                work_id=work["id"],
                version_id=work["version_ids"][0],
                route_kind="publisher_page",
                provider_origin=group["provider_origin"],
                access_mode=group["access_mode"],
                access_generation=group["access_generation"],
                evidence_revision=0,
            )

    def test_state_limits_and_open_access_handoff_uniqueness(self) -> None:
        with self.assertRaisesRegex(ValueError, "request limit"):
            self.state_module.new_state(
                ["Synthetic title"] * (self.state_module.MAX_REQUESTS + 1)
            )

        state = self.state_module.new_state(["A title"])
        group = self.add_access_group(
            state, access_mode="authenticated", access_generation=1
        )
        handoff = {
            "id": "handoff-sign-in-one",
            "kind": "sign_in",
            "request_ids": [state["requests"][0]["id"]],
            "work_ids": [state["works"][0]["id"]],
            "access_group_ids": [group["id"]],
            "access_generation": 1,
            "version_ids": [],
            "expected_filenames": [],
            "status": "open",
            "resolution": None,
        }
        duplicate = copy.deepcopy(handoff)
        duplicate.update(id="handoff-challenge-two", kind="human_challenge")
        state["handoffs"] = [handoff, duplicate]
        errors = self.state_module.validate_state(state)
        self.assertTrue(any("duplicates an active access handoff" in error for error in errors))

    def test_bind_refuses_automatic_merge_after_retrieval_history_exists(self) -> None:
        progressed = self.state_module.new_state(["Title A"])
        progressed_work_id = progressed["works"][0]["id"]
        self.add_access_group(progressed)
        with self.assertRaisesRegex(ValueError, "planning, decisions"):
            self.state_module.bind_work_identity(
                progressed,
                work_id=progressed_work_id,
                kind="doi",
                value="10.1000/new-after-planning",
            )

        state = self.state_module.new_state(["Title A", "Title B"])
        first_work, second_work = [work["id"] for work in state["works"]]
        state, _ = self.state_module.bind_work_identity(
            state, work_id=first_work, kind="doi", value="10.1000/shared"
        )
        group = self.add_access_group(state)
        state["attempts"].append(self.make_attempt(state, group, "attempt-one"))
        with self.assertRaises(ValueError):
            self.state_module.bind_work_identity(
                state, work_id=second_work, kind="doi", value="10.1000/shared"
            )

    def test_arxiv_versions_share_one_canonical_work_identity(self) -> None:
        self.assertEqual(
            self.state_module.normalize_identity_key("arxiv", "arXiv:2401.00001v1"),
            ("arxiv", "2401.00001"),
        )
        self.assertEqual(
            self.state_module.normalize_identity_key("arxiv", "2401.00001v12"),
            ("arxiv", "2401.00001"),
        )
        state = self.state_module.new_state(["Same title", "Same title"])
        first_work, second_work = [work["id"] for work in state["works"]]
        state, _ = self.state_module.bind_work_identity(
            state, work_id=first_work, kind="arxiv", value="2401.00001v1"
        )
        state, owner = self.state_module.bind_work_identity(
            state, work_id=second_work, kind="arxiv", value="2401.00001v2"
        )
        self.assertEqual(owner, first_work)
        self.assertEqual(len(state["works"]), 1)
        self.assertEqual(self.state_module.validate_state(state), [])

    def test_identity_merge_preserves_metadata_and_refuses_nonpristine_state(self) -> None:
        state = self.state_module.new_state(["Same title", "Same title"])
        first_work, second_work = [work["id"] for work in state["works"]]
        state["works"][1]["version_ids"].append("version-observed-preprint")
        state, _ = self.state_module.bind_work_identity(
            state, work_id=first_work, kind="doi", value="10.1000/shared"
        )
        state, _ = self.state_module.bind_work_identity(
            state, work_id=second_work, kind="pmid", value="123456"
        )
        state, owner = self.state_module.bind_work_identity(
            state, work_id=second_work, kind="doi", value="10.1000/shared"
        )
        surviving = state["works"][0]
        self.assertEqual(owner, first_work)
        self.assertEqual(
            surviving["identity_keys"],
            [
                {"kind": "doi", "value": "10.1000/shared"},
                {"kind": "pmid", "value": "123456"},
            ],
        )
        self.assertIn("version-observed-preprint", surviving["version_ids"])
        self.assertEqual(surviving["merge_basis"], "strong_identifier")
        self.assertEqual(self.state_module.validate_state(state), [])

        unsafe = self.state_module.new_state(["Same title", "Same title"])
        first_work, second_work = [work["id"] for work in unsafe["works"]]
        unsafe, _ = self.state_module.bind_work_identity(
            unsafe, work_id=first_work, kind="doi", value="10.1000/shared"
        )
        unsafe["requests"][1]["selected_candidate_id"] = "candidate-observed"
        with self.assertRaisesRegex(ValueError, "planning, decisions"):
            self.state_module.bind_work_identity(
                unsafe,
                work_id=second_work,
                kind="doi",
                value="10.1000/shared",
            )

    def test_shared_work_requires_an_explicit_safe_merge_basis(self) -> None:
        state = self.state_module.new_state(["Same title", "Same title"])
        owner = state["works"][0]
        state["requests"][1]["work_id"] = owner["id"]
        errors = self.state_module.validate_state(state)
        self.assertTrue(any("explicit merge basis" in error for error in errors))

        owner["merge_basis"] = "documented_lineage"
        self.assertEqual(self.state_module.validate_state(state), [])

        unrelated = self.state_module.new_state(["Canonical title", "Other title"])
        owner = unrelated["works"][0]
        owner["identity_keys"] = [{"kind": "doi", "value": "10.1000/shared"}]
        owner["merge_basis"] = "strong_identifier"
        unrelated["requests"][1]["work_id"] = owner["id"]
        errors = self.state_module.validate_state(unrelated)
        self.assertTrue(
            any("strong-identifier merge has conflicting titles" in error for error in errors)
        )
        owner_version_id = owner["version_ids"][0]
        unrelated["requests"][1].update(
            selected_candidate_id="candidate-other-title",
            selected_version_id=owner_version_id,
            decision_history=[
                {
                    "action": "select_candidate",
                    "candidate_id": "candidate-other-title",
                    "version_id": owner_version_id,
                    "comment": "Explicit selection must not authorize unsafe merging",
                    "outcome": "applied",
                }
            ],
        )
        errors = self.state_module.validate_state(unrelated)
        self.assertTrue(
            any("strong-identifier merge has conflicting titles" in error for error in errors)
        )

    def test_request_decisions_use_a_closed_request_specific_schema(self) -> None:
        state = self.state_module.new_state(["A title"])
        request = state["requests"][0]
        version_id = state["works"][0]["version_ids"][0]
        request["pending_action"] = {
            "action": "select_candidate",
            "candidate_id": "candidate-one",
            "version_id": version_id,
            "comment": "Prefer the identified version",
            "outcome": "queued",
        }
        self.assertEqual(self.state_module.validate_state(state), [])

        request["selected_candidate_id"] = "candidate-one"
        request["selected_version_id"] = version_id
        request["pending_action"] = None
        request["decision_history"] = [
            {
                "action": "select_candidate",
                "candidate_id": "candidate-one",
                "version_id": version_id,
                "comment": "Prefer the identified version",
                "outcome": "applied",
            }
        ]
        self.assertEqual(self.state_module.validate_state(state), [])

        request["decision_history"][0]["unexpected"] = True
        self.assertTrue(
            any("unknown fields" in error for error in self.state_module.validate_state(state))
        )

    def test_evidence_revision_is_a_closed_cumulative_code_prefix(self) -> None:
        state = self.state_module.new_state(["A title"])
        group = self.add_access_group(state)
        group["evidence_codes"] = ["provider_probe"]
        group["evidence_revision"] = 1
        attempt = self.make_attempt(
            state, group, "attempt-evidence-one", evidence_revision=1
        )
        state["attempts"].append(attempt)
        self.assertEqual(self.state_module.validate_state(state), [])

        group["evidence_codes"].append("new_route_available")
        group["evidence_revision"] = 2
        self.assertEqual(self.state_module.validate_state(state), [])

        attempt["evidence_codes"] = ["new_route_available"]
        self.assertTrue(
            any("revision prefix" in error for error in self.state_module.validate_state(state))
        )
        attempt["evidence_codes"] = ["provider_probe"]
        group["evidence_codes"].append("provider_specific_cookie")
        group["evidence_revision"] = 3
        self.assertTrue(
            any("unsupported code" in error for error in self.state_module.validate_state(state))
        )

    def test_reserve_attempt_is_transactional_and_records_one_suppression(self) -> None:
        initial_state = self.state_module.new_state(["A title"])
        group = self.add_access_group(initial_state)
        work = initial_state["works"][0]
        context = {
            "work_id": work["id"],
            "version_id": work["version_ids"][0],
            "route_kind": "publisher_page",
            "provider_origin": group["provider_origin"],
            "access_mode": group["access_mode"],
            "access_generation": group["access_generation"],
            "evidence_revision": 0,
        }
        state, first = self.state_module.reserve_attempt(
            initial_state, attempt_id="attempt-reserved-one", trigger="initial", **context
        )
        self.assertEqual(initial_state["attempts"], [])
        self.assertEqual(first["status"], "planned")
        with self.assertRaisesRegex(self.state_module.RetryCircuitOpen, "planned or running"):
            self.state_module.reserve_attempt(
                state, attempt_id="attempt-active-duplicate", trigger="user_retry", **context
            )

        state["attempts"][0].update(status="completed", outcome="no_result")
        state, second = self.state_module.reserve_attempt(
            state, attempt_id="attempt-reserved-two", trigger="user_retry", **context
        )
        second_record = state["attempts"][-1]
        self.assertEqual(second_record["id"], second["id"])
        second_record.update(status="completed", outcome="no_result")
        state, suppression = self.state_module.reserve_attempt(
            state, attempt_id="attempt-suppressed", trigger="user_retry", **context
        )
        self.assertEqual(suppression["outcome"], "suppressed_unchanged")
        self.assertEqual(
            suppression["suppressed_by_attempt_id"], "attempt-reserved-one"
        )
        self.assertEqual(self.state_module.validate_state(state), [])
        with self.assertRaisesRegex(self.state_module.RetryCircuitOpen, "suppression record"):
            self.state_module.reserve_attempt(
                state, attempt_id="attempt-suppressed-again", trigger="user_retry", **context
            )

    def test_missing_entitlement_suppresses_cross_revision_authenticated_retry(self) -> None:
        state = self.state_module.new_state(["A title"])
        group = self.add_access_group(
            state, access_mode="authenticated", access_generation=1
        )
        work = state["works"][0]
        context = {
            "work_id": work["id"],
            "version_id": work["version_ids"][0],
            "route_kind": "publisher_page",
            "provider_origin": group["provider_origin"],
            "access_mode": "authenticated",
            "access_generation": 1,
            "evidence_revision": 0,
        }
        state, _ = self.state_module.reserve_attempt(
            state, attempt_id="attempt-entitlement-probe", trigger="initial", **context
        )
        state["attempts"][0].update(status="completed", outcome="access_blocked")
        group = state["access_groups"][0]
        group.update(
            authentication="signed_in",
            entitlement="not_entitled",
            evidence_codes=["entitlement_changed"],
            evidence_revision=1,
            next_action="retry_public",
        )
        context["evidence_revision"] = 1
        state, suppression = self.state_module.reserve_attempt(
            state,
            attempt_id="attempt-entitlement-suppressed",
            trigger="retry_authenticated",
            **context,
        )
        self.assertEqual(suppression["outcome"], "suppressed_unchanged")
        self.assertEqual(
            suppression["suppressed_by_attempt_id"], "attempt-entitlement-probe"
        )
        self.assertEqual(self.state_module.validate_state(state), [])

    def test_duplicate_active_attempt_digest_and_path_are_rejected(self) -> None:
        state = self.state_module.new_state(["A title"])
        group = self.add_access_group(state)
        first = self.make_attempt(state, group, "attempt-active-one", status="planned")
        duplicate = copy.deepcopy(first)
        duplicate.update(id="attempt-active-two", trigger="user_retry")
        state["attempts"] = [first, duplicate]
        self.assertTrue(
            any("duplicate active attempts" in error for error in self.state_module.validate_state(state))
        )

        state = self.state_module.new_state(["A title"])
        first_artifact = self.add_verified_artifact(state)
        duplicate_artifact = copy.deepcopy(first_artifact)
        duplicate_artifact["id"] = "artifact-duplicate-bytes"
        state["artifacts"].append(duplicate_artifact)
        errors = self.state_module.validate_state(state)
        self.assertTrue(any("already identifies another artifact" in error for error in errors))
        self.assertTrue(any("already used by another artifact" in error for error in errors))

    def test_manual_handoffs_are_unique_per_work_version_and_filename_aligned(self) -> None:
        state = self.state_module.new_state(["A title"])
        work = state["works"][0]
        request = state["requests"][0]
        work["version_ids"].append("version-second")

        def handoff(handoff_id: str, version_id: str, filename: str) -> dict:
            return {
                "id": handoff_id,
                "kind": "manual_download",
                "request_ids": [request["id"]],
                "work_ids": [work["id"]],
                "access_group_ids": [],
                "access_generation": None,
                "version_ids": [version_id],
                "expected_filenames": [filename],
                "status": "open",
                "resolution": None,
            }

        state["handoffs"] = [
            handoff("handoff-manual-one", work["version_ids"][0], "paper-one.pdf"),
            handoff("handoff-manual-two", "version-second", "paper-two.pdf"),
        ]
        self.assertEqual(self.state_module.validate_state(state), [])

        state["handoffs"].append(
            handoff("handoff-manual-duplicate", "version-second", "duplicate.pdf")
        )
        self.assertTrue(
            any("duplicates an active manual" in error for error in self.state_module.validate_state(state))
        )
        state["handoffs"].pop()
        state["handoffs"][0]["expected_filenames"] = ["../paper.pdf"]
        self.assertTrue(
            any("unsafe hint" in error for error in self.state_module.validate_state(state))
        )

    def test_resolved_candidate_handoff_requires_an_applied_request_decision(self) -> None:
        state = self.state_module.new_state(["A title"])
        request = state["requests"][0]
        work = state["works"][0]
        version_id = work["version_ids"][0]
        handoff = {
            "id": "handoff-candidate",
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
        state["handoffs"] = [handoff]
        self.assertTrue(
            any("lacks a selected candidate" in error for error in self.state_module.validate_state(state))
        )

        request.update(
            selected_candidate_id="candidate-one",
            selected_version_id=version_id,
            decision_history=[
                {
                    "action": "select_candidate",
                    "candidate_id": "candidate-one",
                    "version_id": version_id,
                    "comment": "",
                    "outcome": "applied",
                }
            ],
        )
        self.assertEqual(self.state_module.validate_state(state), [])

        work["version_ids"].append("version-candidate-extra")
        request["decision_history"][0]["version_id"] = "version-candidate-extra"
        errors = self.state_module.validate_state(state)
        self.assertTrue(
            any("resolved candidate handoff lacks an applied decision" in error for error in errors)
        )
        request["decision_history"][0]["version_id"] = version_id

        handoff["version_ids"] = sorted(
            [version_id, "version-candidate-extra"]
        )
        errors = self.state_module.validate_state(state)
        self.assertTrue(
            any("candidate handoff permits at most one version" in error for error in errors)
        )

        handoff.update(kind="fallback_acceptance", resolution="accepted")
        request["decision_history"][0]["action"] = "accept_fallback"
        errors = self.state_module.validate_state(state)
        self.assertTrue(
            any("candidate handoff permits at most one version" in error for error in errors)
        )

    def test_typed_access_accepts_existing_session_and_rejects_public_signin(self) -> None:
        state = self.state_module.new_state(["A title"])
        group = self.add_access_group(
            state, access_mode="authenticated", access_generation=1
        )
        group.update(
            authentication="signed_in",
            prompt_status="not_needed",
            challenge="none",
            entitlement="entitled",
            capture="direct",
            download="available",
            next_action="probe",
        )
        self.assertEqual(self.state_module.validate_state(state), [])

        public = self.state_module.new_state(["A title"], access_policy="public_only")
        public_group = self.add_access_group(public)
        public_group["next_action"] = "sign_in"
        errors = self.state_module.validate_state(public)
        self.assertTrue(any("public access cannot request sign-in" in error for error in errors))

    def test_done_requires_terminal_work_actions_handoffs_and_provider_state(self) -> None:
        state = self.state_module.new_state(["A title"])
        request = state["requests"][0]
        work = state["works"][0]
        request["status"] = "failed"
        work["status"] = "failed"
        request["pending_action"] = {
            "action": "stop_retrying",
            "candidate_id": None,
            "version_id": None,
            "comment": "",
            "outcome": "queued",
        }
        state["status"] = "done"
        self.assertTrue(
            any("actions are pending" in error for error in self.state_module.validate_state(state))
        )
        request["pending_action"] = None
        state["handoffs"] = [
            {
                "id": "handoff-failure-submitted",
                "kind": "failure_review",
                "request_ids": [request["id"]],
                "work_ids": [work["id"]],
                "access_group_ids": [],
                "access_generation": None,
                "version_ids": [],
                "expected_filenames": [],
                "status": "submitted",
                "resolution": "stop",
            }
        ]
        self.assertTrue(
            any("handoff is unfinished" in error for error in self.state_module.validate_state(state))
        )
        state["handoffs"][0]["status"] = "resolved"
        self.assertEqual(self.state_module.validate_state(state), [])

    def test_validator_is_total_for_json_shaped_wrong_field_types(self) -> None:
        artifact_state = self.state_module.new_state(["A title"])
        artifact = self.add_verified_artifact(artifact_state)
        artifact["format"] = {}
        errors = self.state_module.validate_state(artifact_state)
        self.assertTrue(any(".format is invalid" in error for error in errors))
        self.assertFalse(any("could not be validated safely" in error for error in errors))

        attempt_state = self.state_module.new_state(["A title"])
        group = self.add_access_group(attempt_state)
        attempt = self.make_attempt(attempt_state, group, "attempt-malformed")
        attempt["status"] = {}
        attempt_state["attempts"] = [attempt]
        errors = self.state_module.validate_state(attempt_state)
        self.assertTrue(any(".status is invalid" in error for error in errors))
        self.assertFalse(any("could not be validated safely" in error for error in errors))

        handoff_state = self.state_module.new_state(["A title"])
        handoff_state["handoffs"] = [
            {
                "id": "handoff-malformed",
                "kind": "retry_review",
                "request_ids": [{}],
                "work_ids": [handoff_state["works"][0]["id"]],
                "access_group_ids": [],
                "access_generation": None,
                "version_ids": [],
                "expected_filenames": [],
                "status": {},
                "resolution": None,
            }
        ]
        errors = self.state_module.validate_state(handoff_state)
        self.assertTrue(any("request_ids must be sorted" in error for error in errors))
        self.assertTrue(any(".status is invalid" in error for error in errors))
        self.assertFalse(any("could not be validated safely" in error for error in errors))

    def test_diagnostics_redact_unknown_keys_values_and_encoded_credentials(self) -> None:
        state = self.state_module.new_state(["A title"])
        secret_key = "api_key=NEVER_ECHO_KEY_MATERIAL"
        secret_value = "Authorization: Bearer NEVER_ECHO_VALUE_MATERIAL"
        state["works"][0][secret_key] = secret_value
        errors = self.state_module.validate_state(state)
        rendered = "\n".join(errors)
        self.assertTrue(any("secret, session, header" in error for error in errors))
        self.assertTrue(any("unknown fields" in error for error in errors))
        self.assertNotIn(secret_key, rendered)
        self.assertNotIn("NEVER_ECHO_VALUE_MATERIAL", rendered)

        encoded = self.state_module.new_state(["A title"])
        artifact = self.add_verified_artifact(encoded)
        artifact["verified_url"] = (
            "https://publisher.example/paper.pdf?%61pi%5Fkey=ENCODED_SECRET"
        )
        errors = self.state_module.validate_state(encoded)
        rendered = "\n".join(errors)
        self.assertTrue(any("secret" in error for error in errors))
        self.assertTrue(any("stable safe HTTPS" in error for error in errors))
        self.assertNotIn("ENCODED_SECRET", rendered)

        semicolon_urls = [
            "https://publisher.example/article;JSESSIONID=PATH_JAVA_SECRET",
            "https://publisher.example/article;PHPSESSID=PATH_PHP_SECRET",
            "https://publisher.example/article;ASP.NET_SessionId=PATH_ASPNET_SECRET",
            "https://publisher.example/article?ok=1;sig=QUERY_SIGNATURE_SECRET",
            "https://publisher.example/article?ok=1;sid=QUERY_SID_SECRET",
            "https://publisher.example/article?ok=1;session=QUERY_SESSION_SECRET",
        ]
        for url in semicolon_urls:
            with self.subTest(url=url):
                semicolon = self.state_module.new_state(["A title"])
                artifact = self.add_verified_artifact(semicolon)
                artifact["verified_url"] = url
                errors = self.state_module.validate_state(semicolon)
                rendered = "\n".join(errors)
                self.assertTrue(any("secret" in error for error in errors))
                self.assertTrue(
                    any("stable safe HTTPS" in error for error in errors)
                )
                self.assertNotIn(url.rsplit("=", 1)[-1], rendered)

        scoped = self.state_module.new_state(["A title"])
        scoped_values = {
            "browser_profile_id": "OPAQUE_BROWSER_PROFILE_VALUE",
            "profile_id": "OPAQUE_PROFILE_VALUE",
            "browser_state": "OPAQUE_BROWSER_STATE_VALUE",
            "session_state": "OPAQUE_SESSION_STATE_VALUE",
            "session_url": "OPAQUE_SESSION_URL_VALUE",
            "publisher_browser_identifier": "OPAQUE_SCOPED_BROWSER_VALUE",
            "provider_profile_url": "OPAQUE_SCOPED_PROFILE_VALUE",
            "origin_session_state": "OPAQUE_SCOPED_SESSION_VALUE",
            "tenant_api_key": "OPAQUE_SCOPED_API_KEY_VALUE",
        }
        scoped.update(scoped_values)
        errors = self.state_module.validate_state(scoped)
        rendered = "\n".join(errors)
        self.assertTrue(any("secret, session, header" in error for error in errors))
        for key, value in scoped_values.items():
            self.assertNotIn(key, rendered)
            self.assertNotIn(value, rendered)

    def test_request_work_title_binding_requires_selection_evidence(self) -> None:
        swapped = self.state_module.new_state(["First title", "Second title"])
        first_work_id = swapped["requests"][0]["work_id"]
        second_work_id = swapped["requests"][1]["work_id"]
        swapped["requests"][0]["work_id"] = second_work_id
        swapped["requests"][1]["work_id"] = first_work_id
        errors = self.state_module.validate_state(swapped)
        self.assertEqual(
            sum("title does not match its bound work" in error for error in errors),
            2,
        )

        accepted = self.state_module.new_state(["Requested title"])
        request = accepted["requests"][0]
        work = accepted["works"][0]
        version_id = work["version_ids"][0]
        work["canonical_title"] = "Accepted expanded candidate title"
        request.update(
            selected_candidate_id="candidate-expanded",
            selected_version_id=version_id,
            decision_history=[
                {
                    "action": "select_candidate",
                    "candidate_id": "candidate-expanded",
                    "version_id": version_id,
                    "comment": "Accepted as relevant",
                    "outcome": "applied",
                }
            ],
        )
        self.assertEqual(self.state_module.validate_state(accepted), [])

        request["decision_history"][0]["candidate_id"] = "candidate-other"
        self.assertTrue(
            any(
                "title does not match its bound work" in error
                for error in self.state_module.validate_state(accepted)
            )
        )

    def test_identity_numeric_grammar_is_ascii_and_arxiv_months_are_real(self) -> None:
        self.assertEqual(
            self.state_module.normalize_identity_key("arxiv", "2401.01234v12"),
            ("arxiv", "2401.01234"),
        )
        self.assertEqual(
            self.state_module.normalize_identity_key("arxiv", "hep-th/9901001v2"),
            ("arxiv", "hep-th/9901001"),
        )
        invalid_arxiv = [
            "2400.01234",
            "2413.01234",
            "2401.01234v0",
            "2401.01234v01",
            "２４０１.０１２３４",
        ]
        for value in invalid_arxiv:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.state_module.normalize_identity_key("arxiv", value)

        non_ascii_identifiers = [
            ("doi", "10.１２３４/paper"),
            ("pmid", "１２３４"),
            ("pmcid", "PMC１２３４"),
            ("isbn", "９７８１２３４５６７８９０"),
        ]
        for kind, value in non_ascii_identifiers:
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.state_module.normalize_identity_key(kind, value)

    def test_raw_attempt_history_rejects_first_retry_and_premature_suppression(self) -> None:
        state = self.state_module.new_state(["A title"])
        group = self.add_access_group(state)
        active = self.make_attempt(
            state,
            group,
            "attempt-first-active-retry",
            status="planned",
            trigger="user_retry",
        )
        state["attempts"] = [active]
        self.assertTrue(
            any(
                "first active attempt" in error
                for error in self.state_module.validate_state(state)
            )
        )

        first = self.make_attempt(
            state, group, "attempt-first-retry", trigger="user_retry"
        )
        state["attempts"] = [first]
        self.assertTrue(
            any(
                "first completed attempt" in error
                for error in self.state_module.validate_state(state)
            )
        )

        first["trigger"] = "initial"
        suppression = copy.deepcopy(first)
        suppression.update(
            id="attempt-premature-suppression",
            trigger="suppression",
            suppressed_by_attempt_id=first["id"],
            outcome="suppressed_unchanged",
        )
        state["attempts"] = [first, suppression]
        self.assertTrue(
            any(
                "suppression is premature" in error
                for error in self.state_module.validate_state(state)
            )
        )

        first["outcome"] = "retrieved"
        self.assertEqual(self.state_module.validate_state(state), [])

    def test_handoff_scope_done_retry_and_artifact_candidates_fail_closed(self) -> None:
        scoped = self.state_module.new_state(["First title", "Second title"])
        group = self.add_access_group(scoped)
        scoped["handoffs"] = [
            {
                "id": "handoff-wrong-scope",
                "kind": "retry_review",
                "request_ids": [scoped["requests"][1]["id"]],
                "work_ids": [scoped["works"][1]["id"]],
                "access_group_ids": [group["id"]],
                "access_generation": group["access_generation"],
                "version_ids": [],
                "expected_filenames": [],
                "status": "open",
                "resolution": None,
            }
        ]
        self.assertTrue(
            any(
                "access-group scope does not cover" in error
                for error in self.state_module.validate_state(scoped)
            )
        )

        done = self.state_module.new_state(["A title"])
        request = done["requests"][0]
        work = done["works"][0]
        request["status"] = "failed"
        work["status"] = "failed"
        done["status"] = "done"
        done["handoffs"] = [
            {
                "id": "handoff-unexecuted-retry",
                "kind": "failure_review",
                "request_ids": [request["id"]],
                "work_ids": [work["id"]],
                "access_group_ids": [],
                "access_generation": None,
                "version_ids": [],
                "expected_filenames": [],
                "status": "resolved",
                "resolution": "retry",
            }
        ]
        self.assertTrue(
            any(
                "matching terminal attempt" in error
                for error in self.state_module.validate_state(done)
            )
        )

        group = self.add_access_group(done)
        group["next_action"] = "none"
        cancelled_retry = self.make_attempt(
            done,
            group,
            "attempt-cancelled-after-review",
            status="cancelled",
            trigger="user_retry",
            outcome="cancelled",
        )
        done["attempts"] = [cancelled_retry]
        self.assertTrue(
            any(
                "matching terminal attempt" in error
                for error in self.state_module.validate_state(done)
            )
        )

        initial = self.make_attempt(done, group, "attempt-before-review")
        retry = self.make_attempt(
            done, group, "attempt-after-review", trigger="user_retry"
        )
        done["attempts"] = [initial, retry]
        self.assertEqual(self.state_module.validate_state(done), [])

        candidate = self.state_module.new_state(["A title"])
        candidate["requests"][0]["status"] = "failed"
        candidate["works"][0]["status"] = "failed"
        candidate["status"] = "done"
        artifact = self.add_verified_artifact(candidate)
        artifact["status"] = "candidate"
        self.assertTrue(
            any(
                "artifact candidates remain" in error
                for error in self.state_module.validate_state(candidate)
            )
        )

    def test_control_paths_and_challenge_actions_are_rejected(self) -> None:
        state = self.state_module.new_state(["A title"])
        artifact = self.add_verified_artifact(state)
        artifact["local_relpath"] = "papers/bad\nname.pdf"
        self.assertTrue(
            any(
                "relative POSIX path" in error
                for error in self.state_module.validate_state(state)
            )
        )

        for unsafe_path in (
            "papers/CON.pdf",
            "papers/paper.pdf:secret",
            "papers/paper.pdf.",
        ):
            with self.subTest(unsafe_path=unsafe_path):
                artifact["local_relpath"] = unsafe_path
                self.assertTrue(
                    any(
                        "relative POSIX path" in error
                        for error in self.state_module.validate_state(state)
                    )
                )

        manual_state = self.state_module.new_state(["A title"])
        manual_work = manual_state["works"][0]
        manual_state["handoffs"] = [
            {
                "id": "handoff-unsafe-filename",
                "kind": "manual_download",
                "request_ids": [manual_state["requests"][0]["id"]],
                "work_ids": [manual_work["id"]],
                "access_group_ids": [],
                "access_generation": None,
                "version_ids": [manual_work["version_ids"][0]],
                "expected_filenames": ["NUL.pdf"],
                "status": "open",
                "resolution": None,
            }
        ]
        self.assertTrue(
            any(
                "unsafe hint" in error
                for error in self.state_module.validate_state(manual_state)
            )
        )

        challenge = self.state_module.new_state(["A title"])
        group = self.add_access_group(challenge)
        group["next_action"] = "complete_challenge"
        self.assertTrue(
            any(
                "requires a human-required state" in error
                for error in self.state_module.validate_state(challenge)
            )
        )
        group["challenge"] = "human_required"
        self.assertEqual(self.state_module.validate_state(challenge), [])

    def test_state_tree_rejects_unsafe_keys_and_overlarge_integers_without_echoing(self) -> None:
        non_integer_schema = self.state_module.new_state(["A title"])
        non_integer_schema["schema_version"] = 2.0
        errors = self.state_module.validate_state(non_integer_schema)
        self.assertTrue(any("must be integer 2" in error for error in errors))

        boolean_schema = self.state_module.new_state(["A title"])
        boolean_schema["schema_version"] = True
        errors = self.state_module.validate_state(boolean_schema)
        self.assertTrue(any("must be integer 2" in error for error in errors))

        non_string_key = self.state_module.new_state(["A title"])
        non_string_key[7] = "value"
        errors = self.state_module.validate_state(non_string_key)
        self.assertTrue(any("non-string mapping key" in error for error in errors))

        long_key = "NEVER_ECHO_LONG_KEY_" + (
            "x" * self.state_module.MAX_MAPPING_KEY_CHARACTERS
        )
        overlong = self.state_module.new_state(["A title"])
        overlong[long_key] = "value"
        errors = self.state_module.validate_state(overlong)
        self.assertTrue(any("overlong mapping key" in error for error in errors))
        self.assertNotIn(long_key, "\n".join(errors))

        huge = self.state_module.new_state(["A title"])
        huge["schema_version"] = 10 ** self.state_module.MAX_INTEGER_DECIMAL_DIGITS
        errors = self.state_module.validate_state(huge)
        self.assertTrue(any("overlarge integer" in error for error in errors))

    def test_state_and_planner_limits_fail_closed_without_recursion(self) -> None:
        many_errors = self.state_module.new_state(["A title"])
        many_errors["attempts"] = [
            {} for _ in range(self.state_module.MAX_STATE_ERRORS + 50)
        ]
        errors = self.state_module.validate_state(many_errors)
        self.assertLessEqual(len(errors), self.state_module.MAX_STATE_ERRORS + 1)
        self.assertIn("additional state errors omitted", errors[-1])

        state = self.state_module.new_state(["A title"])
        nested: dict = {}
        cursor = nested
        for _ in range(self.state_module.MAX_STATE_NESTING_DEPTH + 2):
            cursor["child"] = {}
            cursor = cursor["child"]
        state["too_deep"] = nested
        errors = self.state_module.validate_state(state)
        self.assertTrue(any("nesting limit" in error for error in errors))

        old_group_limit = self.state_module.MAX_ACCESS_GROUPS
        old_plan_limit = self.state_module.MAX_ACCESS_PLANS
        try:
            self.state_module.MAX_ACCESS_GROUPS = 1
            plans = [
                self.access_plan("work-one", provider_origin="https://one.example"),
                self.access_plan("work-two", provider_origin="https://two.example"),
            ]
            with self.assertRaisesRegex(ValueError, "group limit"):
                self.state_module.plan_access_groups(
                    plans, access_policy="prompt_if_needed"
                )
            self.state_module.MAX_ACCESS_GROUPS = old_group_limit
            self.state_module.MAX_ACCESS_PLANS = 1
            with self.assertRaisesRegex(ValueError, "entry limit"):
                self.state_module.plan_access_groups(
                    plans, access_policy="prompt_if_needed"
                )
        finally:
            self.state_module.MAX_ACCESS_GROUPS = old_group_limit
            self.state_module.MAX_ACCESS_PLANS = old_plan_limit


if __name__ == "__main__":
    unittest.main()
