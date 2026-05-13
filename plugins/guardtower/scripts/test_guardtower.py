#!/usr/bin/env python3
"""Regression tests for Guardtower scanner primitives."""

from __future__ import annotations

import unittest
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import guardtower


class ThreatFilteringTests(unittest.TestCase):
    def test_rejects_generic_ai_news_roundup(self) -> None:
        text = (
            "Top AI news today: 1. Altman testifies in Musk's OpenAI suit this week "
            "2. Google blocks first AI-weaponized zero-day 3. Nebius: gigawatt"
        )

        self.assertFalse(guardtower.is_security_exploit_news(text[:140], text))

    def test_accepts_concrete_exploit_item(self) -> None:
        text = "CVE-2026-21510 is confirmed exploited in the wild for Windows RCE."

        self.assertTrue(guardtower.is_security_exploit_news(text, text))


class SurfaceNameMatchingTests(unittest.TestCase):
    def test_surface_names_do_not_match_inside_words(self) -> None:
        self.assertFalse(guardtower.surface_name_matches("Vite", "Vaultwarden allows a user to purge data."))

    def test_surface_names_match_exact_tokens_and_product_names(self) -> None:
        self.assertTrue(guardtower.surface_name_matches("Vite", "Critical vulnerability in Vite plugin chain."))
        self.assertTrue(guardtower.surface_name_matches("Next.js", "Next.js cache poisoning exploit disclosed."))


class DependencyVersionParsingTests(unittest.TestCase):
    def test_lower_bounds_are_not_exact_installed_versions(self) -> None:
        self.assertIsNone(guardtower.clean_version("pillow>=10.4.0"))
        self.assertIsNone(guardtower.clean_version("python-multipart>=0.0.9"))

    def test_exact_versions_are_preserved(self) -> None:
        self.assertEqual(guardtower.clean_version("pillow==10.4.0"), "10.4.0")
        self.assertEqual(guardtower.clean_version("10.4.0"), "10.4.0")


class ReportFormattingTests(unittest.TestCase):
    def test_excerpts_do_not_cut_words_mid_token(self) -> None:
        text = (
            "Next.js is a React framework for building full-stack web applications. "
            "From 12.2.0 to before 15.5.16 and 16.2.5, an external client could send "
            "a crafted request that triggers incorrect middleware handling."
        )

        excerpt = guardtower.text_excerpt(text, limit=150)

        self.assertFalse(excerpt.endswith("could se..."))
        self.assertTrue(excerpt.endswith("..."))

    def test_short_excerpts_are_not_modified(self) -> None:
        text = "CVE summary with enough detail."

        self.assertEqual(guardtower.text_excerpt(text), text)


class ExposureFingerprintTests(unittest.TestCase):
    def test_fingerprint_ignores_title_when_advisory_is_present(self) -> None:
        base = {
            "kind": "watched-surface-package",
            "source": "nvd-recent",
            "project": "web",
            "dependency": {"ecosystem": "npm", "name": "next", "version": "15.5.18"},
            "advisory_id": "CVE-2026-44572",
            "url": "https://github.com/vercel/next.js/security/advisories/GHSA-3g8h-86w9-wvmq",
            "title": "short title",
        }
        updated = dict(base, title="longer word-aware title with more context")

        self.assertEqual(
            guardtower.exposure_fingerprint_dict(base),
            guardtower.exposure_fingerprint_dict(updated),
        )

    def test_fingerprint_uses_title_as_fallback_without_stable_ids(self) -> None:
        base = {
            "kind": "watched-surface-mention",
            "source": "rss:example.test",
            "project": None,
            "dependency": None,
            "advisory_id": None,
            "url": None,
            "title": "one item",
        }
        updated = dict(base, title="another item")

        self.assertNotEqual(
            guardtower.exposure_fingerprint_dict(base),
            guardtower.exposure_fingerprint_dict(updated),
        )

    def test_delta_recomputes_stale_fingerprints(self) -> None:
        previous_exposure = {
            "kind": "watched-surface-package",
            "source": "nvd-recent",
            "project": "web",
            "dependency": {"ecosystem": "npm", "name": "next", "version": "15.5.18"},
            "advisory_id": "CVE-2026-44572",
            "url": "https://github.com/vercel/next.js/security/advisories/GHSA-3g8h-86w9-wvmq",
            "title": "short title",
            "fingerprint": "stale-title-derived-hash",
        }
        current_exposure = dict(previous_exposure, title="longer word-aware title")
        current_exposure.pop("fingerprint")

        delta = guardtower.compute_delta(
            {"exposures": [current_exposure], "source_failures": []},
            {"generated_at": "previous", "exposures": [previous_exposure], "source_failures": []},
        )

        self.assertEqual(delta["new"], 0)
        self.assertEqual(delta["resolved"], 0)
        self.assertEqual(delta["persisting"], 1)


class PermissionRequestTests(unittest.TestCase):
    def test_builds_fix_request_for_high_direct_package_cluster(self) -> None:
        payload = {
            "remediation_clusters": [
                {
                    "urgency": "high",
                    "package": "PyPI:urllib3@2.2.2",
                    "affected_directories": ["/workspace/api"],
                    "affected_directory_count": 1,
                    "deployment_statuses": ["container marker found"],
                    "severity": "active repo",
                    "advisories": ["GHSA-2xpw-w6gg-jr37"],
                    "exposure_count": 1,
                    "kinds": ["direct-package"],
                    "recommended_action": "Upgrade urllib3.",
                    "attribution_commands": ["cd /workspace/api && pipdeptree -r -p urllib3"],
                }
            ]
        }

        requests = guardtower.build_permission_requests({}, payload)

        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["type"], "fix")
        self.assertTrue(requests[0]["id"].startswith("GT-FIX-"))
        self.assertIn("Approve", requests[0]["question"])
        self.assertIn("Do not deploy", requests[0]["question"])

    def test_builds_review_request_for_critical_watched_surface_cluster(self) -> None:
        payload = {
            "remediation_clusters": [
                {
                    "urgency": "critical",
                    "package": "npm:next@15.5.18",
                    "affected_directories": ["/workspace/web"],
                    "affected_directory_count": 1,
                    "deployment_statuses": ["deployed"],
                    "severity": "deployed",
                    "advisories": ["CVE-2026-44572"],
                    "exposure_count": 1,
                    "kinds": ["watched-surface-package"],
                    "recommended_action": "Review applicability.",
                    "attribution_commands": ["cd /workspace/web && npm explain next"],
                }
            ]
        }

        requests = guardtower.build_permission_requests({}, payload)

        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["type"], "review")
        self.assertTrue(requests[0]["id"].startswith("GT-REVIEW-"))

    def test_permission_requests_can_be_disabled(self) -> None:
        payload = {"remediation_clusters": [{"urgency": "high", "kinds": ["direct-package"]}]}

        requests = guardtower.build_permission_requests(
            {"remediation_permission": {"enabled": False}},
            payload,
        )

        self.assertEqual(requests, [])


class ReviewStateTests(unittest.TestCase):
    def sample_exposure(self) -> dict:
        return {
            "kind": "watched-surface-package",
            "severity": "medium",
            "source": "nvd-recent",
            "project": "web",
            "dependency": {
                "ecosystem": "npm",
                "name": "next",
                "version": "15.5.18",
                "project": "web",
                "manifest": "/workspace/web/package.json",
                "source": "dependencies",
            },
            "title": "Next.js affected before 15.5.16",
            "advisory_id": "CVE-2026-44572",
            "url": "https://example.test/advisory",
            "evidence": "nvd-recent mentions watched surface nextjs and project uses npm:next",
        }

    def test_review_state_suppresses_reviewed_exposures_from_actionable_surfaces(self) -> None:
        exposure = self.sample_exposure()
        fingerprint = guardtower.exposure_fingerprint_dict(exposure)
        with tempfile.TemporaryDirectory() as directory:
            review_file = Path(directory) / "reviews.json"
            review_file.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "reviews": [
                            {
                                "fingerprint": fingerprint,
                                "status": "not_affected",
                                "reason": "Installed version is outside the affected range.",
                                "reviewed_at": "2026-05-13T00:00:00+00:00",
                                "reviewed_by": "codex",
                                "request_id": "GT-REVIEW-example",
                            }
                        ],
                    }
                )
            )
            config = {"review_state_file": str(review_file)}
            payload = {"summary": {"exposures": 1}, "exposures": [exposure], "deployment_inventory": []}

            guardtower.attach_exposure_fingerprints(payload)
            guardtower.apply_review_state(config, payload)

            self.assertEqual(payload["summary"]["raw_exposures"], 1)
            self.assertEqual(payload["summary"]["reviewed_exposures"], 1)
            self.assertEqual(payload["summary"]["exposures"], 0)
            self.assertEqual(payload["exposures"], [])
            self.assertEqual(payload["reviewed_exposures"][0]["review"]["status"], "not_affected")
            self.assertEqual(guardtower.build_action_view(config, payload), [])
            payload["remediation_clusters"] = guardtower.build_remediation_clusters(config, payload)
            self.assertEqual(payload["remediation_clusters"], [])
            self.assertEqual(guardtower.build_permission_requests(config, payload), [])

    def test_record_review_decision_can_resolve_fingerprints_from_permission_request(self) -> None:
        exposure = self.sample_exposure()
        fingerprint = guardtower.exposure_fingerprint_dict(exposure)
        exposure["fingerprint"] = fingerprint
        with tempfile.TemporaryDirectory() as directory:
            report_file = Path(directory) / "report.json"
            review_file = Path(directory) / "reviews.json"
            report_file.write_text(
                json.dumps(
                    {
                        "all_exposures": [exposure],
                        "permission_requests": [
                            {
                                "id": "GT-REVIEW-example",
                                "package": "npm:next@15.5.18",
                                "affected_directories": ["/workspace/web"],
                                "advisories": ["CVE-2026-44572"],
                            }
                        ],
                    }
                )
            )

            path, count = guardtower.record_review_decision(
                {"review_state_file": str(review_file)},
                report_file,
                request_id="GT-REVIEW-example",
                explicit_fingerprints=None,
                status="not_affected",
                reason="Installed version is outside the affected range.",
                reviewed_by="codex",
                expires_at=None,
            )

            self.assertEqual(path, review_file)
            self.assertEqual(count, 1)
            reviews = json.loads(review_file.read_text())["reviews"]
            self.assertEqual(reviews[0]["fingerprint"], fingerprint)
            self.assertEqual(reviews[0]["request_id"], "GT-REVIEW-example")
            self.assertEqual(reviews[0]["exposure"]["package"], "npm:next@15.5.18")


if __name__ == "__main__":
    unittest.main()
