#!/usr/bin/env python3
"""Regression tests for Guardtower scanner primitives."""

from __future__ import annotations

import unittest
import sys
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


if __name__ == "__main__":
    unittest.main()
