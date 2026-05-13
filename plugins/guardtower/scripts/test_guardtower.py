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


if __name__ == "__main__":
    unittest.main()
