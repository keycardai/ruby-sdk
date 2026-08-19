"""Unit tests for scripts/changelog.py.

Run with:

    python3 -m unittest discover -s scripts -p 'test_*.py'
"""

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import changelog

FIXTURE_CZ = """\
[tool.commitizen]
version = "{version}"
version_files = ["lib/keycardai/{slug}/version.rb:VERSION"]
tag_format = "${{version}}-keycardai-{slug}"
"""

FIXTURE_VERSION_RB = """\
# frozen_string_literal: true

module Keycardai
  module {const}
    VERSION = "{version}"
  end
end
"""


def build_repo(root: Path, gems: dict[str, dict]) -> None:
    """Lay out a miniature gem monorepo under ``root``.

    ``gems`` maps a directory slug to ``{const, cz_version, rb_version, deps}``.
    """
    for slug, spec in gems.items():
        gem_dir = root / slug
        lib_dir = gem_dir / "lib" / "keycardai" / slug
        lib_dir.mkdir(parents=True)

        (gem_dir / ".cz.toml").write_text(
            FIXTURE_CZ.format(version=spec["cz_version"], slug=slug)
        )
        (lib_dir / "version.rb").write_text(
            FIXTURE_VERSION_RB.format(const=spec["const"], version=spec["rb_version"])
        )

        deps = "\n".join(f'  spec.add_dependency "{d}", ">= 0.1.0"' for d in spec.get("deps", []))
        (gem_dir / f"keycardai-{slug}.gemspec").write_text(
            f'Gem::Specification.new do |spec|\n  spec.name = "keycardai-{slug}"\n{deps}\nend\n'
        )


THREE_GEMS = {
    "oauth": {"const": "OAuth", "cz_version": "0.1.0", "rb_version": "0.1.0"},
    "mcp": {
        "const": "MCP",
        "cz_version": "0.1.0",
        "rb_version": "0.1.0",
        "deps": ["keycardai-oauth", "rack"],
    },
    "a2a": {
        "const": "A2A",
        "cz_version": "0.1.0",
        "rb_version": "0.1.0",
        "deps": ["keycardai-oauth"],
    },
}


class GemMonorepoTestCase(unittest.TestCase):
    """Points changelog.ROOT at a temporary gem layout for the duration."""

    gems = THREE_GEMS

    def setUp(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        build_repo(tmp, self.gems)

        patcher = mock.patch.object(changelog, "ROOT", tmp)
        patcher.start()
        self.addCleanup(patcher.stop)


class DiscoverGemsTests(GemMonorepoTestCase):
    def test_dependencies_are_ordered_before_dependents(self) -> None:
        names = [gem["package_name"] for gem in changelog.discover_gems()]
        self.assertEqual(names[0], "keycardai-oauth")
        self.assertLess(names.index("keycardai-oauth"), names.index("keycardai-mcp"))
        self.assertLess(names.index("keycardai-oauth"), names.index("keycardai-a2a"))

    def test_order_is_stable_not_filesystem_dependent(self) -> None:
        first = [gem["package_name"] for gem in changelog.discover_gems()]
        second = [gem["package_name"] for gem in changelog.discover_gems()]
        self.assertEqual(first, second)
        # Ties among independent gems break alphabetically.
        self.assertEqual(first, ["keycardai-oauth", "keycardai-a2a", "keycardai-mcp"])

    def test_gem_name_and_dir_come_from_the_tag_format(self) -> None:
        gems = {gem["package_name"]: gem["package_dir"] for gem in changelog.discover_gems()}
        self.assertEqual(gems["keycardai-oauth"], "oauth")
        self.assertEqual(gems["keycardai-mcp"], "mcp")

    def test_third_party_dependencies_are_not_treated_as_gems(self) -> None:
        # keycardai-mcp's gemspec also depends on rack, which this repo does not
        # ship. If rack leaked into the graph, ordering would never resolve.
        names = [gem["package_name"] for gem in changelog.discover_gems()]
        self.assertEqual(len(names), 3)
        self.assertNotIn("rack", names)


class ExtractPackageFromTagTests(GemMonorepoTestCase):
    def test_resolves_tag_to_gem_and_gemspec(self) -> None:
        info = changelog.extract_package_from_tag("0.4.1-keycardai-mcp")
        self.assertEqual(info["version"], "0.4.1")
        self.assertEqual(info["package_name"], "keycardai-mcp")
        self.assertEqual(info["package_dir"], "mcp")
        self.assertEqual(info["gemspec"], "mcp/keycardai-mcp.gemspec")

    def test_strips_refs_tags_prefix(self) -> None:
        info = changelog.extract_package_from_tag("refs/tags/1.2.3-keycardai-oauth")
        self.assertEqual(info["version"], "1.2.3")
        self.assertEqual(info["package_name"], "keycardai-oauth")

    def test_unknown_tag_raises(self) -> None:
        with self.assertRaises(Exception):
            changelog.extract_package_from_tag("1.0.0-keycardai-nope")


class CheckDriftTests(GemMonorepoTestCase):
    def test_matching_versions_report_no_drift(self) -> None:
        self.assertEqual(changelog.check_version_drift(), [])

    def test_hand_edited_version_rb_is_caught(self) -> None:
        version_rb = changelog.ROOT / "oauth" / "lib" / "keycardai" / "oauth" / "version.rb"
        version_rb.write_text(version_rb.read_text().replace("0.1.0", "0.9.9"))

        drift = changelog.check_version_drift()
        self.assertEqual(len(drift), 1)
        self.assertEqual(drift[0]["package"], "keycardai-oauth")
        self.assertEqual(drift[0]["cz_version"], "0.1.0")
        self.assertEqual(drift[0]["file_version"], "0.9.9")

    def test_rubygems_prerelease_syntax_is_caught_as_drift(self) -> None:
        # The failure this check exists for: commitizen renders "0.1.0.pre" as
        # "0.1.0-rc0", never finds it in version.rb, and advances .cz.toml alone.
        version_rb = changelog.ROOT / "mcp" / "lib" / "keycardai" / "mcp" / "version.rb"
        version_rb.write_text(version_rb.read_text().replace('"0.1.0"', '"0.1.0.pre"'))

        drift = changelog.check_version_drift()
        self.assertEqual([d["package"] for d in drift], ["keycardai-mcp"])
        self.assertEqual(drift[0]["file_version"], "0.1.0.pre")

    def test_missing_version_file_is_drift_not_a_crash(self) -> None:
        (changelog.ROOT / "a2a" / "lib" / "keycardai" / "a2a" / "version.rb").unlink()

        drift = changelog.check_version_drift()
        self.assertEqual([d["package"] for d in drift], ["keycardai-a2a"])
        self.assertIsNone(drift[0]["file_version"])


class ReadVersionFileTests(GemMonorepoTestCase):
    def test_pattern_selects_the_matching_line(self) -> None:
        gem_dir = changelog.ROOT / "oauth"
        path, version = changelog.read_version_file(
            gem_dir, "lib/keycardai/oauth/version.rb:VERSION"
        )
        self.assertEqual(path, "lib/keycardai/oauth/version.rb")
        self.assertEqual(version, "0.1.0")

    def test_entry_without_a_pattern_is_accepted(self) -> None:
        gem_dir = changelog.ROOT / "oauth"
        path, version = changelog.read_version_file(gem_dir, "lib/keycardai/oauth/version.rb")
        self.assertEqual(path, "lib/keycardai/oauth/version.rb")
        self.assertEqual(version, "0.1.0")

    def test_pattern_that_matches_nothing_yields_no_version(self) -> None:
        gem_dir = changelog.ROOT / "oauth"
        _, version = changelog.read_version_file(
            gem_dir, "lib/keycardai/oauth/version.rb:NOT_A_CONSTANT"
        )
        self.assertIsNone(version)


class DetectChangedGemsTests(GemMonorepoTestCase):
    def test_changed_gems_keep_publish_order(self) -> None:
        with mock.patch.object(changelog, "has_unreleased_changes", return_value=True):
            names = [gem["package_name"] for gem in changelog.detect_changed_gems()]
        self.assertEqual(names[0], "keycardai-oauth")

    def test_gems_without_unreleased_changes_are_dropped(self) -> None:
        with mock.patch.object(
            changelog, "has_unreleased_changes", side_effect=lambda d: d == "mcp"
        ):
            names = [gem["package_name"] for gem in changelog.detect_changed_gems()]
        self.assertEqual(names, ["keycardai-mcp"])


class HasUnreleasedChangesTests(GemMonorepoTestCase):
    def test_unreleased_section_with_entries_counts_as_changed(self) -> None:
        output = "## Unreleased\n\n- fix(keycardai-oauth): tighten issuer check\n\n## 0.1.0-keycardai-oauth (2026-08-18)"
        with mock.patch.object(changelog, "run_command", return_value=(0, output, "")):
            self.assertTrue(changelog.has_unreleased_changes("oauth"))

    def test_empty_unreleased_section_counts_as_unchanged(self) -> None:
        output = "## Unreleased\n\n## 0.1.0-keycardai-oauth (2026-08-18)"
        with mock.patch.object(changelog, "run_command", return_value=(0, output, "")):
            self.assertFalse(changelog.has_unreleased_changes("oauth"))

    def test_changelog_without_an_unreleased_section_counts_as_unchanged(self) -> None:
        output = "## 0.1.0-keycardai-oauth (2026-08-18)\n\n- feat(keycardai-oauth): initial"
        with mock.patch.object(changelog, "run_command", return_value=(0, output, "")):
            self.assertFalse(changelog.has_unreleased_changes("oauth"))


if __name__ == "__main__":
    unittest.main()
