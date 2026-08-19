#!/usr/bin/env python3
"""Release plumbing for the gem monorepo.

Usage:
  python3 scripts/changelog.py validate [base_branch]
  python3 scripts/changelog.py check-drift
  python3 scripts/changelog.py changes [--output-format json|github]
  python3 scripts/changelog.py package <tag> [--output-format json|github]

Commands:
  validate      Check commit messages against the conventional commit format
  check-drift   Fail if a gem's .cz.toml version disagrees with its version.rb
  changes       List gems with unreleased changes, in publish order
  package       Resolve a release tag back to the gem it belongs to

Commitizen is a Python tool, so the release scripts are Python even though this
is a Ruby repo. go-sdk does the same.
"""

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run_command(cmd: list[str], cwd: str | Path | None = None) -> tuple[int, str, str]:
    """Run a command and return exit code, stdout, stderr."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, check=False)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except Exception as e:  # noqa: BLE001 - surfaced to the caller as a failure
        return 1, "", str(e)


def get_merge_base(base_branch: str) -> str:
    exit_code, stdout, stderr = run_command(["git", "merge-base", base_branch, "HEAD"])
    if exit_code != 0:
        raise Exception(f"Failed to get merge base: {stderr}")
    return stdout


# ---------------------------------------------------------------------------
# Gem discovery
# ---------------------------------------------------------------------------


def _read_cz_config(cz_path: Path) -> dict:
    with open(cz_path, "rb") as f:
        return tomllib.load(f).get("tool", {}).get("commitizen", {})


def _gem_name_from_tag_format(tag_format: str, fallback: str) -> str:
    name = tag_format.replace("${version}-", "").replace("$version-", "")
    return name or fallback


def _sibling_dependencies(gem_dir: Path, known_gems: set[str]) -> set[str]:
    """Return the sibling gems this gem's gemspec depends on.

    Bundler's ``path:`` only works in a Gemfile, never in a gemspec, so these
    are plain version constraints: a dependent gem cannot be pushed against a
    sibling version that is not live on rubygems.org yet.
    """
    deps: set[str] = set()
    for gemspec in gem_dir.glob("*.gemspec"):
        for match in re.finditer(
            r"""add_(?:runtime_)?dependency\s+["']([^"']+)["']""", gemspec.read_text()
        ):
            if match.group(1) in known_gems:
                deps.add(match.group(1))
    return deps


def discover_gems() -> list[dict]:
    """Discover the gems in the repo, ordered so dependencies publish first.

    A gem is any top-level directory holding a ``.cz.toml``. The order matters:
    ``max-parallel: 1`` serialises the bump matrix but does not order it, and
    ``keycardai-mcp`` cannot be pushed against a ``keycardai-oauth`` version
    that is not live yet.
    """
    gems: dict[str, dict] = {}

    for cz_path in sorted(ROOT.glob("*/.cz.toml")):
        gem_dir = cz_path.parent
        config = _read_cz_config(cz_path)
        if not config:
            continue
        name = _gem_name_from_tag_format(config.get("tag_format", ""), gem_dir.name)
        gems[name] = {
            "package_name": name,
            "package_dir": str(gem_dir.relative_to(ROOT)),
            "_path": gem_dir,
        }

    if not gems:
        raise Exception("No gems with a .cz.toml were found")

    known = set(gems)
    pending = {
        name: _sibling_dependencies(gem["_path"], known) for name, gem in gems.items()
    }

    ordered: list[dict] = []
    while pending:
        # Alphabetical among gems whose dependencies are already ordered, so the
        # result is stable rather than filesystem-dependent.
        ready = sorted(name for name, deps in pending.items() if not deps)
        if not ready:
            raise Exception(f"Dependency cycle among gems: {sorted(pending)}")
        for name in ready:
            ordered.append(gems[name])
            del pending[name]
            for deps in pending.values():
                deps.discard(name)

    return [{k: v for k, v in gem.items() if not k.startswith("_")} for gem in ordered]


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def validate_commits_with_cz(base_branch: str) -> bool:
    base_sha = get_merge_base(base_branch)
    rev_range = f"{base_sha}..HEAD"

    exit_code, stdout, _ = run_command(["git", "rev-list", rev_range])
    if exit_code != 0 or not stdout.strip():
        return True  # No commits to validate

    exit_code, stdout, stderr = run_command(["cz", "check", "--rev-range", rev_range])
    if exit_code != 0:
        print(stdout or stderr)
    return exit_code == 0


def has_unreleased_changes(package_dir: str) -> bool:
    """True when ``cz changelog --dry-run`` reports entries under Unreleased."""
    exit_code, stdout, _ = run_command(["cz", "changelog", "--dry-run"], cwd=ROOT / package_dir)
    if exit_code != 0 or not stdout.strip():
        return False

    lines = stdout.split("\n")
    if not lines[0].strip().startswith("## Unreleased"):
        return False

    for line in lines[1:]:
        line = line.strip()
        if line.startswith("##"):
            break
        if line:
            return True
    return False


def detect_changed_gems() -> list[dict]:
    return [gem for gem in discover_gems() if has_unreleased_changes(gem["package_dir"])]


def extract_package_from_tag(tag: str) -> dict:
    """Resolve a ``<version>-<gem-name>`` release tag back to its gem."""
    if not tag:
        raise Exception("Tag cannot be empty")

    if tag.startswith("refs/tags/"):
        tag = tag[len("refs/tags/") :]

    for gem in discover_gems():
        suffix = gem["package_name"]
        if tag.endswith(f"-{suffix}"):
            return {
                "tag": tag,
                "version": tag[: -len(f"-{suffix}")],
                "package_name": gem["package_name"],
                "package_dir": gem["package_dir"],
                "gemspec": f"{gem['package_dir']}/{gem['package_name']}.gemspec",
            }

    raise Exception(f"No gem found for tag '{tag}'. Expected format: <version>-<gem-name>")


def read_version_file(package_dir: Path, entry: str) -> tuple[str, str | None]:
    """Read the version literal a ``version_files`` entry points at.

    Entries are ``path`` or ``path:pattern``; the pattern selects the line, and
    the version is the quoted string on it (``VERSION = "0.1.0"``).
    """
    path_part, _, pattern = entry.partition(":")
    target = package_dir / path_part
    if not target.exists():
        return path_part, None

    for line in target.read_text().splitlines():
        if pattern and not re.search(pattern, line):
            continue
        match = re.search(r"""["']([^"']+)["']""", line)
        if match:
            return path_part, match.group(1)
    return path_part, None


def check_version_drift() -> list[dict]:
    """Return drift entries, one per gem whose version files disagree.

    Commitizen treats ``[tool.commitizen].version`` as the source of truth for
    "what is the current version". ``cz bump`` computes the next version from it
    and rewrites the files in ``version_files``. Hand-edit ``version.rb`` without
    running ``cz bump`` and the two drift apart, after which the next automated
    bump tries to create a tag that already exists. Python needs no equivalent
    check: uv-dynamic-versioning derives the wheel version from the git tag, so
    it has no version file to drift. A gemspec needs a literal, so Ruby does.
    """
    drift = []

    for gem in discover_gems():
        gem_dir = ROOT / gem["package_dir"]
        config = _read_cz_config(gem_dir / ".cz.toml")
        cz_version = config.get("version")

        for entry in config.get("version_files", []):
            path_part, file_version = read_version_file(gem_dir, entry)
            if file_version is None:
                drift.append(
                    {
                        "package": gem["package_name"],
                        "file": f"{gem['package_dir']}/{path_part}",
                        "cz_version": cz_version,
                        "file_version": None,
                    }
                )
            elif cz_version and file_version != cz_version:
                drift.append(
                    {
                        "package": gem["package_name"],
                        "file": f"{gem['package_dir']}/{path_part}",
                        "cz_version": cz_version,
                        "file_version": file_version,
                    }
                )

    return drift


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def cmd_validate(args):
    if validate_commits_with_cz(args.base_branch):
        print("All commit messages are valid.")
    else:
        print(
            "\nSome commit messages are invalid. Use conventional commits, and scope "
            "gem changes with the full gem name (feat(keycardai-oauth): ...)."
        )
        sys.exit(1)


def cmd_check_drift(_args):
    drift = check_version_drift()
    if not drift:
        print("No version drift: every .cz.toml matches its version.rb.")
        return
    print("Version drift detected:")
    for d in drift:
        found = d["file_version"] or "no version literal found"
        print(f"  {d['package']}: .cz.toml says {d['cz_version']}, {d['file']} says {found}")
    print(
        "\nFix by setting [tool.commitizen].version in .cz.toml to match the version "
        "file. Change gem versions with `cz bump`, never by hand, so both stay in sync."
    )
    sys.exit(1)


def cmd_changes(args):
    changed = detect_changed_gems()
    print(json.dumps(changed, indent=2) if args.output_format == "json" else json.dumps(changed))


def cmd_package(args):
    info = extract_package_from_tag(args.tag)
    print(json.dumps(info, indent=2) if args.output_format == "json" else json.dumps(info))


def cmd_gems(args):
    gems = discover_gems()
    print(json.dumps(gems, indent=2) if args.output_format == "json" else json.dumps(gems))


def main():
    parser = argparse.ArgumentParser(description="Release plumbing for the gem monorepo")
    subparsers = parser.add_subparsers(dest="command")

    validate_p = subparsers.add_parser("validate", help="Validate commit messages")
    validate_p.add_argument("base_branch", nargs="?", default="origin/main")
    validate_p.set_defaults(func=cmd_validate)

    drift_p = subparsers.add_parser(
        "check-drift", help="Check each gem's .cz.toml version against its version.rb"
    )
    drift_p.set_defaults(func=cmd_check_drift)

    changes_p = subparsers.add_parser("changes", help="List gems with unreleased changes")
    changes_p.add_argument("--output-format", choices=["json", "github"], default="github")
    changes_p.set_defaults(func=cmd_changes)

    package_p = subparsers.add_parser("package", help="Resolve a release tag to its gem")
    package_p.add_argument("tag")
    package_p.add_argument("--output-format", choices=["json", "github"], default="github")
    package_p.set_defaults(func=cmd_package)

    gems_p = subparsers.add_parser("gems", help="List all gems in publish order")
    gems_p.add_argument("--output-format", choices=["json", "github"], default="github")
    gems_p.set_defaults(func=cmd_gems)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001 - CLI boundary
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
