"""Unit tests for the branch, increment and recovery plumbing in bump_package.py.

Kept symmetric with python-sdk's copy, plus coverage of the recovery pre-check,
which is the half that neither sibling repo tests and the half that matters when
a merge-wait times out. Run with:

    python3 -m unittest discover -s scripts -p 'test_*.py'
"""

import json
import unittest
from unittest import mock

import bump_package


class BumpBranchNameTests(unittest.TestCase):
    def test_main_line_branch_name(self) -> None:
        self.assertEqual(
            bump_package.bump_branch_name("main", "keycardai-mcp", "1.0.1"),
            "bump/main/keycardai-mcp-1.0.1",
        )

    def test_release_line_slashes_are_sanitized(self) -> None:
        self.assertEqual(
            bump_package.bump_branch_name("release/mcp-v1", "keycardai-mcp", "1.0.1"),
            "bump/release-mcp-v1/keycardai-mcp-1.0.1",
        )


class PullBranchTests(unittest.TestCase):
    @mock.patch.object(bump_package, "run_command", return_value=(0, "", ""))
    def test_pull_branch_fetches_and_resets_to_target(self, run_command) -> None:
        self.assertTrue(bump_package.pull_branch("main"))
        run_command.assert_any_call(["git", "fetch", "origin", "main"])
        run_command.assert_any_call(["git", "reset", "--hard", "origin/main"])


class CzBumpTests(unittest.TestCase):
    @mock.patch.object(
        bump_package,
        "run_command",
        return_value=(0, "bump: keycardai-mcp 0.27.0 -> 1.0.0", ""),
    )
    def test_forced_increment_is_forwarded_to_commitizen(self, run_command) -> None:
        version = bump_package.cz_bump_files_only("mcp", "keycardai-mcp", increment="major")
        self.assertEqual(version, "1.0.0")
        command = run_command.call_args[0][0]
        self.assertIn("--increment", command)
        self.assertIn("MAJOR", command)
        # Without --allow-no-commit a forced increment fails when nothing since
        # the last tag is eligible, which is exactly the no-op bump case.
        self.assertIn("--allow-no-commit", command)

    @mock.patch.object(
        bump_package,
        "run_command",
        return_value=(0, "bump: keycardai-mcp 1.0.0 -> 1.0.1", ""),
    )
    def test_auto_increment_leaves_commitizen_derivation_alone(self, run_command) -> None:
        version = bump_package.cz_bump_files_only("mcp", "keycardai-mcp")
        self.assertEqual(version, "1.0.1")
        command = run_command.call_args[0][0]
        self.assertNotIn("--increment", command)
        self.assertNotIn("--allow-no-commit", command)

    @mock.patch.object(
        bump_package,
        "run_command",
        return_value=(0, "bump: keycardai-oauth 0.1.0 → 0.1.1\ntag to create: 0.1.1-keycardai-oauth", ""),
    )
    def test_unicode_arrow_in_cz_output_is_parsed(self, _run_command) -> None:
        # cz renders the transition with U+2192, not "->".
        self.assertEqual(bump_package.cz_bump_files_only("oauth", "keycardai-oauth"), "0.1.1")

    @mock.patch.object(
        bump_package,
        "run_command",
        return_value=(1, "", "NO_COMMITS_TO_BUMP"),
    )
    def test_no_eligible_commits_is_not_a_failure(self, _run_command) -> None:
        self.assertIsNone(bump_package.cz_bump_files_only("oauth", "keycardai-oauth"))

    @mock.patch.object(bump_package, "run_command")
    def test_untracked_changelog_is_included_in_the_commit(self, run_command) -> None:
        # update_changelog_on_bump writes CHANGELOG.md, which is untracked the
        # first time a gem is bumped, so git diff alone would miss it.
        run_command.side_effect = [
            (0, "oauth/.cz.toml\noauth/lib/keycardai/oauth/version.rb", ""),
            (0, "oauth/CHANGELOG.md", ""),
        ]
        self.assertEqual(
            bump_package.get_modified_files(),
            [
                "oauth/.cz.toml",
                "oauth/lib/keycardai/oauth/version.rb",
                "oauth/CHANGELOG.md",
            ],
        )


class RecoverUntaggedBumpTests(unittest.TestCase):
    """The pre-check that stops a timed-out run from double-bumping."""

    @mock.patch.object(bump_package, "get_configured_version", return_value="0.4.0")
    @mock.patch.object(bump_package, "tag_exists_on_remote", return_value=True)
    def test_nothing_to_recover_when_the_tag_already_exists(self, _tag, _version) -> None:
        self.assertIsNone(bump_package.recover_untagged_bump("o/r", "keycardai-oauth", "oauth"))

    @mock.patch.object(bump_package, "get_configured_version", return_value="0.4.0")
    @mock.patch.object(bump_package, "tag_exists_on_remote", return_value=False)
    @mock.patch.object(bump_package, "run_command", return_value=(0, "", ""))
    def test_nothing_to_recover_when_no_bump_commit_is_merged(self, _run, _tag, _version) -> None:
        # Version ahead of the last tag but no merged bump commit: the normal
        # bump flow should proceed rather than tagging something arbitrary.
        self.assertIsNone(bump_package.recover_untagged_bump("o/r", "keycardai-oauth", "oauth"))

    @mock.patch.object(bump_package, "get_configured_version", return_value="0.4.0")
    @mock.patch.object(bump_package, "tag_exists_on_remote", return_value=False)
    @mock.patch.object(bump_package, "create_and_push_tag", return_value=True)
    @mock.patch.object(bump_package, "run_command", return_value=(0, "abc123def456", ""))
    def test_merged_bump_without_a_tag_pushes_the_missing_tag(
        self, run_command, create_tag, _tag, _version
    ) -> None:
        self.assertTrue(bump_package.recover_untagged_bump("o/r", "keycardai-oauth", "oauth"))
        create_tag.assert_called_once_with("o/r", "0.4.0-keycardai-oauth", "abc123def456")

        # The grep has to match the headline create_signed_commit_on_branch
        # writes, arrow included, or recovery silently never fires.
        grep_arg = next(a for a in run_command.call_args[0][0] if a.startswith("--grep="))
        self.assertEqual(grep_arg, "--grep=bump: keycardai-oauth → 0.4.0")
        self.assertIn("--fixed-strings", run_command.call_args[0][0])

    @mock.patch.object(bump_package, "get_configured_version", return_value="0.4.0")
    @mock.patch.object(bump_package, "tag_exists_on_remote", return_value=False)
    @mock.patch.object(bump_package, "create_and_push_tag", return_value=False)
    @mock.patch.object(bump_package, "run_command", return_value=(0, "abc123def456", ""))
    def test_failed_tag_push_fails_the_run(self, _run, _create, _tag, _version) -> None:
        self.assertFalse(bump_package.recover_untagged_bump("o/r", "keycardai-oauth", "oauth"))


class ChecksGreenTests(unittest.TestCase):
    def test_empty_rollup_counts_as_green(self) -> None:
        self.assertTrue(bump_package.checks_green({"statusCheckRollup": []}))

    def test_all_successful_checks_are_green(self) -> None:
        rollup = [
            {"status": "COMPLETED", "conclusion": "SUCCESS"},
            {"status": "COMPLETED", "conclusion": "SKIPPED"},
            {"status": "COMPLETED", "conclusion": "NEUTRAL"},
        ]
        self.assertTrue(bump_package.checks_green({"statusCheckRollup": rollup}))

    def test_a_running_check_is_not_green(self) -> None:
        rollup = [
            {"status": "COMPLETED", "conclusion": "SUCCESS"},
            {"status": "IN_PROGRESS", "conclusion": None},
        ]
        self.assertFalse(bump_package.checks_green({"statusCheckRollup": rollup}))

    def test_a_failed_check_is_not_green(self) -> None:
        rollup = [{"status": "COMPLETED", "conclusion": "FAILURE"}]
        self.assertFalse(bump_package.checks_green({"statusCheckRollup": rollup}))


class PrCreationTests(unittest.TestCase):
    @mock.patch.object(bump_package, "wait_for_pr_stable", return_value=True)
    @mock.patch.object(
        bump_package,
        "run_command",
        side_effect=[
            (0, "https://github.com/keycardai/ruby-sdk/pull/999", ""),  # gh pr create
            (0, "", ""),  # gh pr merge --auto --squash
        ],
    )
    def test_pr_targets_the_requested_branch_and_arms_automerge(
        self, run_command, _stable
    ) -> None:
        pr_number = bump_package.create_pr_with_automerge(
            "bump/main/keycardai-oauth-0.1.1", "main", "keycardai-oauth", "0.1.1"
        )
        self.assertEqual(pr_number, 999)

        create = run_command.call_args_list[0][0][0]
        self.assertEqual(create[create.index("--base") + 1], "main")
        # The PR title becomes the squash subject on main, and main.yml's
        # anti-recursion guard keys off the "bump:" prefix.
        self.assertEqual(create[create.index("--title") + 1], "bump: keycardai-oauth → 0.1.1")

        merge = run_command.call_args_list[1][0][0]
        self.assertIn("--auto", merge)
        self.assertIn("--squash", merge)


class DirectMergeTests(unittest.TestCase):
    """Green checks must trigger an explicit merge, not just wait on auto-merge."""

    @mock.patch.object(bump_package, "time")
    @mock.patch.object(bump_package, "run_command")
    def test_green_open_pr_is_merged_explicitly(self, run_command, mock_time) -> None:
        mock_time.time.side_effect = [0, 1, 2, 3, 4, 5]
        open_and_green = {
            "state": "OPEN",
            "statusCheckRollup": [{"status": "COMPLETED", "conclusion": "SUCCESS"}],
            "headRefOid": "head123",
        }
        merged = {"state": "MERGED", "mergeCommit": {"oid": "squash456"}}
        run_command.side_effect = [
            (0, json.dumps(open_and_green), ""),  # gh pr view
            (0, "", ""),  # gh pr merge --squash
            (0, json.dumps(merged), ""),  # gh pr view
        ]

        sha = bump_package.wait_for_pr_merge("o/r", 999, "main")
        self.assertEqual(sha, "squash456")

        merge_call = run_command.call_args_list[1][0][0]
        self.assertEqual(merge_call, ["gh", "pr", "merge", "999", "--squash"])

    @mock.patch.object(bump_package, "time")
    @mock.patch.object(bump_package, "run_command")
    def test_refused_merge_falls_back_to_fast_forwarding_the_branch(
        self, run_command, mock_time
    ) -> None:
        mock_time.time.side_effect = [0, 1, 2, 3, 4, 5]
        open_and_green = {
            "state": "OPEN",
            "statusCheckRollup": [{"status": "COMPLETED", "conclusion": "SUCCESS"}],
            "headRefOid": "head123",
        }
        merged = {"state": "MERGED", "mergeCommit": {"oid": "squash456"}}
        run_command.side_effect = [
            (0, json.dumps(open_and_green), ""),  # gh pr view
            (1, "", "Protected branch update failed"),  # gh pr merge --squash
            (0, "", ""),  # gh api PATCH refs/heads/main
            (0, json.dumps(merged), ""),  # gh pr view
        ]

        self.assertEqual(bump_package.wait_for_pr_merge("o/r", 999, "main"), "squash456")

        patch_call = run_command.call_args_list[2][0][0]
        self.assertIn("repos/o/r/git/refs/heads/main", patch_call)
        self.assertIn("sha=head123", patch_call)

    @mock.patch.object(bump_package, "time")
    @mock.patch.object(bump_package, "run_command")
    def test_closed_pr_stops_the_run(self, run_command, mock_time) -> None:
        mock_time.time.side_effect = [0, 1, 2]
        run_command.return_value = (0, json.dumps({"state": "CLOSED"}), "")
        self.assertIsNone(bump_package.wait_for_pr_merge("o/r", 999, "main"))


class TagCreationTests(unittest.TestCase):
    @mock.patch.object(bump_package, "run_command", return_value=(0, "", ""))
    def test_tag_is_created_at_the_squash_sha_via_the_refs_api(self, run_command) -> None:
        self.assertTrue(
            bump_package.create_and_push_tag("o/r", "0.1.1-keycardai-oauth", "squash456")
        )
        command = run_command.call_args[0][0]
        self.assertIn("repos/o/r/git/refs", command)
        self.assertIn("ref=refs/tags/0.1.1-keycardai-oauth", command)
        self.assertIn("sha=squash456", command)


if __name__ == "__main__":
    unittest.main()
