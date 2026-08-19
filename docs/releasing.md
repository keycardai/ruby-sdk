# Releasing

Three gems release independently from one repo. Which gem releases is decided by
the **scope on your commit subject**, not by which files you touched.

## The path a change takes

1. You merge a PR whose squash subject is `feat(keycardai-oauth): ...`.
2. `main.yml` runs `changelog.py changes`, which asks commitizen, per gem,
   whether anything since that gem's last tag matches its `changelog_pattern`.
3. For each gem with changes it calls `bump-package.yml`, one at a time.
4. `bump_package.py` runs `cz bump --files-only`, opens a bump PR from the
   release app, merges it once checks are green, and creates
   `<version>-<gem-name>` at the squash SHA.
5. That tag triggers `release.yml`, which builds the gem and pushes it to
   rubygems.org using trusted publishing.

Nothing about step 1 is inferred from paths. A commit that edits `oauth/` with
the scope `keycardai-mcp` releases mcp.

## Commit scopes

| Change in | Scope |
| --- | --- |
| `oauth/` | `keycardai-oauth` |
| `mcp/` | `keycardai-mcp` |
| `a2a/` | `keycardai-a2a` |
| anywhere else | no scope |

The scope must be the **full gem name**. `feat(oauth):` matches nothing, so
`detect-changes` returns empty and nothing releases, with no error anywhere.

Releasable types are `feat`, `fix`, `refactor`, `perf`, `test`, `build`, `ci`,
`revert`. `docs`, `chore` and `style` are deliberately absent: a docs-only
change must not cut a release.

Increments: `feat` is a minor, `fix`/`refactor`/`perf` are patches, and a `!`
after the scope (`feat(keycardai-oauth)!:`) is a major. While
`major_version_zero = true` a major lands as a minor instead. **Flip
`major_version_zero` to `false` in that gem's `.cz.toml` the moment it reaches
1.0.0**, or breaking changes keep landing as minors.

Squash merges are what main sees, so the **PR title** is what carries the scope.

## Repo settings this depends on

| Setting | Value |
| --- | --- |
| Variable `SDK_RELEASE_APP_ID` | the Keycard SDK Release app id |
| Secret `SDK_RELEASE_PRIVATE_KEY` | that app's private key |
| Environment | `release` |
| Allow auto-merge | enabled |
| Squash merge | enabled |
| Keycard SDK Release app | installed, contents:write + pull-requests:write |

`main.yml` skips the bump job entirely while `SDK_RELEASE_APP_ID` is unset, and
logs a warning annotation when it does, so an unconfigured repo is visible
rather than silently quiet.

On rubygems.org each gem needs a **pending trusted publisher**: repository
`keycardai/ruby-sdk`, workflow `release.yml`, environment `release`. Pending
publishers work for gems that do not exist yet. The workflow filename and the
environment name are both part of the match, so renaming either breaks
publishing with an auth error rather than something obvious.

No registry API token is needed, and none should be created.

## Proving the pipeline without a real change

Run `bump-package.yml` from the Actions tab with `increment` forced:

```
gh workflow run bump-package.yml \
  -f package_name=keycardai-oauth -f package_dir=oauth -f increment=patch
```

The forced increment passes `--allow-no-commit`, so it works even when nothing
since the last tag is eligible. Watch for: a `bump/main/keycardai-oauth-<v>`
branch, a `bump: keycardai-oauth → <v>` PR that merges itself, and the tag at
the squash SHA.

## The first release

Until a gem has its first tag, commitizen walks the whole history, and the
older PR squash subjects in this repo already carry gem scopes. So the first
automated bump computes from all of that rather than from nothing, and lands on
0.2.0 rather than 0.1.0.

If 0.1.0 should be the first published version, create the baseline tags by hand
at a green main SHA, in dependency order, and let `release.yml` publish each:

```
gh api repos/keycardai/ruby-sdk/git/refs -f ref="refs/tags/0.1.0-keycardai-oauth" -f sha=<main-sha>
# wait for the oauth publish to go green, then
gh api repos/keycardai/ruby-sdk/git/refs -f ref="refs/tags/0.1.0-keycardai-a2a" -f sha=<main-sha>
gh api repos/keycardai/ruby-sdk/git/refs -f ref="refs/tags/0.1.0-keycardai-mcp" -f sha=<main-sha>
```

After that every gem has a baseline and bumps compute from real deltas.

## Publish order

`keycardai-oauth` first, then `keycardai-mcp` and `keycardai-a2a` in either
order. Bundler's `path:` source works only in a Gemfile, never in a gemspec, so
the sibling dependencies are plain version constraints and a dependent gem
cannot be pushed against an oauth version that is not live.

`changelog.py` topologically sorts gems by their gemspec sibling dependencies,
so the bump matrix is emitted in that order. `max-parallel: 1` serialises it but
does not order it, which is why the ordering lives in the script.

`release.yml` waits for each push to become queryable before going green, but
the three release runs are independent, so a hand-driven first publish should
still wait for oauth to finish before tagging the others.

## When something goes wrong

**A bump PR merged but nothing published.** The tag is missing. Re-running the
bump job is safe: the recovery pre-check sees a version ahead of the last tag
with a merged bump commit and pushes the missing tag instead of running
commitizen again.

**Do not re-run a bump job that failed after its PR merged, if the recovery
pre-check is somehow bypassed.** Re-running `cz` against already-bumped version
files opens a spurious double-bump PR. This happened in python-sdk #193 and
typescript-sdk #121.

**Manual tag push** (the break-glass path):

```
gh pr view <bump-pr> --json mergeCommit
gh api repos/keycardai/ruby-sdk/git/refs \
  -f ref="refs/tags/<version>-<gem-name>" -f sha=<squash-sha>
```

**Version drift.** `changelog.py check-drift` runs on every PR and fails when a
gem's `.cz.toml` version disagrees with its `version.rb`. Change gem versions
with `cz bump`, never by hand. Note that RubyGems prerelease syntax (`0.1.0.pre`)
cannot be used here: commitizen reads it as PEP 440, renders it back as
`0.1.0-rc0`, fails to find that string in `version.rb`, and advances `.cz.toml`
alone without erroring.

**A release was skipped and nothing failed.** Almost always a short scope in the
PR title. Check `changelog.py changes` locally.
