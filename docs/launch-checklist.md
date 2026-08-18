# Launch checklist

Ordered so that every step's prerequisites are already true when you reach it.
Linear tickets in brackets; items marked **(no ticket)** are gaps worth filing.

Verified state as of 2026-08-18: 16 PRs merged, main green on Ruby 3.2/3.4/4.0,
158 spec-mapped conformance examples, 12/12 live rows against a real zone. See
[conformance-report.md](conformance-report.md).

## 0. Start immediately, because it has external lead time (no ticket)

Request a **RubyGems Organization** by emailing support@rubygems.org.
Organizations are in limited private beta, so there is no self-service path and
the turnaround is unknown.

This must **not** gate publishing. Publish under individual ownership with
trusted publishing, then transfer the gems once access is granted (RubyGems
supports gem transfer). Otherwise the launch blocks on a third party.

Related and worth settling in the same conversation: **no repo in the SDK family
documents who owns the registry accounts.** Searching python-sdk, typescript-sdk,
go-sdk and the engineering handbook turns up nothing on PyPI or npm account
ownership, MFA posture, or a break-glass path if OIDC fails. Ruby is a good
excuse to write that down once for all four.

## 1. Publishing identity [ECO-283]

Gem names were confirmed available on 2026-08-18: `keycardai-oauth`,
`keycardai-mcp`, `keycardai-a2a`, and the bare `keycardai`. Note `keycard` alone
is already taken by an unrelated authentication gem, which validates the
`keycardai-` prefix. Names are first-come, so publishing (even a `.pre`) is what
actually reserves them.

1. Create a GitHub **environment** on `keycardai/ruby-sdk`, named `release`.
2. On rubygems.org, add a **pending trusted publisher** for each of the three
   gems: repository `keycardai/ruby-sdk`, workflow file `release.yml`,
   environment `release`. Pending publishers work for gems that do not exist yet
   and convert after the first push. **The workflow filename and environment
   name are part of the match**, so renaming either later breaks publishing with
   an auth error rather than an obvious failure. python-sdk hit the same
   coupling with `release.yml` + `pypi-release`.
3. No registry API token, and none should be created. python-sdk's only repo
   secret is `SOCKET_API_TOKEN`; PyPI publishing there is already OIDC. The
   gemspecs set `rubygems_mfa_required`, which trusted publishing satisfies.
   The owning rubygems.org account still needs MFA set to "UI and API".

Repo settings the automation depends on, none of which are currently set on
ruby-sdk (it has no secrets, no variables, no environments):

| Setting | Value | Why |
| --- | --- | --- |
| Variable `SDK_RELEASE_APP_ID` | the Keycard SDK Release app id | python-sdk and typescript-sdk both read the id from `vars`, not `secrets` |
| Secret `SDK_RELEASE_PRIVATE_KEY` | that app's private key | used by `actions/create-github-app-token@v2` |
| Allow auto-merge | enabled | the bump script arms auto-merge as a fallback |
| Squash merge | available | the bump PR is squash-merged and the tag lands on the squash SHA |

The **Keycard SDK Release** app (actorId 4487400) is already a bypass actor on
the org `require-review` ruleset. It must also be **installed on ruby-sdk** with
contents:write and pull-requests:write. Note go-sdk still uses the older
`GH_REPO_ACCESS` app; follow python-sdk and typescript-sdk instead.

## 2. Release automation [ECO-282]

Copy the **post-fix** python-sdk pipeline. The original deadlocked; the fixes
landed in python-sdk#194 and typescript-sdk#122. Trigger is a push to `main`,
not a manual dispatch: `main.yml` detects changed packages and fans out to
`bump-package.yml` with `max-parallel: 1`, guarded by
`!startsWith(github.event.head_commit.message, 'bump:')` so bumps don't recurse.

**Version source of truth: follow TypeScript, not Python.** This is the one
thing Python cannot teach us. Python derives its wheel version from the git tag
via `uv-dynamic-versioning`, so no version file exists and drift is impossible.
A gemspec needs a literal, so Ruby gets:

```toml
version_files = ["lib/keycardai/oauth/version.rb:VERSION"]
ignored_tag_formats = ["${version}-*"]
tag_format = "${version}-keycardai-oauth"
major_version_zero = true
bump_message = "bump: keycardai-oauth $current_version → $new_version"
```

and therefore **also needs a `check-drift` port**, comparing `.cz.toml`'s
`version` against the `VERSION` constant. Without it, a hand-edited version file
silently desyncs and the next bump tries to create a tag that already exists.
`ignored_tag_formats` matters in a monorepo: without it commitizen's walk back
for "the last release of this gem" stops at any other gem's tag.

Details that bite:

- **Scope must be the full gem name.** `feat(keycardai-oauth):`, never
  `feat(oauth):`. A short scope matches nothing, `detect-changes` returns empty,
  and nothing releases with no error anywhere. Keep go-sdk's comment about the
  optional-scope group as a warning.
- **Allowed types are `feat|fix|refactor|perf|test|build|ci|revert`.** `docs`,
  `chore` and `style` are deliberately absent, so a docs-only change cannot cut
  a release. python-sdk's playbook claims otherwise; the playbook is wrong.
- **`bump_message` uses a Unicode arrow (U+2192)** and must match byte-for-byte
  in three places: the loop guard, the recovery grep, and the PR title.
- **`major_version_zero = true` must flip to `false`** the moment a gem reaches
  1.0.0, or breaking changes land as minors. python-sdk's mcp package carries
  that comment after being bitten.
- **The bump script must merge the PR explicitly** once checks are green.
  GitHub auto-merge never exercises a ruleset bypass; arming it and waiting is
  exactly what deadlocked. Keep auto-merge armed only as a fallback.
- **Recovery pre-check**: if the version is ahead of the last tag and the bump
  commit is merged, push the missing tag instead of re-running commitizen.
  Re-running produces a spurious double-bump PR.
- **Signed commits** come from the GraphQL `createCommitOnBranch` mutation, which
  GitHub signs as the app. No GPG key needed.
- **`fetch-depth: 0`** everywhere; commitizen's tag walk and `cz check
  --rev-range` need full history.
- **Exempt bots** from commit-message validation
  (`github.event.pull_request.user.type != 'Bot'`) or the bump PR fails its own
  gate.
- **Commitizen is a Python tool**; run it via `setup-python` + `pip install
  commitizen`, as go-sdk already does inside a non-Python repo. Keep the bump
  script in Python too: it is ~640 lines of GitHub API choreography with a lot of
  absorbed edge cases.
- **Wire up the bump-script unit tests.** python-sdk has
  `scripts/test_bump_package.py` that nothing ever runs; typescript-sdk runs its
  copy in CI. Do it from day one.

**Publish job** (`release.yml`), tag-triggered, `permissions: id-token: write`,
`environment: release`. Unlike `uv publish` and `pnpm publish`, **`gem push` does
not auto-discover the OIDC token**, so this needs an explicit exchange step:
`rubygems/release-gem@v1` (or `configure-trusted-publisher` then `gem push`).
There is no in-repo precedent for that step. Drop npm's `--provenance` (no
RubyGems equivalent) and its dist-tag routing (RubyGems has no dist-tags;
maintenance lines are steered by dependency constraints).

**Prove all of this with a no-op bump while ruby-sdk is still excluded from
require-review.** That is what ECO-282 is asking for, and step 4 depends on it.

## 3. Take the repo public [ECO-281]

Prerequisite: step 2 proven, so a locked-down repo cannot strand a release.

Already done: the internal-identifier audit is clean (no real zone, org, user or
client IDs in tracked files; only placeholder `keycard.cloud` strings; no
secrets or `.env` in the index), and each gem now ships its LICENSE (#16, which
caught all three gems declaring MIT while packaging no license text).

Still to do:

1. Replace the four **"Private preview / not published"** notices, which become
   false on publish, in `README.md`, `oauth/README.md`, `mcp/README.md` and
   `a2a/README.md`, with the sibling wording adapted: `> **Preview.** APIs may
   change between minor versions while the surface settles. Conformance against
   the cross-SDK contract is tracked in docs/conformance-report.md.`
2. Replace the root README's `path:`/`git:` install instructions with
   `gem install` / `bundle add`.
3. Flip visibility to public and confirm CI is green in public.

## 4. Re-govern the repo like the other SDKs (no ticket)

Remove `ruby-sdk` from `rulesets:requireReviewRepoExcludes` in
`keycardlabs/infra` `stacks/github/Pulumi.keycardai.yaml`. That is the removal
condition stated in infra#173 when the exclusion was added. After step 2, so
bump PRs keep flowing through the bypass actor.

## 5. First publish [ECO-283]

**Publish order is a real constraint: `keycardai-oauth`, then `keycardai-mcp`,
then `keycardai-a2a`.** Bundler's `path:` works only in a Gemfile, never in a
gemspec, so the sibling dependencies are version constraints and `keycardai-mcp`
cannot be pushed against a `keycardai-oauth` version that is not live yet.
`max-parallel: 1` serializes the matrix but does not order it, so verify the
discovery order rather than assuming.

Then verify from the registry rather than the checkout: a clean `gem install` of
each, and both examples running against published artifacts, which means
swapping the `examples/*/Gemfile` `path:` sources for version constraints.

## 6. Docs and spec [ECO-285, ECO-284]

Per-gem quickstarts, YARD rendered, preview notices on READMEs and the gem
registry only, no svc-docs sweep while in closed alpha. Then `context/ruby.md`
in keycard-sdk-spec from [idiom-profile.md](idiom-profile.md), and the Ruby
package column on each capability spec, `keycardai-oauth` first.

## 7. Findings back to the spec (no ticket)

The four findings in the conformance report are the most transferable output of
this build, and none is Ruby-specific:

1. `impersonation.md` requires an `act` chain no live zone issues, root-caused
   to `svc-sts` populating actor info only from an explicit `actor_token`. Owned
   by another team; either the spec relaxes or the service emits the claim.
2. `token-exchange.md` error codes do not match live behaviour
   (`invalid_request` and `invalid_grant` where the spec says `invalid_grant`
   and `invalid_target`).
3. An unwritten security invariant: substitute-user tokens are not
   re-exchangeable, which prevents laundering an impersonated token into a
   broader one.
4. `jwt-signing-and-verification.md` contradicts its own Divergences table
   twice, on the `clock_skew` default and the required-claim set.

## 8. Templates entry (no ticket, genuinely downstream)

Add `mcp-server-ruby` on the 13-file `mcp-server-go` precedent, plus a
`verify-ruby` job. Two details from that CI: `discover` keys off `package.json`
/ `pyproject.toml` / `go.mod` only, so a Ruby directory is invisible in "all"
mode; and the `workflow_dispatch` single-template branch falls through to
**python** in its `else`, so a dispatched Ruby template is misclassified.
Blocked on step 5, since templates CI installs from the registry with no
path-override.

## 9. Close the last coverage gap (no ticket)

The production `grant` path exchanges a real inbound user token, and
impersonated tokens are not re-exchangeable, so the live suite cannot stand in
for it. Covered hermetically in both example selftests. Closing it live needs
one interactive browser login against a zone.
