# AGENTS.md

Context for coding agents working in keycardai/ruby-sdk. CLAUDE.md points here.

## What this repo is

A monorepo of three independently versioned gems, namespace `Keycardai`. Ruby >= 3.2 (`.ruby-version` pins 4.0.6 for dev; CI runs 3.2, 3.4, 4.0).

Gems (dependency direction in parentheses):

- `oauth/` (`keycardai-oauth`, `Keycardai::OAuth`): OAuth 2.0 primitives, token verification, application credentials, `AccessContext`. Runtime dep: `jwt`. Depends on no sibling.
- `mcp/` (`keycardai-mcp`, `Keycardai::MCP`): MCP server auth at the Rack seam (depends on oauth, `rack`). Wraps no MCP SDK.
- `a2a/` (`keycardai-a2a`, `Keycardai::A2A`): agent-to-agent delegation client (depends on oauth). No community A2A gems.
- `examples/`: `mcp-server`, `a2a-delegation`, `device-authorization`, each with its own Gemfile using `path:` to the gems. Excluded from RuboCop.

The root `Gemfile` loads all three gems by `path:`. Gemspecs use plain version constraints for siblings, so `keycardai-oauth` must publish before a dependent gem that needs a new oauth version.

## Setup, build, test, lint

These are the commands CI runs (`.github/workflows/ci.yml`):

```sh
bundle install
bundle exec rake spec       # all three gems (spec:oauth, spec:mcp, spec:a2a)
bundle exec rake rubocop    # lint, Ruby 4.0
```

`bundle exec rake` runs both. One gem: `bundle exec rake spec:oauth`.

CI job `release-tooling` (needs `pip install commitizen==4.19.2`):

```sh
python3 -m unittest discover -s scripts -p 'test_*.py' -v
python3 scripts/changelog.py check-drift      # .cz.toml vs version.rb
```

CI job `validate-commits` (PRs, non-bot): `python3 scripts/changelog.py validate origin/<base>`.

RuboCop: target 3.2, double quotes, `Metrics/MethodLength` 15, `AbcSize` 20, `ClassLength` 150. Config at repo root.

## Commits and releases

Conventional commits. Squash merges, so the PR title carries the scope. Details in `docs/releasing.md`.

- Scope is the full gem name: `keycardai-oauth`, `keycardai-mcp`, `keycardai-a2a`. Changes outside the gems take no scope.
- `feat(oauth):` matches nothing, so nothing releases and nothing errors.
- The scope decides which gem releases, not the paths touched.
- Releasable types (each gem's `.cz.toml` `changelog_pattern`): `feat`, `fix`, `refactor`, `perf`, `test`, `build`, `ci`, `revert`. `docs`, `chore`, `style` never release.
- Increments (`bump_pattern`/`bump_map`): `feat` minor; `fix`, `refactor`, `perf` patch.
- Breaking change: `!` after the scope (`feat(keycardai-oauth)!: ...`). The bump pattern only reads the subject line, so a `BREAKING CHANGE` footer alone does not cut a major. All gems have `major_version_zero = true`, so a major lands as a minor while 0.x; flip it to `false` in that gem's `.cz.toml` at 1.0.0.
- Merge to `main` runs `main.yml`: `scripts/changelog.py changes` finds gems with unreleased scoped commits (emitted oauth first), then `bump-package.yml` per gem, one at a time. `scripts/bump_package.py` runs `cz bump --files-only`, opens and merges a bump PR from the release app, and tags `<version>-keycardai-<gem>`. The tag triggers `release.yml`, which pushes to rubygems.org via trusted publishing.
- Never hand-edit `version.rb`, `.cz.toml` versions, tags or `CHANGELOG.md`. CI checks drift between `.cz.toml` and `version.rb`.
- Keep versions plain semver; RubyGems prerelease syntax (`0.1.0.pre`) makes commitizen silently drift.

## Spec first

- Behavior changes start as a PR in keycardai/keycard-sdk-spec (`specs/<area>/<name>.md`, with a Unit Tests table of rows and a Divergences section). Implement against the merged spec's rows.
- The conformance suite mirrors the spec: one `<gem>/spec/conformance/<spec-slug>_spec.rb` per capability spec, and each `it` starts with the row number it implements (`it "1: POSTs the credential's headers ..."`). Extra examples beyond the spec rows carry no number. Other unit specs go in `<gem>/spec/keycardai/`.
- Cross-SDK expression differences must be sanctioned in `docs/idiom-profile.md`; anything else is a contract bug. `docs/conformance-report.md` tracks coverage per spec.

## Testing rule

- Gem specs, CI and examples' default runs are hermetic only: no live Keycard zone. keycardai/templates' eval owns live-zone coverage.
- Existing live runners (`examples/mcp-server/bin/live-e2e`, `examples/a2a-delegation/bin/live`, `examples/device-authorization/bin/device-login`) are manual and not in CI. Do not add more or wire them into CI; the hermetic `bin/selftest` in each example is the check to keep green.

## Idioms and gotchas

From `docs/idiom-profile.md`:

- Sync only, blocking. One `Client`, no async pair. Internals are thread-safe (Mutex-guarded JWKS and discovery caches) for Puma/Sidekiq.
- Keyword arguments, not functional options. Flat methods on client objects.
- Errors are exceptions rooted at `Keycardai::Error` (`oauth/lib/keycardai/oauth/errors.rb`); spec error categories are subclasses, with `error` / `error_description` attributes.
- Rack shape: middleware for enforcement (`use provider.grant(...)`), Rack apps for metadata; handlers read `keycardai.auth_info` and `keycardai.access_context` from the env.
- HTTP goes through a small injectable client (`http_client:` kwarg, `Net::HTTP` default). No hidden retries.
- No implicit reads of Keycard config from ENV. The one exception is `FileTokenSource` path discovery via platform vars; `discover_application_credential(env: ENV)` is an explicit opt-in helper.
- One `TokenVerifier` class with a zone argument (`verify_token_for_zone`).
- JSON payloads are hashes with symbol keys at the public surface; keys are `OpenSSL::PKey`, times are `Time`.
- `AccessContext` setter names (`set_token`, `set_error`, ...) are the cross-SDK contract; RuboCop excludes them from `Naming/AccessorMethodName`.
