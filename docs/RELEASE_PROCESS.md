# Release Process

## Philosophy

Ship fast. In the AI agent space, Claude Code ships daily, Codex ships multiple times per day. A week of silence is a week of irrelevance. Our cadence matches the pace of the market.

## Cadence

### Ship When Ready — Daily or Faster

Every PR merge that touches runtime behavior is a release candidate. Don't batch. Don't wait.

**Rules:**
- **Feature or fix merged → release same day** (patch or minor bump)
- **Multiple PRs merged in one session → one release at the end** (don't release per-PR)
- **Docs/CI/chore only → skip** (no user-facing change, no release)
- **End of day with unreleased commits → release before signing off**

### Release Tiers

| Tier | Bump | When | Notes |
|------|------|------|-------|
| **Hotfix** | Patch | Immediately | Security, data loss, broken builds. Drop everything. |
| **Improvement** | Patch | Same day | Bug fixes, small enhancements, deps |
| **Feature** | Minor | Same day | New channel, provider, tool, or capability |
| **Breaking** | Minor (pre-1.0) | On completion | Config/API changes. Document in release notes. |
| **Major** | Major | Milestone | Reserved for v1.0 |

### Anti-Patterns

- Sitting on 19 unreleased commits for 2 days — **ship it**
- Batching a week of work into one release — **that's enterprise pace, not startup pace**
- Releasing 6 times in 3 hours for the same feature — **finish the feature, then release once**
- Skipping release because "it's just a small fix" — **small fixes compound into user trust**

## How to Release

### 1. Pre-flight (30 seconds)

```bash
git checkout main && git pull
cargo fmt -- --check && cargo clippy -- -D warnings && cargo nextest run --lib && cargo test --doc
```

If green, ship. If red, fix first.

### 2. Cut (10 seconds)

```bash
# Patch (fixes, improvements)
cargo release patch --execute --no-confirm

# Minor (features)
cargo release minor --execute --no-confirm
```

### 3. Verify CI

`release.yml` auto-triggers on tag push → builds 4 binaries + sha256 → creates GitHub release.

```bash
gh run list --workflow release.yml --limit 1
gh release view v$VERSION --json assets -q '.assets[].name'
```

### 4. Update Homebrew Tap

```bash
gh release download v$VERSION --pattern '*.sha256' --dir /tmp/release
# Update version + sha256 in qhkm/homebrew-tap Formula/zeptoclaw.rb
```

### 5. Verify Install Paths

```bash
zeptoclaw update                    # Self-update
brew upgrade zeptoclaw              # Homebrew
cargo install zeptoclaw --version $VERSION --dry-run  # crates.io
```

## Release Notes

**Patch releases:** Auto-generated notes are fine.

**Minor releases:** Write a summary — these are marketing moments.

```bash
gh release edit v$VERSION --notes "$(cat <<'EOF'
## What's New

One-line headline.

### Highlights
- Feature A
- Feature B

### Breaking Changes
- None

### Contributors
@contributor1
EOF
)"
```

## Benchmarks

| Project | Pace | Our target |
|---------|------|------------|
| Claude Code | Daily | Match this |
| Codex | Multiple/day | Aspirational |
| ZeptoClaw (old) | Burst then silence | Never again |
| ZeptoClaw (new) | Ship when ready, daily minimum | This is the way |

## Decision Log

| Date | Decision | Reason |
|------|----------|--------|
| 2026-03-26 | Ship-when-ready cadence | Weekly was too slow for AI agent market. Claude Code ships daily. We match or lose. |
| 2026-03-26 | One release per session, not per PR | Avoids v0.5.1-v0.5.9 in 3 days chaos while still shipping fast. |
| 2026-03-26 | Hotfix = drop everything | Users on `zeptoclaw update` shouldn't wait for anything when security is involved. |
| 2026-03-26 | Custom notes for minor+ only | Patch is routine. Minor is a marketing moment worth writing up. |
