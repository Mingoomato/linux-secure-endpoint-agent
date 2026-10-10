# Changelog

## Unreleased

- Pair directory move cookies, record matched and unmatched directory moves, and rebuild recursive watches on a fresh inotify FD. The new collector path has not been technically verified.

## 0.1.0 — 2026-10-10

- Initial educational implementation based on the associated SRS.
- Added bounded CLI functionality, security and architecture notes, and isolated smoke validation.
- Runtime and enforcement claims remain limited to the evidence recorded in `docs/TEST_RESULTS.md`.
