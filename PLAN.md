# PLAN.md — v2.0.1 Remaining Work

Organized by phase. Each phase is independent and can be shipped separately.
Items marked ~~RESOLVED~~ are completed and kept for reference.

**Status:** Phases 1-5 complete. Phase 6 (post-release audit) open with 4 items (5 resolved).

---

# ~~Phase 1 — Correctness Bugs~~ RESOLVED

All three items shipped: dedup regex anchoring (1.1), per-file fallback exit
codes (1.2), clean() YARA rescan (1.3).

# ~~Phase 2 — Documentation & Display Fixes~~ RESOLVED

Shipped: copyright 2026 (2.1), CHANGELOG CI matrix fix (2.2), date block merge
(2.3), cron_prune_days default (2.4), sigup() YARA(cav) qualifier (2.6),
usage_short() formatting (2.7), legacy README replacement (2.8). Open item
carried forward to Phase 3 as 3.5.

# ~~Phase 3 — YARA Hardening~~ RESOLVED

All five items shipped: YARA download validation (3.1), compiled.yarc
cross-engine validation (3.2), compiled.yarc integrity validation (3.3),
ignore_sigs regex/substring documentation (3.4), README.md YARA docs (3.5).

---

# ~~Phase 4 — Performance & Refactoring~~ RESOLVED

All four items shipped: _yara_scan_rules() extraction (4.3),
_yara_init_cache() binary/scan-list caching (4.1),
_yara_filter_filelist() stale file filtering (4.2),
unused yarac discovery removal (4.4).

---

# Phase 5 — CI / Infrastructure

Test and documentation improvements. All items resolved.

## ~~5.1 rocky10 and ubuntu2204 Dockerfiles not in CI/Makefile~~ RESOLVED

Rocky Linux 10 added to CI matrix, Makefile, and run-tests.sh (9-target matrix).
Ubuntu 22.04 intentionally excluded.

## ~~5.2 No SHA-256 checksum for YARA-X binary in Dockerfile.yara-x~~ RESOLVED

Added `sha256sum -c` verification after downloading YARA-X v1.13.0 binary.

## ~~5.3 No test coverage for clean() YARA rescan or YARA(cav) display~~ RESOLVED

Added 3 tests to `tests/23-yara.bats`: clean() YARA rescan path exercised,
YARA(cav) label verified when scan_yara=0, plain YARA label verified when
scan_yara=1.

## ~~5.4 No test coverage for import_custsigs_yara_url validation~~ RESOLVED

Added 3 tests to `tests/22-updates.bats`: valid rules installed, malformed
rules rejected with warning, existing custom.yara preserved on failure.

## ~~5.5 No test coverage for compiled.yarc validation~~ RESOLVED

Added 3 tests to `tests/23-yara.bats`: corrupt compiled.yarc skipped with
warning, valid compiled.yarc used in scan (yarac skip guard), scan completes
normally without compiled.yarc.

## ~~5.6 README.md md5v2.dat format description missing SIZE field~~ RESOLVED

Corrected format column to `HASH:SIZE:{MD5}sig.name.N` in README.md section 8.

---

# Phase 6 — Post-Release Audit

Findings from comprehensive assessment of v2.0.1 changes. Organized by
severity. All items are independent.

## ~~6.1 cron.daily update failure logging is dead code (Medium, Bug)~~ RESOLVED

Fixed pipeline exit code capture using `${PIPESTATUS[0]}` matching
cron.watchdog pattern. Added 2 tests for failure logging.

## ~~6.2 README.md config variable names/defaults wrong (Medium, Doc)~~ RESOLVED

Corrected all variable names (slack_channels, telegram_bot_token,
telegram_channel_id), defaults (email_alert=0, quarantine_clean=0,
email_addr, inotify_cpunice=18), and paths (maldetect.last,
/usr/lib/systemd/system/).

## 6.3 CLAUDE.md stale data (Low, Doc)

**Problem:** Several items in CLAUDE.md are stale:
- Test counts: `06-config-options.bats` says 11 (actual 10),
  `17-version.bats` says 5 (actual 6), files 18-22 say "(tests)"
  instead of counts
- Known Issues section still lists PLAN.md 5.6 (md5v2.dat SIZE field)
  as open, but it was resolved in Phase 5
- Signature table shows `HASH:{MD5}sig.name.N` without SIZE field
  (inconsistent with README fix in 5.6)

**Fix:** Update test counts, remove resolved known-issues entries,
fix signature table format.

**Files:** `CLAUDE.md:283,294-299,~390,~422`

## 6.4 Dockerfile.ubuntu2204 orphaned (Low)

**Problem:** `tests/Dockerfile.ubuntu2204` exists and is functional but
is not wired into `smoke-test.yml`, `tests/Makefile`, or
`tests/run-tests.sh`. Was intentionally excluded from CI per Phase 5.1,
but the orphaned file could confuse contributors.

**Options:**
1. Delete `Dockerfile.ubuntu2204` (cleanest — Ubuntu 20.04 and 24.04
   already cover the Ubuntu matrix)
2. Add a comment at top: `# Not in CI — covered by ubuntu2004/ubuntu2404`

**Files:** `tests/Dockerfile.ubuntu2204`

## 6.5 cron.daily `|| :` swallows inner-run errors (Low)

**Problem:** The flock command form uses `flock -n "$LOCKFILE" "$0" "$@" || :`.
The `|| :` cannot distinguish lock contention (exit 1, intended silent skip)
from real inner-script errors (exit 1 for missing $intcnf, also suppressed).

**Mitigation:** In practice, cron.daily errors surface via stdout/stderr
which cron captures and mails to root. The `|| :` only suppresses the
exit code, not the output. Using `flock -n -E 73` would cleanly separate
lock contention from real errors, but `-E` requires util-linux >= 2.25
(excludes CentOS 6).

**Deferred until CentOS 6 support is dropped.**

**Files:** `cron.daily:12`

## 6.6 LMDCRON=1 exported but never read (Low, Cleanup)

**Problem:** `cron.daily` line 3 exports `LMDCRON=1` but no code in
`files/maldet`, `files/internals/functions`, or `files/internals/internals.conf`
references this variable. It is dead code.

**Fix:** Either remove the export (if truly unused) or document its purpose
if it is intended for user scripts or future use.

**Files:** `cron.daily:3`

## ~~6.7 Rocky 8/9 Dockerfiles missing curl (Low, CI)~~ RESOLVED

Added `curl` to `microdnf install` in both Dockerfile.rocky8 and
Dockerfile.rocky9.

## ~~6.8 conf.maldet comment typo (Low, Doc)~~ RESOLVED

Changed `-a|--al` to `-a|--scan-all` in conf.maldet comment.

## ~~6.9 email_subj documented as user config but lives in internals.conf (Low, Doc)~~ RESOLVED

Relocated `email_subj` from `internals.conf` to `conf.maldet` (after
`email_ignore_clean`). `internals.conf` now uses `${email_subj:-...}`
fallback for backward compatibility with old configs.

---

# Resolved Items (reference only)

## ~~YARA scan performance: O(N*M) process spawning~~ RESOLVED
Batch `--scan-list` scanning implemented, reducing from N×M to M+1 invocations.

## ~~No error handling for YARA syntax errors in rule files~~ RESOLVED
stderr captured and logged via `eout`. Exit codes logged.

## ~~Duplicate hits when scan_yara_scope=all + ClamAV enabled~~ RESOLVED
Dedup via `grep -qF` on `$scan_session` (has substring bug, tracked in Phase 1).

## ~~Duplicate hits when ClamAV + YARA detect same file~~ RESOLVED
Same dedup mechanism (has substring bug, tracked in Phase 1).

## ~~usage_short() does not mention YARA~~ RESOLVED
Added YARA hint line (has formatting issue, tracked in Phase 2).

## ~~YARA sig count displayed even when native YARA disabled~~ RESOLVED
Shows `YARA(cav)` qualifier when `scan_yara=0`.

## ~~Files quarantined by ClamAV skipped by YARA in monitor_check()~~ ACCEPTED
ClamAV already detected the threat. Dedup prevents double-recording. Not a bug.
