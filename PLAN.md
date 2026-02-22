# PLAN.md — v2.0.1 Remaining Work

Organized by phase. Each phase is independent and can be shipped separately.
Items marked ~~RESOLVED~~ are completed and kept for reference.

**Status:** Phases 1-5 complete. All items resolved.

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
