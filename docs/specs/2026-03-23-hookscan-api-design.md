# Hook Scanning API — Design Specification

**Date:** 2026-03-23
**Author:** R-fx Networks
**Status:** DRAFT
**Supersedes:** `docs/specs/2026-03-23-hookscan-improvement-proposal.md` (preliminary)

---

## 1. Problem Statement

LMD's hook scanning is a single-purpose ModSecurity integration (`hookscan.sh`)
with no formal API contract, no FTP service coverage, no mail service integration,
no timeout protection, and no documentation for third-party integrators. The
competitive landscape (Imunify360, cPGuard, defunct CXS) has set expectations for
multi-service hook scanning that LMD does not meet.

CXS's shutdown has created a direct migration opportunity — its shared hosting
customers need a drop-in replacement that covers ModSecurity, pure-ftpd, and
ProFTPD hooks. LMD already has the scan engine; it lacks the service integration
layer.

**Goal:** Design a unified hook scanning API with:
- Single entry point, multi-mode dispatch
- Per-service output contracts
- Unprivileged (usermode) scanning support
- Formal interface contract for third-party integrators
- Adversarial-grade security hardening
- Alert suppression with session-pollution-free hit logging
- Unified digest architecture spanning monitor mode and hook scanning
- Test alert capability across all delivery channels

---

## 2. Competitive Analysis

### 2.1 Integration Coverage Matrix

| Integration Point | LMD 2.0.1 | Imunify360 | cPGuard | CXS (dead) | ClamAV |
|-------------------|-----------|------------|---------|------------|--------|
| ModSecurity `@inspectFile` | Yes | Yes (WAF) | Yes | Yes | No |
| pure-ftpd upload hook | **No** | Yes (native) | Yes | Yes | No |
| ProFTPD upload hook | **No** | No | No | Yes | No |
| Exim content scanner | **No** | No | No | No | Yes (clamd) |
| Inotify file watch | Yes | Yes | Yes | Yes | Yes |
| fanotify kernel blocking | No | Yes | No | No | Yes |
| ClamAV signature bridge | Yes | N/A | No | Yes | N/A |
| Daemon/socket scan API | **No** | Yes (agent) | Yes (API) | Yes (cxswatch) | Yes (clamd) |
| Usermode scanning | Partial* | Yes (UI) | No | No | Yes (clamdscan) |
| Per-service toggles | No | Yes | Yes | Yes | Yes |

\* LMD has `scan_user_access=1` but no path restriction or rate limiting.

### 2.2 Competitor Patterns

**Imunify360:** Monolithic agent daemon (`imunify-agent`) with per-channel config
toggles (`enable_scan_inotify`, `enable_scan_pure_ftpd`, `enable_scan_modsec`).
Pure-ftpd integration is native (hooks into the daemon, not via `pure-uploadscript`).
User-facing scans go through a web UI with server-side enforcement. No public
CLI API for third-party integration.

**cPGuard:** cPanel plugin with web API. Real-time scanning via inotify. ModSecurity
rules for upload scanning. FTP scanning via inotify on upload dirs (not native
FTP hooks). No public scanner API.

**CXS (dead):** Separate thin-wrapper scripts per service (`cxscgi.sh`, `cxsftp.sh`)
calling a shared `cxs` binary. Per-hook config files. `cxswatch` inotify daemon
for catch-all coverage. The model LMD should follow, modernized.

**ClamAV:** Socket-based daemon (`clamd`) with formal protocol. Any service speaks
clamd protocol (Samba, Dovecot, Exim, milters). LMD already bridges via
`clamav_linksigs()` — any clamd consumer automatically uses LMD signatures.

### 2.3 Key Insight

No competitor exposes a documented, stable CLI API for third-party integration.
This is LMD's differentiation opportunity: define a **public scanner interface**
that hosting providers, panel vendors, and custom integrations can program against.

---

## 3. Architecture

### 3.1 Single Entry Point, Mode Dispatch

```
hookscan.sh [MODE] FILE
```

`MODE` selects the output contract. `FILE` is the absolute path to scan.

| Mode | Caller | Output Contract |
|------|--------|----------------|
| `modsec` | ModSecurity `@inspectFile` | stdout: `1` clean, `0 SIG PATH` infected |
| `ftp` | pure-ftpd `pure-uploadscript` | fire-and-forget; quarantine on detect |
| `proftpd` | ProFTPD `mod_exec` | fire-and-forget; quarantine on detect |
| `exim` | Exim `cmdline` av_scanner | stdout: `clean` or `maldet: SIGNAME` |
| `generic` | Third-party/custom | exit 0 clean, exit 2 infected; stdout: structured |
| *(default)* | Legacy / no mode arg | `modsec` (backward compatible) |

**Backward compatibility:** `hookscan.sh /path/to/file` (no mode) behaves
identically to current `hookscan.sh` — ModSecurity mode. The mode argument
is positional-first; file path detection uses `[[ "$1" == /* ]]` to distinguish
mode keyword from file path.

**Path validation:** `FILE` must be an absolute path (starts with `/`). If
`$1` is not a recognized mode keyword AND does not start with `/`, the script
rejects with an error. Relative paths are not supported — they create
ambiguity in mode dispatch and are never used by any service integration
(ModSecurity, pure-ftpd, ProFTPD, and Exim all pass absolute paths).

### 3.2 Why Single Script, Not Per-Service Scripts

Research confirms no generic FTP hook standard exists — each server has a unique
invocation contract. However, the scanning logic is identical across all modes:

1. Validate filename
2. Source config
3. Detect scan engine
4. Run scan with timeout
5. Format result per mode

Only step 5 differs. A single script with a mode switch eliminates duplication
(~90% shared code) and provides one file to audit, one file to harden, one file
to document.

### 3.3 Internal Flow

```
hookscan.sh
  ├── parse_mode_and_file()     # mode dispatch + backward compat
  ├── validate_filename()       # reject metacharacters, non-printable
  ├── validate_caller()         # usermode path restriction (§5)
  ├── source_config()           # internals.conf + conf.maldet.hookscan
  ├── detect_engine()           # ClamAV auto-detection
  ├── run_scan()                # timeout + maldet --hook-scan invocation
  │     └── scan() tail:
  │           ├── [hscan] append hits → hook.hits.log (§13)
  │           ├── [hscan] escalation check (§13.5)
  │           ├── [normal] _scan_finalize_session → session.tsv
  │           └── [normal] genalert → email/Slack/Telegram/Discord
  └── format_result()           # mode-specific output formatting
```

These are inline code sections, not sourced functions — `hookscan.sh` performs
all input validation and output formatting without sourcing external libraries.
The scan itself is delegated to a `maldet` subprocess (which sources the full
library chain internally).

**`$hitname` contract:** The current `maldet --hook-scan` code at `lmd_scan.sh:770`
outputs `echo "0 maldet: $hitname $spath"` — but `$hitname` is only populated by
the per-file quarantine path and is **empty** in the batch pipeline or when
`quarantine_hits=0`. The implementation must fix `maldet`'s hook-scan output to
extract the signature name from `session.hits.$datestamp.$$` (the TSV hit record)
rather than relying on the `$hitname` global. This ensures the output contract
is fulfilled regardless of quarantine state.

---

## 4. Per-Service Integration Contracts

### 4.1 ModSecurity (`modsec`)

**Caller:** Apache/nginx via `@inspectFile` operator.

**ModSecurity rule:**
```apache
SecRequestBodyAccess On
SecTmpSaveUploadedFiles On   # Required for ModSecurity >= 2.9
SecRule FILES_TMPNAMES "@inspectFile /usr/local/maldetect/hookscan.sh" \
    "id:1999999,phase:2,t:none,deny,log,auditlog,severity:2, \
     msg:'Malware upload blocked by LMD'"
```

**Contract:**
- Invocation: `popen("hookscan.sh /path/to/tmpfile")` — shell execution
- Input: `$1` = absolute path to uploaded temp file
- Output: stdout first character determines result
  - `1` → clean (rule does NOT match → request proceeds)
  - `0` → infected (rule matches → deny action fires)
  - Empty stdout → treated as infected by ModSecurity
- Exit code: NOT used by ModSecurity (only stdout matters)
- Timeout: **None from ModSecurity.** Script must self-limit.
- v2 and v3 (libmodsecurity): identical `popen()` contract

**LMD stdout format:**
```
1 maldet: OK                          # clean
0 maldet: {HEX}php.shell.b374k /path  # infected
```

**Error paths:** All early exits (validation failure, missing config, scan
timeout) must print `1` and exit — a scanner error must NOT block legitimate
uploads. Log the error via `logger -t maldet-hookscan` for diagnosis.

**Exception:** Filename validation failure (metacharacter rejection) prints `0`
because the filename itself is an attack indicator.

### 4.2 pure-ftpd (`ftp`)

**Caller:** `pure-uploadscript` daemon.

**Setup:**
```bash
# pure-ftpd.conf (or command-line flags):
CallUploadScript yes               # or -o flag
# Requires: pure-ftpd compiled with --with-uploadscript

# Start the upload-script daemon:
pure-uploadscript -r /usr/local/maldetect/hookscan.sh -B
# -B = background (daemonize)
# Script receives "ftp" as implicit mode when UPLOAD_VUSER is set (see §4.2.1)
```

**Contract:**
- Invocation: `pure-uploadscript` daemon calls script with `$1` = file path
- Environment variables from pure-ftpd:
  - `UPLOAD_SIZE` — file size in bytes
  - `UPLOAD_PERMS` — octal permissions
  - `UPLOAD_UID` / `UPLOAD_GID` — numeric owner
  - `UPLOAD_USER` / `UPLOAD_GROUP` — owner names
  - `UPLOAD_VUSER` — virtual username (max 127 chars)
- Exit code: **NOT checked** (fire-and-forget)
- Timing: post-upload — file is fully written before script runs
- **Cannot block the upload** — file is already committed
- Scripts execute sequentially — slow script blocks the queue
- The script quarantines infected files after scanning

**4.2.1 Auto-detection:** When `UPLOAD_VUSER` is set in the environment,
`hookscan.sh` can auto-detect that it was called by pure-ftpd and default to
`ftp` mode without an explicit mode argument. This allows the simpler config:
```bash
pure-uploadscript -r /usr/local/maldetect/hookscan.sh -B
```

**LMD behavior:** Scan, quarantine if infected, log result. No stdout output
needed. Syslog via `logger -t maldet-ftpscan`.

### 4.3 ProFTPD (`proftpd`)

**Caller:** ProFTPD `mod_exec` module.

**Setup:**
```
<IfModule mod_exec.c>
  ExecEngine on
  ExecLog /var/log/proftpd/exec.log
  ExecTimeout 30
  ExecOnCommand STOR /usr/local/maldetect/hookscan.sh proftpd %f
  ExecEnviron PROFTPD_USER %u
  ExecEnviron PROFTPD_HOME %d
</IfModule>
```

**Contract:**
- Invocation: ProFTPD forks script with mode + `%f` (file path) as args
- Environment: custom via `ExecEnviron` directives (NOT automatic)
- Exit code: **NOT checked for blocking** — `mod_exec` always returns
  `PR_DECLINED` regardless of script exit. Both `ExecBeforeCommand` and
  `ExecOnCommand` are fire-and-forget.
- Timeout: `ExecTimeout` directive (admin-configured)
- **Cannot block the upload** — same as pure-ftpd

**IMPORTANT CORRECTION:** The common belief that `ExecBeforeCommand` non-zero
exit rejects the FTP command is **wrong**. ProFTPD source confirms `exec_pre_cmd`
always returns `PR_DECLINED(cmd)`. Only native C modules like `mod_clamav` can
reject uploads (via `PR_ERROR`).

**LMD behavior:** Identical to `ftp` mode — scan, quarantine if infected, log.

### 4.4 Exim (`exim`)

**Caller:** Exim `cmdline` scanner type.

**Setup:**
```
# exim.conf
av_scanner = cmdline:\
  /usr/local/maldetect/hookscan.sh exim %s :\
  maldet\: (.+):\
  maldet\: (.+)
```

The three colon-separated fields after the command are:
1. Command template (`%s` = spool file path)
2. Trigger regex — if stdout matches, malware detected
3. Name-capture regex — `(.+)` extracts the malware name

**Contract:**
- Invocation: Exim fork+exec with `$2` = spool file path
- Output: stdout matched against trigger regex
  - `maldet: clean` → no regex match → message accepted
  - `maldet: {HEX}php.shell.b374k` → regex match, `$1` = signame
- Exit code: not primary (but non-zero may cause Exim to tempfail)
- Timeout: default 120s, configurable via `tmo=N` in av_scanner

**LMD stdout format:**
```
maldet: clean                         # no malware
maldet: {HEX}php.shell.b374k         # malware detected
```

### 4.5 Generic Mode (`generic`)

**For third-party integrators, custom scripts, and programmatic use.**

```bash
hookscan.sh generic /path/to/file
```

**Contract:**
- Exit codes:
  - `0` — clean, no malware found
  - `1` — error (scan failed, timeout, config error)
  - `2` — malware detected
- Stdout (one line):
  - `CLEAN: /path/to/file`
  - `ERROR: reason`
  - `INFECTED: signame /path/to/file`
- Stderr: diagnostic messages (may be empty)
- Timeout: respects `hookscan_timeout` config

This is the recommended mode for custom integrations — the exit code + stdout
format is unambiguous and machine-parseable.

---

## 5. Usermode (Unprivileged) Scanning

### 5.1 Current State

LMD supports non-root scanning via `scan_user_access=1`. When a non-root user
runs maldet, `prerun()` sets `pub=1` and redirects all state to per-user
directories under `$varlibpath/pub/$user/`. The scan runs as the calling user
with no privilege escalation.

**Current gaps:**
- No scan path restriction — non-root can scan any world-readable path
- No rate limiting or concurrent scan cap
- No symlink traversal protection
- Signature names fully visible (oracle attack potential)

### 5.2 Usermode Hook Scanning

When `hookscan.sh` is invoked by a non-root caller (e.g., cPanel File Manager,
user cron, custom script), the following controls apply:

**5.2.1 Path restriction:**
Non-root callers may only scan files within their home directory. The scan
target is validated against `$HOME` (resolved via `getent passwd $(whoami)`):

```bash
_user_home=$(getent passwd "$(whoami)" | cut -d: -f6)
case "$file" in
    "$_user_home"/*)  ;;  # allowed
    *)
        logger -t maldet-hookscan "rejected non-root scan outside homedir: $file"
        # Output mode-appropriate "clean" response — do not leak path info
        _output_clean
        exit 0
        ;;
esac
```

**Exception:** ModSecurity hooks run as the Apache/nginx user, which has no
meaningful homedir. When `hscan=1` and the caller is a web server UID
(detected via `UPLOAD_*` env vars or apache/nginx/www-data/nobody username),
path restriction is skipped — the ModSecurity `@inspectFile` temp path is
the only file passed.

**5.2.2 Rate limiting:**
Non-root callers are limited to `hookscan_user_rate_limit` scans per hour
(default: 60). Tracked via a counter file in the user's session directory.
Hook-triggered scans (ModSecurity, FTP) are exempt from rate limiting — they
are service-initiated, not user-initiated.

```bash
hookscan_user_rate_limit=60     # scans/hour for non-root; 0 = unlimited
```

**5.2.3 Concurrent scan limit:**
One active hook scan per UID at a time. Enforced via `flock` on a per-user
lockfile. Concurrent requests queue (with timeout) rather than fail.

**5.2.4 Symlink handling:**
Non-root scans pass `--nosymlinks` to maldet (resolved internally as
`-not -type l` in find arguments). Root scans follow symlinks by default.

### 5.3 Privilege Model

LMD uses the **unprivileged scanner** model: the scan runs as the calling
user with no privilege escalation. This is the correct security posture:

- **No setuid, no suid wrapper, no sudo rules.** These create privilege
  escalation attack surface.
- Files the user cannot read are simply not scanned (OS enforces permission).
- For files requiring root access (other users' homedirs, system paths),
  rely on root-owned cron scans and inotify monitoring.
- For services that need privileged scanning (Samba, Dovecot), the ClamAV
  bridge (`clamav_linksigs()`) provides coverage via the clamd daemon model.

---

## 6. Configuration

### 6.1 `conf.maldet.hookscan`

All hook-specific configuration lives in `$inspath/conf.maldet.hookscan`.
This file is optional — defaults are sane for shared hosting.

```bash
## Hook scan configuration
## Sourced by hookscan.sh after internals.conf and before scan dispatch.
## These values override conf.maldet defaults for hook-triggered scans only.

# Quarantine malware hits (default: 1)
quarantine_hits=1

# Attempt to clean malware from files (default: 0)
quarantine_clean=0

# Scan engine: auto detects ClamAV daemon, falls back to native (default: auto)
scan_clamscan=auto

# YARA scanning: auto detects yara/yr binary (default: auto)
scan_yara=auto

# Scan timeout in seconds (default: 30)
# ModSecurity has no timeout — this prevents Apache worker thread exhaustion.
# pure-ftpd runs scripts sequentially — this prevents queue blocking.
hookscan_timeout=30

# Usermode rate limit: max scans per hour for non-root callers (default: 60)
# Set to 0 for unlimited. Hook-triggered scans (modsec, ftp) are exempt.
hookscan_user_rate_limit=60

# Signature name visibility for non-root callers (default: 1)
# 0 = opaque "MALWARE-DETECTED" in user-facing output, full names in logs
# 1 = full signature names in all output (industry standard, ClamAV default)
hookscan_user_show_signames=1

# Hook scan escalation threshold: fire immediate alert if >= N hook hits
# within a 1-hour rolling window. 0 = disabled. (default: 0)
# When triggered, fires genalert file (per-scan alert), not digest.
hookscan_escalate_hits=0
```

### 6.2 Config Loading Order

1. `$inspath/internals/internals.conf` — binary paths, internal state
2. `$inspath/conf.maldet.hookscan` — hook-specific overrides
3. Mode-specific env vars (e.g., `UPLOAD_VUSER` from pure-ftpd)
4. Inline defaults for any unset values

**No `-co` processing in hookscan.** The hook script passes `-co` to maldet
for scan-time overrides. The hook config file is for hook-specific settings
only (timeout, rate limit, engine selection).

**ClamAV detection:** The current `hookscan.sh` has inline ClamAV daemon
detection via `$pidof clamd` (lines 41-48). This is **removed** in the new
design — `scan_clamscan=auto` is passed through to maldet's `-co` argument,
and `_resolve_clamscan()` inside maldet handles engine selection. The inline
detection was redundant with the auto-detection already wired into maldet
since commit `958c827`.

### 6.3 Config Security

`conf.maldet.hookscan` is parsed via an inline allowlist parser (see §A5-FIX
in the adversarial analysis). The parser is self-contained in `hookscan.sh`
and does not depend on `_safe_source_conf()` from the library chain:

- Only whitelisted variable names accepted (case statement)
- Shell metacharacters, command substitution, pipes rejected
- Unknown keys logged and rejected

The hook config allowlist:
```
quarantine_hits quarantine_clean scan_clamscan scan_yara
scan_tmpdir_paths hookscan_timeout hookscan_user_rate_limit
hookscan_user_show_signames hookscan_service_users hookscan_fail_open
hookscan_list_max_bytes hookscan_list_max_entries hookscan_escalate_hits
```

---

## 7. Generic API Interface

### 7.1 For Third-Party Integrators

Any service that needs to scan a file via LMD can use:

```bash
/usr/local/maldetect/hookscan.sh generic /absolute/path/to/file
```

**Input:**
- Argument 1: `generic` (mode keyword)
- Argument 2: absolute file path
- The file must exist and be readable by the calling user

**Output:**
- Exit code: `0` (clean), `1` (error), `2` (infected)
- Stdout (single line, machine-parseable):
  ```
  CLEAN: /path/to/file
  INFECTED: {HEX}php.shell.b374k /path/to/file
  ERROR: scan timeout after 30s
  ```
- Stderr: diagnostic messages (may be empty, should not be parsed)

**Timeout:** Scans complete within `hookscan_timeout` seconds (default 30).
If exceeded, returns `ERROR: scan timeout` with exit 1.

**Concurrency:** Safe for concurrent invocation. Each scan creates isolated
temp files under `$tmpdir` namespaced by PID.

**Privilege:** Runs as the calling user. Non-root callers are subject to
path restriction (homedir only) and rate limiting. Root callers have no
restrictions.

### 7.2 Batch File List (`--list` and `--stdin`)

For scanning multiple files in a single invocation (batch integrations,
rsync post-transfer, cron jobs), `generic` mode accepts a file list:

```bash
# From a file list
hookscan.sh generic --list /tmp/filelist.txt

# From stdin (pipe)
find /uploads -newer /tmp/marker -type f | hookscan.sh generic --stdin
```

**Output:** One `STATUS: path` line per file, same format as single-file mode:
```
CLEAN: /uploads/doc.pdf
INFECTED: {HEX}php.shell.b374k /uploads/shell.php
CLEAN: /uploads/image.jpg
ERROR: scan timeout after 30s
```

**Exit code:** Worst result wins: `2` if any infected, `1` if any errors
(and no infections), `0` if all clean.

**Implementation:** The validated file list is passed to maldet via
`maldet --hook-scan -f "$validated_list" ...` (maldet's existing file list
mode). Output is post-processed by `hookscan.sh` to produce per-file
`STATUS:` lines.

**Batch timeout:** `hookscan_timeout` applies to the entire batch, not
per-file. For large lists, increase the timeout via `conf.maldet.hookscan`.

#### 7.2.1 File List Validation (Security-Critical)

The file list is an **untrusted input** — an attacker can craft a list file
or pipe content containing shell injection, path traversal, binary data, or
non-file entries. Every line is validated before any scan occurs.

**Step 1: File type check (--list only)**

Before reading the list file, verify it is a regular text file:

```bash
# Reject if not a regular file
if [ ! -f "$listfile" ]; then
    echo "ERROR: list file does not exist or is not a regular file"
    exit 1
fi

# Reject if not text (binary, device, FIFO, etc.)
_ftype=$(file -b --mime-type "$listfile" 2>/dev/null)
case "$_ftype" in
    text/plain|text/x-*|application/x-empty) ;;  # allowed text types
    *)
        logger -t maldet-hookscan "rejected non-text list file: $_ftype"
        echo "ERROR: list file is not a text file (detected: $_ftype)"
        exit 1
        ;;
esac

# Reject if oversized (default: 1MB / ~20,000 paths)
_fsize=$(stat -c %s "$listfile" 2>/dev/null || stat -f %z "$listfile" 2>/dev/null)
if [ "${_fsize:-0}" -gt "${hookscan_list_max_bytes:-1048576}" ]; then
    logger -t maldet-hookscan "rejected oversized list file: ${_fsize} bytes"
    echo "ERROR: list file exceeds maximum size"
    exit 1
fi
```

**Step 2: Per-line validation**

Every line in the list (from file or stdin) is validated with the same
rigor as a single-file argument. Lines that fail validation are skipped
with a logged warning — they do not abort the entire batch.

```bash
_validated_list=$(mktemp "$tmpdir/hookscan_list.XXXXXX")
_line_num=0
_rejected=0
_accepted=0

while IFS= read -r _line || [ -n "$_line" ]; do
    _line_num=$((_line_num + 1))

    # Skip empty lines and comments
    [ -z "$_line" ] && continue
    [[ "$_line" == "#"* ]] && continue

    # RULE 1: Must be absolute path (starts with /)
    if [[ "$_line" != /* ]]; then
        logger -t maldet-hookscan "list:$_line_num: rejected relative path"
        _rejected=$((_rejected + 1))
        continue
    fi

    # RULE 2: Printable characters only (no null, no control chars)
    # Uses the same [:print:] check as single-file validation
    case "$_line" in
        *[![:print:]]*)
            logger -t maldet-hookscan "list:$_line_num: rejected non-printable chars"
            _rejected=$((_rejected + 1))
            continue
            ;;
    esac

    # RULE 3: No shell metacharacters
    if [[ "$_line" =~ $metachar_pat ]]; then
        logger -t maldet-hookscan "list:$_line_num: rejected shell metacharacters"
        _rejected=$((_rejected + 1))
        continue
    fi

    # RULE 4: No path traversal components
    if [[ "$_line" == *".."* ]]; then
        logger -t maldet-hookscan "list:$_line_num: rejected path traversal"
        _rejected=$((_rejected + 1))
        continue
    fi

    # RULE 5: Path format — only characters valid in file paths
    # Allowed: alphanumeric, /, -, _, ., space, @, +, ~, %, =, ','
    # This is a POSITIVE match (allowlist), not a blocklist
    _path_valid_pat='^[a-zA-Z0-9/_. @+~%=,{}-]+$'
    if [[ ! "$_line" =~ $_path_valid_pat ]]; then
        logger -t maldet-hookscan "list:$_line_num: rejected invalid path characters"
        _rejected=$((_rejected + 1))
        continue
    fi

    # RULE 6: Resolve symlinks and verify existence
    _resolved=$(readlink -e "$_line" 2>/dev/null)
    if [ -z "$_resolved" ]; then
        # File does not exist or dangling symlink — skip silently
        continue
    fi

    # RULE 7: Must be a regular file (not directory, device, socket, FIFO)
    if [ ! -f "$_resolved" ]; then
        logger -t maldet-hookscan "list:$_line_num: rejected non-regular file"
        _rejected=$((_rejected + 1))
        continue
    fi

    # RULE 8: Usermode homedir restriction (same as single-file, §A4-FIX)
    if [ "$_is_service" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
        case "$_resolved" in
            "$_user_home"/*) ;;
            *)
                logger -t maldet-hookscan "list:$_line_num: rejected outside homedir"
                _rejected=$((_rejected + 1))
                continue
                ;;
        esac
    fi

    # RULE 9: Line count cap (defense against unbounded lists)
    if [ "$_accepted" -ge "${hookscan_list_max_entries:-10000}" ]; then
        logger -t maldet-hookscan "list: max entries reached ($_accepted), truncating"
        break
    fi

    printf '%s\n' "$_resolved" >> "$_validated_list"
    _accepted=$((_accepted + 1))
done < "${_input_source}"

# Reject if zero valid entries survived validation
if [ "$_accepted" -eq 0 ]; then
    rm -f "$_validated_list"
    echo "ERROR: no valid file paths in list ($_rejected rejected)"
    exit 1
fi

logger -t maldet-hookscan "list: $_accepted accepted, $_rejected rejected"
```

**Step 3: Pass validated list to maldet**

Only the validated, resolved, existence-checked paths reach maldet:
```bash
timeout --kill-after=5 "$hookscan_timeout" \
    "$inspath/maldet" --hook-scan \
    -co "quarantine_hits=$quarantine_hits,quarantine_clean=$quarantine_clean,scan_clamscan=$scan_clamscan,scan_yara=$scan_yara" \
    -f "$_validated_list"
```

The validated list contains only `readlink -e` resolved absolute paths —
no symlinks, no traversal, no metacharacters, no non-files.

#### 7.2.2 File List Config

```bash
# Maximum list file size in bytes (default: 1MB, ~20,000 paths)
hookscan_list_max_bytes=1048576

# Maximum entries accepted from a list (default: 10,000)
hookscan_list_max_entries=10000
```

#### 7.2.3 Stdin Security

When using `--stdin`, the input is read from a pipe — there is no file to
type-check. The per-line validation (Step 2) applies identically. Additional
stdin-specific controls:

- **Read timeout:** If stdin produces no data within 5 seconds, exit with
  error. Prevents indefinite blocking on a dead pipe.
- **Size cap:** Total bytes read from stdin capped at
  `hookscan_list_max_bytes`. Excess input is discarded with a warning.
- **No tty:** Reject if stdin is a terminal (`[ -t 0 ]`) — interactive
  input is not a valid use case and likely indicates user error.

```bash
if [ -t 0 ]; then
    echo "ERROR: --stdin requires piped input, not terminal"
    exit 1
fi
```

### 7.3 Integration Examples

**Custom PHP upload handler (single file):**
```php
$result = exec('/usr/local/maldetect/hookscan.sh generic ' .
    escapeshellarg($uploaded_file), $output, $exitcode);
if ($exitcode === 2) {
    // Malware detected — file already quarantined by LMD
    http_response_code(406);
    die('Upload rejected: malware detected');
}
```

**Batch scan after rsync transfer:**
```bash
find /var/uploads -newer /tmp/.last-scan -type f > /tmp/scanlist.txt
/usr/local/maldetect/hookscan.sh generic --list /tmp/scanlist.txt
touch /tmp/.last-scan
```

**inotifywait pipe to stdin:**
```bash
inotifywait -m -e close_write --format '%w%f' /var/uploads/ | \
    /usr/local/maldetect/hookscan.sh generic --stdin
```

**Cron job scanning recent uploads:**
```bash
find /home/*/public_html -mmin -60 -type f | \
    /usr/local/maldetect/hookscan.sh generic --stdin
```

**Note:** For directory-recursive scanning, use `maldet -a /path/to/dir`
directly. `hookscan.sh` operates on explicit file lists only.

### 7.4 Stability Contract

The `generic` mode interface is a **stable API**:
- Exit codes 0, 1, 2 will not change semantics
- Stdout format `STATUS: details` will not change structure
- `--list` and `--stdin` batch modes are part of the stable contract
- New status values may be added (forward-compatible)
- The `hookscan.sh generic` invocation path will not be removed

Service-specific modes (`modsec`, `ftp`, etc.) follow the service's own
contract and may evolve with the service.

---

## 8. Adversarial Security Analysis

### 8.1 Threat Model

The hook scanning interface is a **security boundary**: untrusted input
(uploaded files, FTP transfers, email attachments) passes through `hookscan.sh`
to the maldet scanner. The interface is exposed to:

- **Remote attackers** (via ModSecurity: HTTP uploads, FTP uploads)
- **Authenticated users** (via usermode scanning, panel integrations)
- **Local users** (shared hosting: any user with shell access)
- **Service accounts** (Apache, nginx, proftpd, exim running as non-root)

### 8.2 Attack Surface

#### A1: Filename Injection

**Vector:** Attacker uploads a file with a crafted filename containing shell
metacharacters, newlines, null bytes, or path traversal sequences.

**Current defense:** `hookscan.sh` validates filenames in two stages:
1. `case` statement rejects non-printable characters (`[![:print:]]`)
2. Regex rejects shell metacharacters (`[;|&$(){}\`]`)
3. `-f "$file"` confirms file exists (rejects directory traversal to non-files)

**Residual risk:**

| Payload | Current Defense | Status |
|---------|----------------|--------|
| `file;rm -rf /` | metachar_pat rejects `;` | BLOCKED |
| `file$(whoami)` | metachar_pat rejects `$()` | BLOCKED |
| `file\`id\`` | metachar_pat rejects backtick | BLOCKED |
| `file\nmalicious` | non-printable check rejects `\n` | BLOCKED |
| `file\x00null` | non-printable check rejects null | BLOCKED |
| `../../../etc/passwd` | `-f` check passes if file exists | **PARTIAL** |
| `file with spaces` | NOT rejected — passed quoted to maldet | SAFE |
| `file'with'quotes` | Single quotes NOT in metachar_pat | **GAP** |
| `file"with"doublequotes` | Double quotes NOT in metachar_pat | **GAP** |

**A1-FIX-1:** Add double quotes to `metachar_pat`:
```bash
metachar_pat='[;|&$(){}`"]'
```

**Note on `$` in filenames:** Java `.class` files commonly contain `$`
(e.g., `ClassName$1.class`). The `$` is in the metachar_pat because it
enables command substitution in unquoted contexts. Since `hookscan.sh`
always passes the filename double-quoted to maldet, `$` is only dangerous
if it reaches an `eval` or unquoted expansion. The current defense is
conservative (reject `$`) — this is acceptable for the ModSecurity and FTP
use cases where filenames with `$` are rare. If Java class file scanning
is needed, users should use `maldet -a` directly, not hookscan.

**Note on single quotes:** Single quotes inside double-quoted strings are
harmless in bash. They do NOT need to be in metachar_pat. The filename is
always double-quoted when passed to maldet (`-a "$file"`), so single quotes
have no special meaning.

**A1-FIX-2:** Add path traversal check — reject filenames containing `..`:
```bash
if [[ "$file" == *".."* ]]; then
    logger -t maldet-hookscan "rejected filename with path traversal"
    _output_clean  # or _output_error depending on mode
    exit 0
fi
```

**A1-FIX-3:** Canonicalize the path via `readlink` before passing to maldet:
```bash
file=$(readlink -e "$file" 2>/dev/null) || { _output_clean; exit 0; }
```
This resolves symlinks and `..` components. `-e` requires the file to exist.
Note: `readlink -e` is used instead of `readlink -e` because `realpath` was
not added to GNU coreutils until 8.15 (absent on CentOS 6, coreutils 8.4).
On FreeBSD, `readlink -f` is available but `-e` is not — gate with a
`[ -e "$file" ]` check followed by `readlink -f` on FreeBSD.

#### A2: Scan Timeout / Resource Exhaustion

**Vector:** Attacker uploads a file designed to cause excessive scan time
(zip bomb, deeply nested archive, regex backtracking payload), exhausting
Apache worker threads (ModSecurity) or blocking the FTP upload queue
(pure-ftpd).

**Current defense:** NONE. No timeout on maldet invocation.

**A2-FIX:** Wrap maldet invocation in `timeout`:
```bash
timeout "$hookscan_timeout" "$inspath/maldet" --hook-scan ... -a "$file"
_rc=$?
if [ "$_rc" -eq 124 ]; then
    logger -t maldet-hookscan "scan timeout after ${hookscan_timeout}s: $file"
    _output_clean  # timeout must not block legitimate uploads
fi
```

Default 30 seconds. This is the single highest-priority fix.

**A2-NOTE:** `timeout` sends SIGTERM, which maldet traps for cleanup. If
maldet doesn't exit within 5s, `timeout --kill-after=5` sends SIGKILL.
Use: `timeout --kill-after=5 "$hookscan_timeout" ...`

#### A3: Signature Oracle

**Vector:** Local user (shared hosting) runs repeated scans against crafted
test files to discover which payloads evade detection, then uploads the
evasion variant.

**Exposure:** Any client-side scanner is inherently vulnerable to this.
ClamAV exposes signature names via `clamdscan`. Imunify360 shows detection
names in its UI.

**Mitigations (defense-in-depth, not elimination):**

| Control | Mechanism | Default |
|---------|-----------|---------|
| Rate limit | `hookscan_user_rate_limit=60/hr` | ON |
| Concurrent limit | flock per UID | ON |
| Signature suppression | `hookscan_user_show_signames=0` | OFF (industry norm is visible) |
| Audit log | All non-root scans logged with UID, path, result | ON |
| Detection-in-depth | inotify monitor + cron scans catch bypass attempts | Existing |

**Accept:** Oracle resistance is impractical for a local scanner. The
mitigations slow the attacker and create an audit trail; they do not prevent
a determined adversary with shell access. This is an accepted industry-wide
limitation.

#### A4: Cross-User Information Disclosure

**Vector:** Non-root user scans paths outside their homedir to confirm
whether files in other users' directories match malware signatures.

**Current defense:** OS file permissions prevent reading files the user
cannot access. But world-readable web content (common on shared hosting)
is scannable by any user.

**A4-FIX:** Restrict non-root scan paths to `$HOME`, gated on **UID** not mode:
```bash
# Service UIDs that may scan outside their homedir (web server, FTP, MTA).
# Configurable via hookscan_service_users in conf.maldet.hookscan.
_service_users="${hookscan_service_users:-apache,nginx,www-data,nobody,proftpd,exim}"

_caller=$(whoami)
if [ "$(id -u)" -ne 0 ]; then
    _is_service=0
    IFS=',' read -ra _svc_arr <<< "$_service_users"
    for _svc in "${_svc_arr[@]}"; do
        [ "$_caller" == "$_svc" ] && _is_service=1 && break
    done

    if [ "$_is_service" -eq 0 ]; then
        _user_home=$(getent passwd "$_caller" | cut -d: -f6)
        _resolved=$(readlink -e "$file" 2>/dev/null)
        case "$_resolved" in
            "$_user_home"/*) ;;
            *)
                logger -t maldet-hookscan "non-root scan outside homedir rejected: $_caller"
                _output_clean
                exit 0
                ;;
        esac
    fi
fi
```

**SECURITY NOTE:** The homedir bypass is gated on the calling UID's username
being in the `hookscan_service_users` whitelist — **NOT** on the mode
argument or environment variables. Mode strings and env vars are
attacker-controlled inputs in the shared hosting threat model. A local user
running `hookscan.sh modsec /etc/shadow` is still restricted to their
homedir unless their username matches a service account.

```bash
# conf.maldet.hookscan — service accounts exempt from homedir restriction
hookscan_service_users="apache,nginx,www-data,nobody,proftpd,exim"
```

#### A5: Config Injection

**Vector:** Attacker modifies `conf.maldet.hookscan` to inject malicious
config values (requires root or write access to install dir).

**Current defense:** `source "$hookcnf"` with no validation.

**A5-FIX:** Inline allowlist parser (not `_safe_source_conf`, which is part
of the library chain that hookscan.sh must not depend on post-config-load):
```bash
if [ -f "$hookcnf" ]; then
    while IFS='=' read -r _key _val; do
        [[ "$_key" =~ ^[[:space:]]*# ]] && continue   # skip comments
        [[ -z "$_key" ]] && continue                    # skip blank lines
        _key="${_key// /}"                               # strip spaces
        _val="${_val// /}"
        case "$_key" in
            quarantine_hits|quarantine_clean|scan_clamscan|scan_yara| \
            scan_tmpdir_paths|hookscan_timeout|hookscan_user_rate_limit| \
            hookscan_user_show_signames|hookscan_service_users| \
            hookscan_fail_open|hookscan_escalate_hits)
                # Reject values with shell metacharacters
                if [[ "$_val" =~ [';|&$(){}`\"'] ]]; then
                    logger -t maldet-hookscan "rejected unsafe config value: $_key"
                    continue
                fi
                declare "$_key=$_val"
                ;;
            *)  logger -t maldet-hookscan "rejected unknown config key: $_key" ;;
        esac
    done < "$hookcnf"
fi
```

This is self-contained — no dependency on `_safe_source_conf()` from the
library chain. The 10-variable allowlist is hardcoded as a case statement.
Unknown keys and metacharacter-laden values are rejected with syslog.

**Risk assessment:** LOW — requires root write access to exploit. But
defense-in-depth: applying the same validation as `conf.maldet` costs nothing.

#### A6: Symlink Race (TOCTOU)

**Vector:** Attacker creates a benign file, triggers a scan, then replaces
the file with a symlink to a sensitive file between the `-f` existence check
and the actual scan.

**Timing window:** Between `[ -f "$file" ]` (hookscan.sh line 24) and
maldet reading the file (seconds later).

**A6-FIX-1:** `readlink -e` at entry resolves the symlink once, then the
resolved path is used throughout. If the target changes after resolution,
maldet scans whatever is at the resolved path — no information leak.

**A6-FIX-2:** For non-root callers, `find -P` (no symlink follow) combined
with homedir restriction (§A4-FIX) prevents following symlinks to
out-of-scope targets.

**Risk assessment:** LOW — the scanner reads file content (for malware
patterns), it does not output file content. An attacker cannot exfiltrate
data through scan results. The worst case is a false clean/infected result
on a swapped file.

#### A7: Denial of Service via Hook Queue

**Vector:** Attacker floods the FTP upload queue (pure-ftpd) or sends many
concurrent HTTP uploads (ModSecurity), each triggering a maldet fork.

**Defense layers:**

| Layer | Mechanism |
|-------|-----------|
| Timeout | `hookscan_timeout=30` prevents indefinite hangs |
| Resource | `nice -n 19` + `ionice -c3` on maldet |
| Concurrency | OS process limits (ulimit), systemd service limits |
| pure-ftpd | Sequential queue = natural rate limit (one scan at a time) |
| ModSecurity | Apache `MaxRequestWorkers` limits concurrent scans |
| Application | `hookscan_user_rate_limit` for usermode callers |

**Accept:** Full DoS protection requires OS-level controls (cgroups, ulimit)
outside LMD's scope. LMD's timeout and nice settings prevent a single scan
from monopolizing resources. The service layer (Apache, pure-ftpd) provides
its own concurrency controls.

#### A8: Log Injection

**Vector:** Crafted filename appears in syslog messages via `logger -t
maldet-hookscan`, potentially injecting false log entries.

**Current defense:** Filename validation rejects metacharacters and
non-printable characters before any logging occurs.

**A8-FIX:** Already mitigated by A1 validation. The filename passed to
`logger` has already passed the printable + metachar checks. `logger` itself
does not interpret its arguments as shell code.

#### A9: Incomplete Scan Silent Pass

**Vector:** maldet scan encounters an internal error (corrupt signatures,
missing binary, disk full) and exits non-zero without scanning. The hook
script misinterprets this as "clean" and allows the upload.

**A9-FIX:** Distinguish between maldet exit codes:
```bash
timeout --kill-after=5 "$hookscan_timeout" "$inspath/maldet" \
    --hook-scan -co ... -a "$file"
_rc=$?
case $_rc in
    0)   _output_clean ;;        # scanned, clean
    2)   _output_infected ;;     # scanned, malware found
    124) _output_clean ;;        # timeout — don't block legitimate uploads
    *)   # scan error — policy decision:
         # SAFE DEFAULT: treat as clean (don't block on scanner error)
         # PARANOID: treat as infected (block on scanner error)
         if [ "${hookscan_fail_open:-1}" == "1" ]; then
             logger -t maldet-hookscan "scan error (rc=$_rc), fail-open: $file"
             _output_clean
         else
             logger -t maldet-hookscan "scan error (rc=$_rc), fail-closed: $file"
             _output_infected
         fi
         ;;
esac
```

**Config option:**
```bash
# Fail-open (default: 1) — scanner errors allow the file through
# Fail-closed (0) — scanner errors block the file
# Fail-open is the safe default for production: a broken scanner
# should not cause a site-wide upload outage
hookscan_fail_open=1
```

#### A10: File List Injection

**Vector:** Attacker supplies a crafted file list (via `--list` or `--stdin`)
containing shell injection payloads, binary data, non-file paths, symlinks
to sensitive files, or entries designed to exhaust resources.

**Sub-vectors:**

| Attack | Payload | Defense |
|--------|---------|---------|
| Shell injection in path | `/tmp/file;rm -rf /` | metachar_pat rejects `;` per line |
| Command substitution | `/tmp/$(whoami).php` | metachar_pat rejects `$()` per line |
| Binary data in list | `\x00\xff\xfe` raw bytes | `[:print:]` check rejects non-printable |
| Path traversal | `/tmp/../../../etc/shadow` | `..` check + `readlink -e` resolves |
| Relative paths | `../../etc/passwd` | Must start with `/` |
| Symlink to sensitive file | `/tmp/link -> /etc/shadow` | `readlink -e` resolves; homedir check |
| Directory entry | `/etc/` | `[ ! -f "$_resolved" ]` rejects |
| Device file | `/dev/zero` | `[ ! -f "$_resolved" ]` rejects |
| FIFO/socket | `/tmp/mypipe` | `[ ! -f "$_resolved" ]` rejects |
| Unbounded list | 10M entries | `hookscan_list_max_entries` cap (10,000) |
| Oversized file | 500MB list file | `hookscan_list_max_bytes` cap (1MB) |
| Binary list file | ELF/gzip/tar as list | `file --mime-type` rejects non-text |
| Null bytes in lines | `/tmp/file\x00/etc/shadow` | `[:print:]` rejects null |
| Unicode homoglyphs | `/tmp/fіle.php` (Cyrillic і) | Allowed if printable; harmless |
| Invalid path chars | `/tmp/file\x01\x02` | `[:print:]` rejects control chars |
| Exotic but valid chars | `/tmp/file name (1).txt` | Positive-match `_path_valid_pat` allowlist |
| Extremely long path | 4096+ char line | Kernel `PATH_MAX` causes `readlink -e` to fail → skipped |
| Cross-user homedir | `/home/victim/public_html/...` | Homedir restriction (§A4-FIX) |
| Pipe bomb (--stdin) | `yes /tmp/file \| --stdin` | Read timeout (5s), size cap, entry cap |
| Terminal input | `--stdin` with no pipe | `[ -t 0 ]` rejects tty |

**Defense layers (defense in depth):**

1. **File type gate** (--list only): `file --mime-type` rejects binary, ELF,
   archives, images, etc. before any line parsing.
2. **Size gate**: File size and entry count caps prevent resource exhaustion.
3. **Per-line positive-match allowlist**: `_path_valid_pat` accepts ONLY
   characters valid in file paths (`[a-zA-Z0-9/_. @+~%=,{}-]`). This is a
   **whitelist**, not a blacklist — anything not explicitly allowed is rejected.
4. **Path canonicalization**: `readlink -e` resolves all symlinks and `..`
   components. The resolved path is what reaches maldet.
5. **Existence + type check**: `readlink -e` fails for non-existent paths;
   `[ -f ]` rejects non-regular-files.
6. **Homedir restriction**: Non-root, non-service callers can only scan files
   within their own homedir — applied to each resolved path individually.
7. **Stdin safety**: Terminal rejection, read timeout, size cap.

**Residual risk:** MINIMAL. The only paths that survive validation are
existing regular files with printable-only absolute paths containing only
allowlisted characters, resolved through symlinks, within the caller's
permitted scope. The validated list is written to a temp file that maldet
reads — no line from the original untrusted input reaches a shell expansion
context without passing all 7 defense layers.

### 8.3 Threat Summary

| ID | Threat | Severity | Status | Fix |
|----|--------|----------|--------|-----|
| A1 | Filename injection | HIGH | Mostly blocked, 1 gap | Add `"` to metachar_pat, `..` check, `readlink -e` |
| A2 | Scan timeout | HIGH | Not mitigated | `timeout --kill-after=5` wrapper |
| A3 | Signature oracle | MEDIUM | Inherent to local scanners | Rate limit, audit log, optional name suppression |
| A4 | Cross-user disclosure | MEDIUM | Not mitigated | Homedir restriction gated on UID |
| A5 | Config injection | LOW | Not mitigated | Inline allowlist parser |
| A6 | Symlink race | LOW | Partially mitigated | `readlink -e` + `-P` for non-root |
| A7 | DoS via hook queue | MEDIUM | Partially mitigated | Timeout + nice; OS controls for the rest |
| A8 | Log injection | LOW | Already mitigated | Filename validation catches injection |
| A9 | Silent scan failure | MEDIUM | Not mitigated | Exit code dispatch + fail-open/closed policy |
| A10 | File list injection | HIGH | Mitigated by design | 7-layer validation pipeline (§7.2.1) |
| A11 | Test alert amplification | LOW | Mitigated | `--test-alert` gated on root (§15.9) |
| A12 | Cursor exhaustion via `--digest` | LOW | Mitigated | `--digest` requires root via `prerun()` |
| A13 | Hook hit log unbounded growth | LOW | Mitigated | `trim_log()` at 50K lines, cron.daily trim owner (§13.2, §14.5) |

**Mandatory before merge:** A1 (traversal + readlink), A2 (timeout), A4 (homedir
by UID), A5 (inline parser), A9 (exit code dispatch), A10 (list validation).

**Recommended:** A3 (rate limit + audit), A6 (readlink).

**Accepted risk:** A7 (OS-level controls), A8 (already mitigated),
A11-A13 (mitigated by root gates and trim).

### 8.4 Error Behavior Matrix

| Error Condition | modsec stdout | generic exit | Configurable | Rationale |
|-----------------|--------------|-------------|-------------|-----------|
| Clean file | `1 maldet: OK` | 0 | No | Normal path |
| Malware found | `0 maldet: SIG PATH` | 2 | No | Normal path |
| Metachar filename | `0` (reject) | 1 | No | Attack indicator |
| File not found | `1` (pass) | 1 | No | Already deleted/moved |
| Scan timeout | `1` (pass) | 1 | No | Don't block legitimate uploads |
| Scan error (rc!=0,2) | `1` or `0` | 0 or 2 | `hookscan_fail_open` | Default: fail-open (1) |
| Config missing | `1` (pass) | 1 | No | Broken scanner != upload block |
| Path outside homedir | `1` (pass) | 0 | No | Don't leak scan capability |

**Design principle:** Scanner errors must never cause a site-wide upload outage.
The only condition that produces a "malware" signal is actual malware detection
or a filename that is itself an attack (metacharacters). All other errors fail
open by default, with `hookscan_fail_open=0` available for paranoid
environments.

---

## 9. ClamAV Bridge Note

Services that only speak clamd protocol — Samba `vfs_virusfilter`, Dovecot
antivirus plugin, Exim `clamd` scanner type, milter-clamav — are already
covered by LMD's `clamav_linksigs()`. When ClamAV is installed, LMD signatures
are symlinked to ClamAV data directories. No hook script needed.

A future `clamd`-compatible socket interface for LMD's native engine is
out of scope for this spec (significant architecture: persistent daemon,
wire protocol, connection pooling). The ClamAV bridge is the pragmatic
path for socket-based consumers.

---

## 10. Install and Documentation

### 10.1 install.sh Changes

- Install `hookscan.sh` to `$inspath/hookscan.sh` (existing)
- Install `conf.maldet.hookscan.default` as reference config
- If `conf.maldet.hookscan` does not exist, do not create it (defaults are
  built into the script)
- `chmod 750 hookscan.sh` (executable, root + group only)

### 10.2 Documentation Updates

| File | Section |
|------|---------|
| `README.md` | Rewrite §10 "ModSecurity2 Upload Scanning" → "Hook Scanning & Service Integration" |
| `README.md` | Add pure-ftpd, ProFTPD, Exim setup instructions |
| `README.md` | Add "Generic API" section for third-party integrators |
| `README.md` | Add "Alert Testing" section with `--test-alert` examples |
| `README.md` | Add "Hook Digest" section explaining hook detection visibility |
| `maldet.1` | Update HOOK SCANNING section with mode dispatch |
| `maldet.1` | Add `--test-alert`, `--digest`, `--report hooks` to SYNOPSIS |
| `maldet.1` | Add TEST ALERTS section |
| `maldet.1` | Add `cron_digest_hook`, `hookscan_escalate_hits` to CONFIGURATION |
| `conf.maldet` | Add `cron_digest_hook` variable with documentation |
| `conf.maldet` | Add comments for hook-related config vars |

### 10.3 Man Page Sections

```
HOOK SCANNING
     hookscan.sh provides real-time file scanning for service integrations.
     It supports multiple output modes for different services:

     hookscan.sh [mode] file

     Modes:
       modsec    ModSecurity @inspectFile (default if no mode specified)
       ftp       pure-ftpd pure-uploadscript daemon
       proftpd   ProFTPD mod_exec
       exim      Exim cmdline av_scanner
       generic   Machine-parseable output for custom integrations

     Hook scan detections are logged to a rolling hit log and included in
     periodic digest alerts. Individual hook scans do not create session
     files or fire per-scan alerts.

     See conf.maldet.hookscan for configuration options.

DIGEST ALERTS
     maldet --digest fires an on-demand digest alert summarizing all new
     detections (monitor mode and hook scans) since the last digest.

     maldet --report hooks displays hook scan detections from the rolling
     hit log, with optional time and mode filters.

TEST ALERTS
     maldet --test-alert TYPE CHANNEL sends a synthetic test alert through
     the specified delivery channel to verify configuration.

     TYPE: scan (per-scan alert) or digest (periodic summary)
     CHANNEL: email, slack, telegram, or discord

     Test alerts use the real rendering pipeline with synthetic data. The
     subject line is prefixed with [TEST] for identification.
```

---

## 11. Test Plan

### 11.1 Existing Tests (update)

- `15-hookscan.bats`: update for timeout, new modes, stdout format
- `24-security.bats`: update filename validation for quotes, `..`

### 11.2 New Tests

| Test | Assertions |
|------|-----------|
| Mode dispatch: default (no arg) = modsec | stdout starts with `1` on clean |
| Mode dispatch: explicit modsec | stdout starts with `1` on clean |
| Mode dispatch: generic clean | exit 0, stdout `CLEAN:` |
| Mode dispatch: generic infected | exit 2, stdout `INFECTED:` |
| Mode dispatch: ftp (fire-and-forget) | exit 0, file quarantined on detect |
| Mode dispatch: exim clean | stdout `maldet: clean` |
| Mode dispatch: exim infected | stdout `maldet: {signame}` |
| Timeout enforcement | scan killed after hookscan_timeout |
| Filename: double quotes rejected | exit, logger called |
| Filename: `..` path traversal rejected | exit, logger called |
| Filename: readlink resolution | symlink resolved before scan |
| Filename: relative path rejected | exit with error |
| Usermode: path outside homedir rejected | clean output, no scan |
| Usermode: path inside homedir allowed | scan runs |
| Usermode: mode=modsec does NOT bypass homedir | still restricted by UID |
| Usermode: service UID bypasses homedir | apache user can scan /tmp |
| Config: inline parser rejects metachar | metachar in config rejected |
| Config: inline parser rejects unknown key | unknown key logged, ignored |
| Fail-open: scan error returns clean | hookscan_fail_open=1 |
| Fail-closed: scan error returns infected | hookscan_fail_open=0 |
| Backward compat: no mode arg + file path | modsec mode |
| **File list tests** | |
| --list: clean list scans all files | per-file CLEAN/INFECTED output |
| --list: exit 2 if any file infected | worst-result-wins exit code |
| --list: binary list file rejected | `file --mime-type` gate |
| --list: oversized list file rejected | size cap enforced |
| --list: entry count cap enforced | truncates at max_entries |
| --list: shell metachar in path rejected | line skipped, logged |
| --list: relative path rejected | line skipped, logged |
| --list: `..` traversal in path rejected | line skipped, logged |
| --list: non-printable chars rejected | line skipped, logged |
| --list: directory entry rejected | `[ -f ]` gate |
| --list: device file entry rejected | `[ -f ]` gate |
| --list: symlink resolved via readlink | resolved path scanned |
| --list: non-existent path skipped | no error, just skipped |
| --list: empty list = error exit 1 | "no valid file paths" |
| --list: path allowlist rejects exotic chars | only `_path_valid_pat` chars |
| --list: usermode homedir applied per-line | out-of-homedir lines skipped |
| --stdin: piped input accepted | same validation as --list |
| --stdin: terminal input rejected | `[ -t 0 ]` gate |
| --stdin: empty pipe = error exit 1 | "no valid file paths" |
| **Hook hit log tests** | |
| Hook scan writes to hook.hits.log | append-only, TSV format, no session.tsv created |
| Hook scan does not call genalert | no email/Slack/Telegram/Discord fired |
| Hook scan session suppression | no session.tsv.* file created for hook scan |
| --report list excludes hook scans | hook hits not in default report list |
| --report hooks shows hook hits | reads hook.hits.log, formatted output |
| --report hooks --last 24h | time-filtered hook hit display |
| Escalation threshold fires alert | hookscan_escalate_hits=3, 3 hits → genalert file |
| Escalation counter hourly rotation | counter resets after 1-hour window |
| **Digest tests** | |
| Digest reads hook.hits.log | 5th tlog source in _genalert_digest |
| Digest renders hook section | {{HOOK_SECTION_TEXT}} populated when hook hits exist |
| Digest omits hook section | {{HOOK_SECTION_TEXT}} empty when no hook hits |
| cron.daily hook digest sweep | fires digest if new hook hits since last cursor |
| cron.daily no hook hits = no digest | cursor unchanged, no alert |
| --digest CLI fires on-demand digest | reads all 5 sources, renders + delivers |
| --digest with no new data = no alert | all cursors at EOF, no alert sent |
| **Test alert tests** | |
| --test-alert scan email | synthetic 3-hit scan alert delivered via email |
| --test-alert scan slack | synthetic scan alert delivered to Slack channel |
| --test-alert scan telegram | synthetic scan alert delivered to Telegram |
| --test-alert scan discord | synthetic scan alert delivered to Discord |
| --test-alert digest email | synthetic digest alert with all 5 sections |
| --test-alert digest slack | synthetic digest alert to Slack |
| --test-alert digest telegram | synthetic digest alert to Telegram |
| --test-alert digest discord | synthetic digest alert to Discord |
| --test-alert channel isolation | only target channel fires, others suppressed |
| --test-alert disabled channel error | error message if channel not enabled |
| --test-alert subject prefix | subject/title contains [TEST] prefix |
| --test-alert synthetic data coverage | all hit types (MD5, HEX, YARA) in scan test |

---

## 12. Migration Guide (from CXS)

For administrators replacing CXS with LMD:

| CXS Component | LMD Equivalent | Config Change |
|---------------|---------------|---------------|
| `cxscgi.sh` | `hookscan.sh modsec` | Change `@inspectFile` path |
| `cxsftp.sh` | `hookscan.sh ftp` | Change `pure-uploadscript -r` path |
| ProFTPD mod_exec → cxs | `hookscan.sh proftpd` | Change ExecOnCommand path |
| `cxswatch` service | `maldet -m` (monitor mode) | Enable in maldet.service |
| `/etc/cxs/cxs.conf` | `conf.maldet.hookscan` | Map quarantine/engine settings |

---

## 13. Hook Session Management & Alert Suppression

### 13.1 Problem

Each hook scan invocation creates a `session.tsv.$datestamp.$$` file. On a
shared hosting server with hundreds of customers uploading files — a single
WordPress or Magento deployment contains tens of thousands of files — this
produces tens of thousands of micro-sessions. `--report list` becomes
unusable, `$sessdir` inode pressure grows unbounded, and the 21-day cron
prune just delays the problem.

Additionally, the alert pipeline (`genalert`) fires unconditionally during
hook scans — there is no `$hscan` guard in `scan()` at `lmd_scan.sh:786-795`.
In practice alerts don't fire because defaults are off (`email_alert=0`,
`slack_alert=0`, etc.), but this is accidental safety, not design protection.
Any admin who enables alerts gets spammed on every hook detection.

### 13.2 Design: Hook Hit Log

Hook scans write to a **rolling hit log** instead of creating per-invocation
session files:

```
$sessdir/hook.hits.log          # append-only, TSV format
```

Each hook detection appends a single TSV line (same 11-field hit record
format as session files) plus two additional fields:

```
sig\tfilepath\tquarpath\thit_type\thit_type_label\thash\tsize\towner\tgroup\tmode\tmtime\thook_mode\ttimestamp
```

| Field | Description |
|-------|-------------|
| Fields 1-11 | Standard hit record (same as `session.tsv.*`) |
| `hook_mode` | Hook mode that triggered the scan (`modsec`, `ftp`, `proftpd`, `exim`, `generic`) |
| `timestamp` | Unix epoch timestamp of the detection |

**Atomic appends:** Single-line appends to a file are atomic on Linux up to
`PIPE_BUF` (4096 bytes). A typical hit record is 150-300 bytes. No flock
needed for the hit log write path.

**Rotation:** `trim_log()` at 50,000 lines (same threshold as monitor
history files). Rotation triggered by cron.daily only (single trim owner —
see §14.5). After trimming, `tlog_adjust_cursor()` is called for both
`digest.hook.alert` and `digest.hook.cron` cursors to prevent data
duplication (same pattern as `_inotify_trim_log` in `lmd_session.sh`).

**Purge behavior:** `maldet -p` wipes `$sessdir/*` (including
`hook.hits.log`) and `$tmpdir/*` (including tlog cursors and escalation
counter). After purge, the hook hit log and all digest state restart from
zero. This is consistent with purge's existing behavior for session files
and monitor state.

**Clean scans:** Files that scan clean produce NO output to the hit log.
Only detections are recorded. This is consistent with monitor mode behavior
and keeps the hit log bounded to actual threats.

### 13.3 Modified `scan()` Tail (Replaces `lmd_scan.sh` Lines 766-797)

The following unified block replaces the session finalization, output, and
alert dispatch at the end of `scan()`. The `$hscan` branch controls both
session handling AND alert suppression — these are inseparable because
`genalert` reads the session file created by `_scan_finalize_session()`.

```bash
# --- Session finalization (line 766 replacement) ---
if [ -n "$hscan" ]; then
    # HOOK SCAN: append hits to rolling log, no session file
    if [ "$tot_hits" != "0" ] && [ -f "$scan_session" ]; then
        local _hook_ts
        _hook_ts=$(date +%s)
        while IFS=$'\t' read -r _line; do
            [[ "$_line" == "#"* ]] && continue
            [ -z "$_line" ] && continue
            printf '%s\t%s\t%s\n' "$_line" "${hscan_mode:-modsec}" "$_hook_ts" \
                >> "$sessdir/hook.hits.log"
        done < "$scan_session"
    fi
else
    # NORMAL SCAN: create session.tsv file
    _scan_finalize_session
fi

# --- Output block (lines 768-783 — unchanged) ---
if [ -n "$hscan" ]; then
    if [ "$tot_hits" != "0" ]; then
        echo "0 maldet: $hitname $spath"
        eout "{scan.hook} results returned FAIL hit found on $spath"
    else
        echo "1 maldet: OK"
        eout "{scan.hook} results returned OK on $spath"
    fi
else
    echo
    eout "{scan} scan completed on $hrspath: files $tot_files, ..." 1
    eout "{scan} scan report saved, to view run: maldet --report $datestamp.$$" 1
fi

# --- Alert dispatch (lines 786-795 — guarded by hscan) ---
if [ "$tot_hits" != "0" ] && [ -z "$hscan" ]; then
    if [ "$email_ignore_clean" == "1" ] && [ "$tot_hits" != "$tot_cl" ]; then
        genalert file "$nsess"
    elif [ "$email_ignore_clean" == "0" ]; then
        genalert file "$nsess"
    fi
    if [ "$email_panel_user_alerts" == "1" ]; then
        genalert panel "$nsess"
    fi
fi

# --- Hook escalation check (new — fires only for hook scans) ---
if [ "$tot_hits" != "0" ] && [ -n "$hscan" ]; then
    _hook_escalate_check
fi
```

When `$hscan` is set:
- **No session file creation** — `_scan_finalize_session()` skipped
- **Hit log append** — detections written to `$sessdir/hook.hits.log`
- **No `genalert` call** — no email, Slack, Telegram, or Discord alerts
- **Escalation check** — fires immediate alert if threshold crossed (§13.4)
- **Stdout output** — mode-specific result (existing behavior preserved)
- **Audit logging** — `_lmd_elog_event()` still fires (audit trail preserved)

The in-flight `$scan_session` temp file (created by `_flush_hit_batch()`)
is still populated by the normal scan pipeline. Only the finalization step
differs — append to hit log instead of creating a session file.

### 13.4 Escalation Threshold

For environments that need immediate notification on hook detection spikes:

```bash
# conf.maldet.hookscan
hookscan_escalate_hits=0    # 0 = disabled; N = fire immediate alert at N hits/hour
```

**Implementation:** A counter file at `$tmpdir/.hook_escalate_count` tracks
detections within a 1-hour rolling window:

```bash
_hook_escalate_check() {
    [ "${hookscan_escalate_hits:-0}" -eq 0 ] && return 0
    local _countfile="$tmpdir/.hook_escalate_count"
    local _now _window_start _count

    _now=$(date +%s)
    _window_start=$((_now - 3600))

    # Read current counter (format: "timestamp count")
    if [ -f "$_countfile" ]; then
        read -r _ts _count < "$_countfile"
        # Reset if window expired
        if [ "${_ts:-0}" -lt "$_window_start" ]; then
            _count=0
        fi
    else
        _count=0
    fi

    _count=$((_count + 1))
    printf '%s %s\n' "$_now" "$_count" > "$_countfile"

    if [ "$_count" -ge "$hookscan_escalate_hits" ]; then
        # Build temp session from recent-window hook hits for genalert
        local _esc_session
        _esc_session=$(mktemp "$tmpdir/.hook_escalation.XXXXXX")
        _session_write_header "$_esc_session" "scan"
        # Extract hits from within the 1-hour window (field 13 = timestamp)
        awk -F'\t' -v cutoff="$_window_start" \
            '$13 >= cutoff && !/^#/ && NF > 0' \
            "$sessdir/hook.hits.log" >> "$_esc_session"
        genalert file "$_esc_session"
        command rm -f "$_esc_session"
        # Reset counter to prevent re-fire within same window
        printf '%s %s\n' "$_now" "0" > "$_countfile"
    fi
}
```

Escalation fires `genalert file` (per-scan template), not `genalert digest`.
The temp session contains only hits from the current 1-hour window — not
the entire hook.hits.log history. The `#LMD:v1` header from
`_session_write_header()` ensures `_genalert_scan()` can parse the file
using the standard TSV path.

The counter file is lightweight — one read, one write per hook scan.
**Concurrency note:** Under high-concurrency hook scans (the exact scenario
escalation targets), concurrent read-modify-write on the counter file may
lose increments. This is accepted as best-effort — the threshold will still
fire within a few extra hits of the target. Adding flock would add latency
to every hook scan's hot path.

### 13.5 Report Integration

**`--report list` (default):** Unchanged. Globs `$sessdir/session.tsv.*` —
hook scans produce no session files, so hook activity is excluded by default.

**`--report hooks`:** New subcommand that reads `$sessdir/hook.hits.log`
directly:

```bash
maldet --report hooks                   # all hook hits (default: last 24h)
maldet --report hooks --last 7d         # last 7 days
maldet --report hooks --last 1h         # last hour
maldet --report hooks --mode modsec     # filter by hook mode
maldet --report hooks --mode ftp        # filter by hook mode
```

Output format (column-formatted, same visual style as `--report list`):

```
HOOK SCAN ACTIVITY (last 24h):

  TIME                    MODE       SIGNATURE                        FILE
  Mar 23 2026 14:22:01    modsec     {HEX}php.cmdshell.generic.482   /home/user1/public_html/shell.php
  Mar 23 2026 14:23:45    ftp        {MD5}test.malware.sample.1      /home/user2/uploads/backdoor.php
  Mar 23 2026 15:01:12    modsec     {YARA}php.webshell.backdoor     /home/user3/public_html/config.old

  Total: 3 detections (modsec: 2, ftp: 1) | Quarantined: 3
```

**Implementation:** `view_report()` gains a `"hooks"` type branch that reads
`hook.hits.log`, applies time/mode filters via awk, and formats output.
No session resolution needed — the hit log is self-contained.

---

## 14. Unified Digest Architecture

### 14.1 Current State

Digest alerting is **monitor-mode-only**. The `_genalert_digest()` function
reads from 4 tlog-cursored sources that only the inotify monitor populates:

| Source | Cursor | Populated By |
|--------|--------|-------------|
| `$scan_session` | `digest.alert` | Monitor mode |
| `$clean_history` | `digest.clean.alert` | Monitor mode |
| `$monitor_scanned_history` | `digest.monitor.alert` | Monitor mode |
| `$suspend_history` | `digest.susp.alert` | Monitor mode |

Hook scan detections are invisible to the digest pipeline. Admins have no
periodic summary of hook scanning activity.

### 14.2 Design: Source-Agnostic Digest

Digest becomes a **source-agnostic aggregation layer** that reads from all
detection sources — monitor mode, hook scans, and potentially future sources.

**Refactoring requirement:** The existing `_genalert_digest()` at
`lmd_alert.sh:1216` has three hard dependencies on a running monitor mode:

1. `session.monitor.current` existence check — aborts if file missing
2. `ps | grep inotifywait` — queries running inotifywait PID
3. `inotify_start_time` — derives monitor uptime for `{{MONITOR_RUNTIME}}`

These dependencies must be made **conditional**. The function splits into:

```
_genalert_digest()
  ├── [if monitor running] read monitor-specific metadata
  │     ├── session.monitor.current → scan_session
  │     ├── inotifywait PID → process uptime → MONITOR_RUNTIME
  │     └── 4 monitor tlog sources (existing)
  ├── [always] read hook.hits.log (5th source)
  ├── [if any hits from any source] render manifest + dispatch
  └── [if no hits from any source] return (no empty digest)
```

When monitor mode is NOT running (cron.daily or `--digest` CLI contexts):
- `{{MONITOR_RUNTIME}}` renders as `-` (not applicable)
- Monitor sources produce zero hits (empty files or no cursor advancement)
- Hook source may have hits — digest fires if hook hits exist
- The digest template already handles conditional sections (empty
  `{{CLEANED_SECTION_*}}`, `{{SUSPENDED_SECTION_*}}`); monitor-specific
  sections follow the same pattern

When monitor mode IS running: behavior is unchanged from current — all 5
sources are read, monitor metadata is populated.

**New 5th source:**

| Source | Cursor | Populated By |
|--------|--------|-------------|
| `$sessdir/hook.hits.log` | `digest.hook.alert` | Hook scans (§13) |

`_genalert_digest()` reads from all available sources:

```bash
# Monitor sources (conditional — only if monitor mode is running)
if [ -f "$sessdir/session.monitor.current" ]; then
    scan_session=$(cat "$sessdir/session.monitor.current")
    tlog_read "$scan_session" "digest.alert" ...
    tlog_read "$clean_history" "digest.clean.alert" ...
    tlog_read "$monitor_scanned_history" "digest.monitor.alert" ...
    tlog_read "$suspend_history" "digest.susp.alert" ...
fi

# Hook source (always — independent of monitor mode)
if [ -f "$sessdir/hook.hits.log" ]; then
    tlog_read "$sessdir/hook.hits.log" "digest.hook.alert" "$_digest_hook_hits" bytes
fi

# Bail if no new data from any source
if [ ! -s "$_digest_hits" ] && [ ! -s "$_digest_hook_hits" ]; then
    return 0
fi
```

The hook hits merge into the same manifest pipeline — `_lmd_parse_hitlist()`
processes the 11-field hit records identically. The two additional fields
(`hook_mode`, `timestamp`) are used for the hook summary section but do
not affect the per-entry rendering.

### 14.3 Digest Template Expansion

New conditional template tokens for the hook section:

```
{{HOOK_SECTION_TEXT}}     — text format hook summary (empty if no hook hits)
{{HOOK_SECTION_HTML}}     — HTML format hook summary (empty if no hook hits)
{{HOOK_TOTAL_HITS}}       — count of hook detections in this digest window
{{HOOK_MODE_BREAKDOWN}}   — "modsec: N, ftp: N, exim: N" breakdown
```

**Text format example:**
```
Hook Scanning:
  3 detections (modsec: 2, ftp: 1) since last digest
  {HEX}php.cmdshell.generic.482    /home/user1/public_html/shell.php      modsec
  {MD5}test.malware.sample.1       /home/user2/uploads/backdoor.php       ftp
  {YARA}php.webshell.backdoor      /home/user3/public_html/config.old     modsec
```

When no hook hits exist in the digest window, `{{HOOK_SECTION_TEXT}}` and
`{{HOOK_SECTION_HTML}}` resolve to empty strings — the section is omitted
entirely (same pattern as `{{CLEANED_SECTION_TEXT}}` and
`{{SUSPENDED_SECTION_TEXT}}`).

### 14.4 Digest Trigger Expansion

Three trigger paths (up from one):

| Trigger | Context | Config | When |
|---------|---------|--------|------|
| Monitor timer | inotify supervisor | `digest_interval` | Every Nh/Nm/Nd during monitoring (existing) |
| cron.daily sweep | Daily cron job | `cron_digest_hook` | Daily if new hook hits since last cursor (new) |
| CLI on-demand | Admin command | `--digest` | Manual fire — reads all 5 sources (new) |

#### 14.4.1 cron.daily Hook Digest

`cron.daily` gains a hook digest sweep block. This is the natural home —
cron.daily already has flock serialization, runs daily, and handles
signature/version updates:

```bash
# Hook scan digest — fire if new hook detections since last sweep
if [ -f "$sessdir/hook.hits.log" ]; then
    _hook_new=$(tlog_read "$sessdir/hook.hits.log" "digest.hook.cron" \
        "$tmpdir/.cron_hook_hits" bytes 2>/dev/null | wc -l)
    if [ "${_hook_new:-0}" -gt 0 ]; then
        eout "{cron} hook digest: $_hook_new new detections, firing digest alert"
        "$inspath/maldet" --digest
    fi
fi
```

**Note:** cron.daily uses cursor name `digest.hook.cron` (not
`digest.hook.alert`) — this is a separate cursor from the monitor digest.
Both can read the same `hook.hits.log` independently. If monitor mode is
running, its digest timer includes hook hits via `digest.hook.alert`.
If monitor mode is NOT running, cron.daily provides the fallback digest.

**Config:**

```bash
# conf.maldet — enable cron.daily hook digest sweep (default: 1)
# Set to 0 to disable cron-based hook digest (e.g., if monitor mode handles it)
cron_digest_hook=1
```

#### 14.4.2 `--digest` CLI Command

New CLI option for on-demand digest fire:

```bash
maldet --digest              # fire digest now, read all 5 sources
```

**Implementation:** New case handler in `files/maldet`:

```bash
--digest)
    _lmd_alert_init
    genalert digest
    ;;
```

This reads all 5 tlog-cursored sources and fires the digest alert. Cursors
advance on read — the next digest (whether from monitor timer, cron.daily,
or another `--digest` call) sees only new data.

**Note:** A `--dry-run` option (render without delivering or advancing
cursors) is deferred to a future enhancement. Cursor-save/restore semantics
add complexity, and `--test-alert digest` (§15) covers the template
verification use case with synthetic data that does not touch real cursors.

### 14.5 Interaction Between Trigger Paths

When both monitor mode and cron.daily are active, they use **independent
cursors** on `hook.hits.log`:

- Monitor digest: cursor `digest.hook.alert`
- cron.daily: cursor `digest.hook.cron`

This means hook hits may appear in **both** a monitor digest and a cron
digest. This is acceptable — the monitor digest is periodic (e.g., hourly),
the cron digest is daily, and the overlap provides defense-in-depth
(an admin who misses the hourly digest catches it in the daily).

To avoid double-alerting in environments where both are active, admins can
set `cron_digest_hook=0` to disable the cron path when monitor mode is the
primary digest driver.

**Trim ownership:** `hook.hits.log` trimming is owned exclusively by
cron.daily (which holds the cron flock). Monitor mode does NOT trim
`hook.hits.log` — it only reads via `tlog_read`. This prevents concurrent
unserialized trim operations that could corrupt the file. After trimming,
cron.daily calls `tlog_adjust_cursor()` for both `digest.hook.alert` and
`digest.hook.cron` cursor names with the byte delta removed, preventing
data duplication on the next read (same pattern as `_inotify_trim_log`).

### 14.6 Session File for Digest Reports

When `genalert digest` fires, `_genalert_digest()` creates a consolidated
session file (existing behavior):

```
$sessdir/session.tsv.$datestamp.$$    # type: "digest"
```

This session file appears in `--report list` as a digest entry. It contains
all hits from the digest window (monitor + hook sources merged). This is the
mechanism by which hook detections become visible in `--report list` — not
as individual micro-sessions, but as consolidated digest entries.

---

## 15. Test Alert Framework

### 15.1 Problem

LMD has no mechanism to verify that alert delivery channels (email, Slack,
Telegram, Discord) are correctly configured. BFD provides
`bfd --test-alert TYPE` for per-channel validation. LMD needs the same
capability, extended to cover both per-scan and digest alert types.

### 15.2 CLI Interface

```bash
maldet --test-alert scan email          # test per-scan email alert
maldet --test-alert scan slack          # test per-scan Slack alert
maldet --test-alert scan telegram       # test per-scan Telegram alert
maldet --test-alert scan discord        # test per-scan Discord alert
maldet --test-alert digest email        # test digest email alert
maldet --test-alert digest slack        # test digest Slack alert
maldet --test-alert digest telegram     # test digest Telegram alert
maldet --test-alert digest discord      # test digest Discord alert
```

**Two-parameter design:** `ALERT_TYPE` (scan|digest) × `CHANNEL`
(email|slack|telegram|discord).

Scan alerts and digest alerts have different templates, different token
sets, and different visual layouts. Testing "email" alone doesn't validate
whether the digest template renders correctly vs the scan template. An
admin setting up Slack wants to verify both what a real-time detection
looks like and what the periodic summary looks like.

### 15.3 Synthetic Test Data

#### 15.3.1 Scan Test Data

Builds a synthetic 3-hit session covering MD5, HEX, and YARA detection
types — exercises the hit-type color registry and per-type template
rendering:

```bash
_test_scan_hits() {
    local _ts
    _ts=$(date +%s)
    local _session
    _session=$(mktemp "$tmpdir/.test_sess.XXXXXX")

    # Write session header (type: scan)
    _session_write_header "$_session" "scan"

    # 3 hits spanning detection types — uses realistic WordPress paths
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "{MD5}test.malware.sample.1" \
        "/home/testuser/public_html/wp-content/uploads/shell.php" \
        "-" "MD5" "MD5 hash" \
        "d41d8cd98f00b204e9800998ecf8427e" "1847" \
        "testuser" "testuser" "644" "$_ts" >> "$_session"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "{HEX}php.cmdshell.generic.482" \
        "/home/testuser/public_html/includes/config.old.php" \
        "-" "HEX" "HEX pattern" \
        "-" "3291" \
        "testuser" "testuser" "644" "$_ts" >> "$_session"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "{YARA}php.webshell.backdoor" \
        "/home/testuser/public_html/assets/thumb.php" \
        "-" "YARA" "YARA rule" \
        "-" "892" \
        "testuser" "testuser" "644" "$_ts" >> "$_session"

    echo "$_session"
}
```

Three hits covering MD5, HEX, and YARA detection types — exercises the
hit-type color registry and per-type template rendering. Uses realistic
WordPress paths (`wp-content/uploads/`, `includes/`, `assets/`) so the
alert looks authentic to the admin verifying delivery.

#### 15.3.2 Digest Test Data

Builds a synthetic digest window with all 5 source types populated:

```bash
_test_digest_data() {
    local _ts
    _ts=$(date +%s)

    # Monitor hits (3 detections)
    local _monitor_hits
    _monitor_hits=$(mktemp "$tmpdir/.test_mon_hits.XXXXXX")
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "{HEX}php.shell.b374k.5461" \
        "/home/customer1/public_html/old/shell.php" \
        "$quardir/customer1/shell.php.12345" "HEX" "HEX pattern" \
        "-" "4523" "customer1" "customer1" "644" "$_ts" >> "$_monitor_hits"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "{MD5}php.mailer.085" \
        "/home/customer2/public_html/includes/mail.php" \
        "-" "MD5" "MD5 hash" \
        "abc123def456" "2180" "customer2" "customer2" "644" "$_ts" >> "$_monitor_hits"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "{YARA}js.cryptominer.coinhive" \
        "/home/customer3/public_html/js/analytics.js" \
        "$quardir/customer3/analytics.js.12346" "YARA" "YARA rule" \
        "-" "1547" "customer3" "customer3" "644" "$_ts" >> "$_monitor_hits"

    # Cleaned files (1 cleaned)
    local _clean_hits
    _clean_hits=$(mktemp "$tmpdir/.test_clean.XXXXXX")
    printf '%s\t%s\n' \
        "/home/customer1/public_html/old/shell.php" \
        "{HEX}php.shell.b374k.5461" >> "$_clean_hits"

    # Hook hits (2 detections)
    local _hook_hits
    _hook_hits=$(mktemp "$tmpdir/.test_hook_hits.XXXXXX")
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "{HEX}php.cmdshell.generic.482" \
        "/home/customer4/public_html/uploads/cmd.php" \
        "$quardir/customer4/cmd.php.12347" "HEX" "HEX pattern" \
        "-" "987" "customer4" "customer4" "644" "$_ts" \
        "modsec" "$_ts" >> "$_hook_hits"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "{MD5}test.malware.sample.1" \
        "/home/customer5/uploads/backdoor.php" \
        "$quardir/customer5/backdoor.php.12348" "MD5" "MD5 hash" \
        "aabbccdd11223344" "1200" "customer5" "customer5" "644" "$_ts" \
        "ftp" "$_ts" >> "$_hook_hits"

    # Scanned file count (monitor total)
    local _scanned
    _scanned=$(mktemp "$tmpdir/.test_scanned.XXXXXX")
    printf '%s\n' "/home/customer1/public_html/index.php" >> "$_scanned"
    # ... (simulate 847 files scanned)
    echo "847" > "$tmpdir/.test_scanned_count"

    echo "$_monitor_hits $_clean_hits $_hook_hits $_scanned"
}
```

Populates all 5 digest sections (monitor threats, cleaned, scanned,
suspended, hook detections) so every conditional template section
(`{{CLEANED_SECTION_*}}`, `{{SUSPENDED_SECTION_*}}`, `{{HOOK_SECTION_*}}`)
renders. Uses realistic multi-customer paths.

### 15.4 Channel Isolation

Following BFD's proven pattern, non-target channels are temporarily
disabled during test delivery to prevent cross-contamination:

```bash
_test_alert_messaging() {
    local _alert_type="$1" _channel="$2"

    # Validate channel is enabled
    case "$_channel" in
        slack)    [ "$slack_alert" != "1" ] && {
                      eout "{test} ERROR: slack_alert is not enabled in conf.maldet" 1
                      eout "{test} set slack_alert=\"1\", slack_token, and slack_channels" 1
                      return 1; } ;;
        telegram) [ "$telegram_alert" != "1" ] && {
                      eout "{test} ERROR: telegram_alert is not enabled in conf.maldet" 1
                      eout "{test} set telegram_alert=\"1\", telegram_bot_token, and telegram_channel_id" 1
                      return 1; } ;;
        discord)  [ "$discord_alert" != "1" ] && {
                      eout "{test} ERROR: discord_alert is not enabled in conf.maldet" 1
                      eout "{test} set discord_alert=\"1\" and discord_webhook_url" 1
                      return 1; } ;;
    esac

    # Save and isolate channel state
    local _saved_slack="$slack_alert"
    local _saved_tg="$telegram_alert"
    local _saved_dc="$discord_alert"

    case "$_channel" in
        slack)    telegram_alert=0; discord_alert=0 ;;
        telegram) slack_alert=0; discord_alert=0 ;;
        discord)  slack_alert=0; telegram_alert=0 ;;
    esac
    _lmd_alert_init    # reinitialize with isolated channel state

    # Build synthetic data and dispatch
    _test_alert_dispatch "$_alert_type" "$_channel"

    # Restore channel states
    slack_alert="$_saved_slack"
    telegram_alert="$_saved_tg"
    discord_alert="$_saved_dc"
    _lmd_alert_init    # restore original state
}
```

### 15.5 Email Test Path

```bash
_test_alert_email() {
    local _alert_type="$1"    # "scan" or "digest"

    # Validate email is configured
    if [ "$email_alert" != "1" ]; then
        eout "{test} ERROR: email_alert is not enabled in conf.maldet" 1
        eout "{test} set email_alert=\"1\" and email_addr to a valid address" 1
        return 1
    fi
    if [ "$email_addr" == "you@domain.com" ] || [ -z "$email_addr" ]; then
        eout "{test} ERROR: email_addr is not configured (still set to default)" 1
        return 1
    fi

    # Build synthetic data and use the real rendering pipeline
    _test_alert_dispatch "$_alert_type" "email"
}
```

Uses the **real rendering pipeline** — not a hardcoded test message. This
validates the full template chain: token substitution, HTML rendering,
MIME assembly, and delivery. The only difference from a real alert is the
synthetic data and the `[TEST]` subject prefix.

### 15.6 Dispatch Router

```bash
_test_alert_dispatch() {
    local _alert_type="$1" _channel="$2"

    case "$_alert_type" in
        scan)
            local _session
            _session=$(_test_scan_hits)
            eout "{test} sending test scan alert to $_channel" 1
            eout "{test} synthetic data: 3 hits (MD5, HEX, YARA)" 1

            # Override subject with [TEST] prefix
            local _saved_subj="$email_subj"
            email_subj="[TEST] $email_subj"

            if [ "$_channel" == "email" ]; then
                _genalert_scan "$_session" "$email_format" "$libpath/alert"
            else
                _genalert_messaging "$_session" "$libpath/alert"
            fi

            email_subj="$_saved_subj"
            command rm -f "$_session"
            ;;
        digest)
            eout "{test} sending test digest alert to $_channel" 1
            eout "{test} synthetic data: 3 monitor + 2 hook hits, 1 cleaned" 1

            # Build synthetic digest sources, render via _genalert_digest
            # with [TEST] subject prefix and synthetic data files
            local _saved_subj="$email_subj"
            email_subj="[TEST] $email_subj"

            _test_digest_render "$_channel"

            email_subj="$_saved_subj"
            ;;
    esac

    local _rc=$?
    if [ "$_rc" -eq 0 ]; then
        eout "{test} $_alert_type alert delivered to $_channel successfully" 1
    else
        eout "{test} $_alert_type alert delivery to $_channel FAILED (rc=$_rc)" 1
    fi
    return $_rc
}
```

### 15.7 CLI Handler

New case handler in `files/maldet`:

```bash
--test-alert)
    # Usage: maldet --test-alert {scan|digest} {email|slack|telegram|discord}
    _alert_type="${2:-}"
    _channel="${3:-}"

    if [ -z "$_alert_type" ] || [ -z "$_channel" ]; then
        eout "{test} usage: maldet --test-alert {scan|digest} {email|slack|telegram|discord}" 1
        exit 1
    fi

    case "$_alert_type" in
        scan|digest) ;;
        *) eout "{test} invalid alert type '$_alert_type' — use 'scan' or 'digest'" 1; exit 1 ;;
    esac

    case "$_channel" in
        email|slack|telegram|discord) ;;
        *) eout "{test} invalid channel '$_channel' — use email, slack, telegram, or discord" 1; exit 1 ;;
    esac

    _lmd_alert_init

    if [ "$_channel" == "email" ]; then
        _test_alert_email "$_alert_type"
    else
        _test_alert_messaging "$_alert_type" "$_channel"
    fi
    ;;
```

### 15.8 Output Examples

**Successful test:**
```
$ maldet --test-alert scan slack
maldet(12345): {test} sending test scan alert to slack channel 'maldetreports'
maldet(12345): {test} synthetic data: 3 hits (MD5, HEX, YARA)
maldet(12345): {test} scan alert delivered to slack successfully
```

**Disabled channel:**
```
$ maldet --test-alert scan telegram
maldet(12345): {test} ERROR: telegram_alert is not enabled in conf.maldet
maldet(12345): {test} set telegram_alert="1", telegram_bot_token, and telegram_channel_id
```

**Digest test:**
```
$ maldet --test-alert digest email
maldet(12345): {test} sending test digest alert to admin@example.com
maldet(12345): {test} synthetic data: 3 monitor + 2 hook hits, 1 cleaned
maldet(12345): {test} digest alert delivered to email successfully (format: html)
```

**Missing args:**
```
$ maldet --test-alert
maldet(12345): {test} usage: maldet --test-alert {scan|digest} {email|slack|telegram|discord}
```

### 15.9 Test Alert Invariants

- **Root required** — `--test-alert` requires root privileges. Non-root
  users cannot trigger email, Slack, or Telegram delivery to admin
  channels. The CLI handler checks `id -u` and exits with an error for
  non-root callers. This prevents amplification attacks (rapid-fire test
  alerts to admin channels from unprivileged accounts)
- Test alerts use the **real rendering pipeline** — same templates, same
  token substitution, same delivery functions as production alerts
- Subject/title always contains `[TEST]` prefix for easy identification
- Only the specified channel fires — all others suppressed via isolation
- Channel must be enabled in config — test does not bypass enable flags
- Synthetic data is deterministic — same hits every time (no randomization)
- Test alerts do NOT advance tlog cursors (they use synthetic data, not
  real hit logs)
- Test alerts do NOT create session files (synthetic data is cleaned up)

### 15.10 Documentation Updates

| File | Change |
|------|--------|
| `maldet.1` | Add `--test-alert` to SYNOPSIS, DESCRIPTION, and new TEST ALERTS section |
| `README.md` | Add test alert examples to alerting documentation |
| `usage_short()` | Add `--test-alert TYPE CHANNEL` line |
| `usage_long()` | Add test alert description with examples |
| `conf.maldet` | Add comments noting `--test-alert` for channel verification |

---

## Appendix A: Exit Code Reference

| Exit Code | Meaning | Used In |
|-----------|---------|---------|
| 0 | Clean / no malware | All modes |
| 1 | Error (scan failed) | generic, internal |
| 2 | Malware detected | generic (maldet native) |
| 124 | Timeout (from `timeout` command) | Internal only, mapped to 0 or 1 |

Note: ModSecurity ignores exit codes entirely (stdout only). pure-ftpd and
ProFTPD mod_exec ignore exit codes. Exim uses exit codes only as fallback.
Only `generic` mode consumers should rely on exit codes.

## Appendix B: Environment Variable Detection

`hookscan.sh` uses environment variables for auto-detection when no explicit
mode is provided:

| Variable | Set By | Implies Mode |
|----------|--------|-------------|
| `UPLOAD_VUSER` | pure-ftpd | `ftp` |
| *(none of above)* | — | `modsec` (default) |

**Auto-detection is limited to pure-ftpd only.** `UPLOAD_VUSER` is set by the
`pure-uploadscript` daemon in a controlled context (not user-spawnable).
ProFTPD and Exim have no reliable auto-detection variables — `PROFTPD_USER`
requires explicit `ExecEnviron` config (admin-controlled, not auto-set), and
Exim's `cmdline` scanner type sets no environment variables.

**Security:** Auto-detection via env vars is convenience for the pure-ftpd
`pure-uploadscript -r hookscan.sh` use case (no mode arg possible). For all
other services, explicit mode argument is required. The homedir restriction
(§A4-FIX) is gated on the calling UID, not the mode, so env-var spoofing
by a local user cannot bypass path restrictions.

Explicit mode argument always takes precedence over auto-detection.

## Appendix C: Adversarial Review Record

### Review 1: Hookscan Core (§1-12)

**Reviewer:** rdf-reviewer (challenge mode)
**Date:** 2026-03-23
**Verdict:** CONCERNS (4 must-fix, 6 should-fix, 3 informational) — all resolved.

All must-fix findings have been integrated into this spec:

| Finding | Severity | Resolution |
|---------|----------|-----------|
| `realpath -e` absent on CentOS 6 | MUST-FIX | Changed to `readlink -e` throughout |
| `$hitname` empty in batch/no-quarantine path | MUST-FIX | Documented in §3.3: read from session.hits TSV |
| `LOCAL_SCAN_DATA` auto-detection wrong | MUST-FIX | Removed; Exim requires explicit mode arg |
| Service-mode homedir bypass spoofable | MUST-FIX | Gated on UID whitelist, not mode string (§A4-FIX) |
| `_safe_source_conf` no context param | SHOULD-FIX | Replaced with inline allowlist parser (§A5-FIX) |
| "Self-contained" language misleading | SHOULD-FIX | Reworded in §3.3 |
| Relative paths not handled | SHOULD-FIX | Absolute path validation added to §3.1 |
| Inconsistent fail-open/closed behavior | SHOULD-FIX | Error behavior matrix added (§8.4) |
| Env-var auto-detection poisonable | SHOULD-FIX | Scoped to pure-ftpd only (Appendix B) |
| Integration examples pass directories | INFO | Fixed examples, added note |
| `cd` guard missing | INFO | Noted for implementation |
| Inline ClamAV detection redundant | INFO | Documented removal in §6.2 |

### Review 2: Alert/Digest/Test-Alert (§13-15)

**Reviewer:** rdf-reviewer (challenge mode)
**Date:** 2026-03-23
**Verdict:** CONCERNS (3 must-fix, 6 should-fix, 5 informational) — all resolved.

| Finding | Severity | Resolution |
|---------|----------|-----------|
| `_genalert_digest()` hard-depends on monitor mode | MUST-FIX | §14.2 refactored: monitor preamble made conditional, hook-only digest path documented |
| Escalation passes raw `hook.hits.log` to `genalert file` | MUST-FIX | §13.4: builds temp session from 1-hour window hits via awk timestamp filter |
| §13.3 and §13.4 describe overlapping code modifications | MUST-FIX | Merged into single unified code block in §13.3 |
| `maldet -p` wipes hook.hits.log undocumented | SHOULD-FIX | §13.2: documented purge behavior |
| `trim_log()` doesn't adjust tlog cursors | SHOULD-FIX | §13.2 + §14.5: `tlog_adjust_cursor()` after trim, cron.daily is single trim owner |
| Concurrent trim from monitor + cron.daily unserialized | SHOULD-FIX | §14.5: cron.daily is exclusive trim owner; monitor only reads |
| Escalation counter race under concurrency | SHOULD-FIX | §13.4: documented as best-effort; flock latency unacceptable on hot path |
| `--test-alert` works for non-root (amplification) | SHOULD-FIX | §15.9: gated on root |
| `--digest --dry-run` unspecified, advances cursors | SHOULD-FIX | §14.4.2: dropped from initial spec, deferred to future |
| Hook hit log injection via filepath | INFO | Hookscan input validation rejects non-printable chars including tabs |
| §3.3 flow diagram stale | INFO | Updated to show hook-scan branch |
| §8 adversarial gaps for §13-15 | INFO | Added A11-A13 to threat summary |
| `cron_digest_hook` in correct config file | INFO | Correctly placed in `conf.maldet` (not hookscan config) |
| Mixed tlog bytes/lines mode | INFO | Independent cursors; trim adjustment uses bytes delta |
