# Linux Malware Detect (LMD)

[![Version](https://img.shields.io/badge/version-2.0.1-blue.svg)](CHANGELOG)
[![License: GPL v2](https://img.shields.io/badge/license-GPL_v2-green.svg)](COPYING.GPL)
[![CI](https://github.com/rfxn/linux-malware-detect/actions/workflows/smoke-test.yml/badge.svg?branch=master)](https://github.com/rfxn/linux-malware-detect/actions/workflows/smoke-test.yml)

**Malware scanner for Linux** — multi-stage threat detection (MD5, HEX, YARA, statistical
analysis), ClamAV integration, real-time inotify monitoring, quarantine/clean/restore
operations, and multi-channel alerting (email, Slack, Telegram).

> (C) 2002-2026, R-fx Networks &lt;proj@rfxn.com&gt;<br>
> (C) 2026, Ryan MacDonald &lt;ryan@rfxn.com&gt;<br>
> Licensed under [GNU GPL v2](COPYING.GPL)

---

## Contents

- [1. Introduction](#1-introduction)
- [2. Installation](#2-installation)
- [3. Configuration](#3-configuration)
  - [3.1 General Options](#31-general-options)
  - [3.2 Alerting](#32-alerting)
  - [3.3 Scanning Options](#33-scanning-options)
  - [3.4 YARA Scanning](#34-yara-scanning)
  - [3.5 Quarantine Options](#35-quarantine-options)
  - [3.6 Monitoring Options](#36-monitoring-options)
  - [3.7 ClamAV Integration](#37-clamav-integration)
  - [3.8 Remote ClamAV](#38-remote-clamav)
  - [3.9 ELK Integration](#39-elk-integration)
  - [3.10 Configuration Loading Order](#310-configuration-loading-order)
- [4. CLI Usage](#4-cli-usage)
- [5. Ignore Options](#5-ignore-options)
- [6. Cron Daily](#6-cron-daily)
- [7. Inotify Monitoring](#7-inotify-monitoring)
- [8. Signature System](#8-signature-system)
  - [8.1 Signature Updates](#81-signature-updates)
  - [8.2 Custom Signatures](#82-custom-signatures)
- [9. Quarantine & Cleaning](#9-quarantine--cleaning)
  - [9.1 Cleaner Rules](#91-cleaner-rules)
- [10. ModSecurity2 Upload Scanning](#10-modsecurity2-upload-scanning)
- [11. License](#11-license)
- [12. Support Information](#12-support-information)

---

## Quick Start

```bash
# Install to /usr/local/maldetect
./install.sh

# Scan all files under a path
maldet -a /home/?/public_html

# Scan files modified in the last 2 days
maldet -r /home/?/public_html 2

# Enable YARA scanning at runtime
maldet -co scan_yara=1 -a /home/?/public_html

# Quarantine all hits from a scan
maldet -q SCANID

# Start real-time inotify monitoring
maldet -m users

# Update signatures
maldet -u
```

---

## 1. Introduction

Linux Malware Detect (LMD) is a malware scanner for Linux released under the GNU GPLv2 license, designed around the threats faced in shared hosted environments. It uses threat data from network edge intrusion detection systems to extract malware that is actively being used in attacks and generates signatures for detection. In addition, threat data is derived from user submissions with the LMD checkout feature and from malware community resources.

LMD focuses on the malware classes that traditional AV products frequently miss: PHP shells, JavaScript injectors, base64-encoded backdoors, IRC bots, and other web-application-layer threats that target shared hosting user accounts rather than operating system internals.

**Detection Stages**
- MD5 file hash matching for exact threat identification
- HEX pattern matching for identifying threat variants and families
- Native YARA rule scanning with full module support and custom rules
- Statistical string-length analysis for detecting obfuscated threats (base64, gzinflate)
- ClamAV integration for extended coverage with LMD-maintained ClamAV signatures

**Scanning & Monitoring**
- Scan all files, recently modified files, or files from a list
- Kernel inotify real-time file monitoring (create/modify/move events)
- HTTP upload scanning via ModSecurity2 `inspectFile` hook
- Background scanning for unattended large-scale operations
- Per-scan include/exclude regex filtering

**Quarantine & Response**
- Quarantine queue with zero-permission file storage
- Batch quarantine/restore by scan ID
- Signature-specific cleaner rules for malware removal
- Full file restoration (content, owner, permissions, mtime)

**Alerting & Reporting**
- Email alerts per scan or daily digest
- Slack alerting via Bot API (files.getUploadURLExternal)
- Telegram alerting via Bot API (sendDocument)
- Scan reports with per-file hit details

**Infrastructure**
- Automatic ClamAV signature linking for dual-engine coverage
- Daily cron with auto-detection of 12+ hosting control panels
- CPU/IO resource control (nice, ionice, cpulimit)
- Signature and version auto-updates
- systemd service unit and SysV init script support

### Supported Platforms

LMD runs on any Linux distribution with bash and standard GNU utilities. Tested platforms:

| Platform | Init System | Package Config Path |
|----------|-------------|---------------------|
| RHEL / Rocky / AlmaLinux 8, 9, 10 | systemd | `/etc/sysconfig/maldet` |
| CentOS 6, 7 | SysV / systemd | `/etc/sysconfig/maldet` |
| Debian 10, 11, 12 | systemd | `/etc/default/maldet` |
| Ubuntu 20.04, 22.04, 24.04 | systemd | `/etc/default/maldet` |
| Gentoo | OpenRC | — |
| Slackware | SysV | — |
| FreeBSD | — | — (partial; no inotify) |

---

## 2. Installation

The included `install.sh` script handles all installation tasks. Previous installations are automatically backed up.

```bash
./install.sh
```

The installer:
- Copies files to `/usr/local/maldetect`
- Creates the `maldet` symlink in `/usr/local/sbin/`
- Installs the cron.daily script to `/etc/cron.daily/maldet`
- Installs the systemd service unit (or SysV init script on older systems)
- Links LMD signatures to ClamAV data directories (if ClamAV is installed)
- Preserves existing configuration (`conf.maldet`), custom signatures, and ignore files across upgrades

Previous installs are saved to `/usr/local/maldetect.bk{PID}` with a `maldetect.last` symlink to the most recent backup.

**Default paths:**
- **Install path:** `/usr/local/maldetect`
- **Binary symlink:** `/usr/local/sbin/maldet`
- **Cron script:** `/etc/cron.daily/maldet`
- **Service unit:** `/usr/lib/systemd/system/maldet.service`

---

## 3. Configuration

The main configuration file is `/usr/local/maldetect/conf.maldet`. All options are commented for ease of configuration. Options use `0`/`1` for disable/enable unless otherwise noted.

Configuration can also be overridden at runtime using the `-co` flag:

```bash
maldet -co quarantine_hits=1,email_addr=you@domain.com -a /home
```

### 3.1 General Options

| Variable | Purpose | Default |
|----------|---------|---------|
| `autoupdate_signatures` | Auto-update signatures daily via cron | `1` |
| `autoupdate_version` | Auto-update LMD version daily via cron | `1` |
| `autoupdate_version_hashed` | Verify LMD executable MD5 against upstream | `1` |
| `cron_prune_days` | Days to retain quarantine/session/temp data | `21` |
| `cron_daily_scan` | Enable daily automatic scanning via cron | `1` |
| `import_config_url` | URL to download remote configuration override | — |
| `import_config_expire` | Cache expiry for imported config (seconds) | `43200` |
| `import_custsigs_md5_url` | URL to download custom MD5 signatures | — |
| `import_custsigs_hex_url` | URL to download custom HEX signatures | — |
| `import_custsigs_yara_url` | URL to download custom YARA rules | — |

### 3.2 Alerting

| Variable | Purpose | Default |
|----------|---------|---------|
| `email_alert` | Enable email alerts after scans | `0` |
| `email_addr` | Alert recipient address | `you@domain.com` |
| `email_subj` | Email subject line template | `maldet alert from $(hostname)` |
| `email_ignore_clean` | Suppress alerts when all hits were cleaned | `1` |
| `email_panel_user_alerts` | Send panel user alerts on hit detection | `0` |
| `email_panel_from` | From header for panel user alerts | `you@example.com` |
| `email_panel_replyto` | Reply-To header for panel user alerts | `you@example.com` |
| `email_panel_alert_subj` | Subject line for panel user alerts | `maldet alert from $(hostname)` |
| `slack_alert` | Enable Slack file upload alerts | `0` |
| `slack_subj` | File name for Slack upload | `maldet alert from $(hostname)` |
| `slack_token` | Slack Bot API token (scopes: `files:write`, `files:read`) | — |
| `slack_channels` | Comma-separated list of channel names or IDs | `maldetreports` |
| `telegram_alert` | Enable Telegram alerts | `0` |
| `telegram_file_caption` | Caption for Telegram report file | `maldet alert from $(hostname)` |
| `telegram_bot_token` | Telegram Bot API token | — |
| `telegram_channel_id` | Telegram chat or group ID | — |

### 3.3 Scanning Options

| Variable | Purpose | Default |
|----------|---------|---------|
| `scan_max_depth` | Maximum directory depth for find | `15` |
| `scan_min_filesize` | Minimum file size to scan | `24` bytes |
| `scan_max_filesize` | Maximum file size to scan | `2048k` |
| `scan_hexdepth` | Byte depth for HEX signature matching | `65536` |
| `scan_hexfifo` | Use FIFO-based HEX scanner (faster) | `1` |
| `scan_hexfifo_depth` | Byte depth for FIFO HEX scanner | `524288` |
| `scan_cpunice` | Nice priority for scan process (-19 to 19) | `19` |
| `scan_ionice` | IO scheduling class priority (0-7) | `6` |
| `scan_cpulimit` | Hard CPU limit percentage (0=disabled) | `0` |
| `scan_ignore_root` | Skip root-owned files in scans | `1` |
| `scan_ignore_user` | Skip files owned by specific users | — |
| `scan_ignore_group` | Skip files owned by specific groups | — |
| `scan_user_access` | Allow non-root users to run scans | `0` |
| `scan_user_access_minuid` | Minimum UID for --mkpubpaths user directory creation | `100` |
| `scan_find_timeout` | Timeout for find file list generation (0=disabled, min 60s) | `0` |
| `scan_export_filelist` | Save find results to tmp/find_results.last | `0` |
| `scan_tmpdir_paths` | World-writable temp paths included in -a/-r scans | `/tmp /var/tmp /dev/shm /var/fcgi_ipc` |
| `string_length_scan` | Enable statistical string-length analysis | `0` |
| `string_length` | Minimum suspicious string length | `150000` |

### 3.4 YARA Scanning

Native YARA scanning invokes the `yara` binary (or `yr` from YARA-X) independently of ClamAV, supporting full YARA modules, compiled rules, and custom rule files that ClamAV's limited YARA subset cannot handle. When both are available, `yr` (YARA-X) is preferred.

| Variable | Purpose | Default |
|----------|---------|---------|
| `scan_yara` | Enable native YARA scan stage | `0` |
| `scan_yara_timeout` | Timeout in seconds (0=no timeout) | `300` |
| `scan_yara_scope` | Rule scope when ClamAV is also active: `all` (full native scan) or `custom` (only custom rules natively, ClamAV handles rfxn.yara) | `custom` |
| `import_custsigs_yara_url` | URL to download custom YARA rules on signature update | — |

**Custom YARA rules** can be placed in two locations, both preserved across upgrades:
- `sigs/custom.yara` — single-file rules
- `sigs/custom.yara.d/` — drop-in directory for `.yar` and `.yara` rule files

Compatible with third-party rule sets such as [YARA Forge](https://yarahq.github.io/) and [Signature Base](https://github.com/Neo23x0/signature-base). Compiled rules (`yarac` output) are also supported via `sigs/compiled.yarc`.

**Batch scanning:** YARA 4.0+ and all YARA-X versions use `--scan-list` for efficient batch file scanning. Older YARA versions fall back to per-file scanning automatically.

Enable at runtime without editing config:

```bash
maldet -co scan_yara=1 -a /home/?/public_html
```

### 3.5 Quarantine Options

| Variable | Purpose | Default |
|----------|---------|---------|
| `quarantine_hits` | Automatically quarantine detected malware | `0` |
| `quarantine_clean` | Try to clean malware from quarantined files | `0` |
| `quarantine_suspend_user` | Suspend cPanel account or revoke shell on hit | `0` |
| `quarantine_suspend_user_minuid` | Minimum UID to suspend (protects system accounts) | `500` |
| `quarantine_on_error` | Quarantine files when scan engine returns error | `1` |

### 3.6 Monitoring Options

| Variable | Purpose | Default |
|----------|---------|---------|
| `default_monitor_mode` | Startup mode for monitor (`users` or path to file) | `users` |
| `inotify_base_watches` | Base number of file watches per user path | `16384` |
| `inotify_minuid` | Minimum UID for user home monitoring | `500` |
| `inotify_docroot` | Subdirectories to monitor in user homes | `public_html,public_ftp` |
| `inotify_sleep` | Seconds between scan batches | `15` |
| `inotify_reloadtime` | Seconds between config reloads | `3600` |
| `inotify_cpunice` | Nice priority for monitor process | `18` |
| `inotify_ionice` | IO priority for monitor process | `6` |
| `inotify_cpulimit` | Hard CPU limit for monitor (0=disabled) | `0` |
| `inotify_verbose` | Log every file scanned (debug only) | `0` |

### 3.7 ClamAV Integration

When `scan_clamscan=1`, LMD selects the best available ClamAV engine in priority order:

1. Remote `clamdscan` (if `scan_clamd_remote=1` and config exists)
2. Local `clamd` daemon running as root
3. Local `clamd` daemon running as non-root (with `--fdpass`)
4. `clamscan` binary (fallback, slower)

LMD signatures are automatically symlinked to ClamAV data directories by `install.sh`, giving ClamAV access to LMD's MD5 (`rfxn.hdb`), HEX (`rfxn.ndb`), and YARA (`rfxn.yara`) signatures.

| Variable | Purpose | Default |
|----------|---------|---------|
| `scan_clamscan` | Enable ClamAV as scan engine | `1` |

### 3.8 Remote ClamAV

| Variable | Purpose | Default |
|----------|---------|---------|
| `scan_clamd_remote` | Use a remote clamd server for scanning | `0` |
| `remote_clamd_config` | Path to remote clamd config file | `/etc/clamd.d/clamd.remote.conf` |
| `remote_clamd_max_retry` | Max retries on remote clamd failure | `5` |
| `remote_clamd_retry_sleep` | Seconds between retries | `3` |

### 3.9 ELK Integration

| Variable | Purpose | Default |
|----------|---------|---------|
| `enable_statistic` | Enable ELK stack statistics collection | `0` |
| `elk_host` | TCP host for ELK input | — |
| `elk_port` | TCP port for ELK input | — |
| `elk_index` | Elasticsearch index name | — |

### 3.10 Configuration Loading Order

Later sources override earlier values:

1. `internals/internals.conf` — internal paths, binary discovery, URL definitions
2. `conf.maldet` — user-facing configuration
3. `internals/compat.conf` — deprecated variable mappings
4. `/etc/sysconfig/maldet` or `/etc/default/maldet` — system overrides
5. CLI `-co|--config-option` — runtime overrides

---

## 4. CLI Usage

```
usage: maldet [OPTION] [ARGUMENT]

SCANNING:
  -a, --scan-all PATH           scan all files in path (wildcard: ?)
  -r, --scan-recent PATH DAYS   scan files created/modified in last X days
  -f, --file-list FILE          scan files from a line-separated file list
  -b, --background              run scan in the background

SCAN FILTERS:
  -i, --include-regex REGEX     include only matching paths
  -x, --exclude-regex REGEX     exclude matching paths
  -co, --config-option V=V,...  override config options at runtime
  -U, --user USER               run as specified user

MONITORING:
  -m, --monitor USERS|PATHS|FILE  start inotify real-time monitoring
  -k, --kill-monitor            stop inotify monitoring

QUARANTINE & RESTORE:
  -q, --quarantine SCANID       quarantine hits from scan
  -n, --clean SCANID            clean malware from scan hits
  -s, --restore FILE|SCANID     restore quarantined file(s)

REPORTING:
  -e, --report [SCANID] [email] view or email scan report
  -E, --dump-report SCANID      dump report to stdout
  --alert-daily                 generate inotify monitor digest alert
  -l, --log                     view event log

UPDATES:
  -u, --update-sigs [--force]   update malware signatures
  -d, --update-ver [--force|--beta]  update LMD version

OTHER:
  -p, --purge                   clear logs, quarantine, temp data
  -c, --checkout FILE           submit suspected malware to rfxn.com
  --web-proxy IP:PORT           set HTTP/HTTPS proxy
  -h, --help                    show detailed help
```

**Exit codes:** `0` = success / no hits, `1` = error, `2` = malware hits found.

**Examples:**

```bash
# Scan all files under user web roots
maldet -a /home/?/public_html

# Scan recent files with auto-quarantine and YARA enabled
maldet -co quarantine_hits=1,scan_yara=1 -r /home/?/public_html 2

# Background scan with email alert to specific address
maldet -b -co email_addr=admin@example.com -a /var/www

# View the most recent scan report
maldet -e

# Email a specific report
maldet -e 050910-1534.21135 admin@example.com

# Restore all quarantined files from a scan
maldet -s 050910-1534.21135
```

---

## 5. Ignore Options

Four ignore files control what is excluded from scanning:

| File | Format | Purpose |
|------|--------|---------|
| `ignore_paths` | Line-separated paths | Exclude directories or files from scans |
| `ignore_file_ext` | Line-separated extensions | Exclude file extensions (`.js`, `.css`) |
| `ignore_sigs` | Line-separated patterns | Skip matching signatures (regex, substring match) |
| `ignore_inotify` | Line-separated regex patterns | Exclude inotify monitoring events |

All ignore files are located under `/usr/local/maldetect/`.

**Examples:**

```
# ignore_paths
/home/user/public_html/cgi-bin

# ignore_file_ext
.js
.css

# ignore_sigs
base64.inject.unclassed

# ignore_inotify
^/home/user$
^/var/tmp/#sql_.*\.MYD$
```

**Note:** `ignore_sigs` entries are treated as extended regex patterns and match as substrings. An entry `php.shell` will suppress `php.shell`, `php.shell.v2`, `{YARA}php.shell.backdoor`, etc. Use `^php\.shell$` for an exact match. The `.` character matches any character in regex; escape it as `\.` for a literal dot.

---

## 6. Cron Daily

The cron job installed at `/etc/cron.daily/maldet` performs three tasks:

1. **Prune** quarantine, session, and temp data older than `cron_prune_days` (default: 21)
2. **Update** signatures and version (when `autoupdate_signatures` and `autoupdate_version` are enabled)
3. **Scan** recently modified files under detected hosting panel paths

The daily scan auto-detects installed control panels and adjusts scan paths accordingly:

| Panel | Scan Path |
|-------|-----------|
| cPanel | `/home?/?/public_html/` (+ addon/subdomain docroots) |
| Plesk | `/var/www/vhosts/?/` |
| DirectAdmin | `/home?/?/domains/?/public_html/` |
| Ensim | `/home/virtual/?/fst/var/www/html/` |
| ISPConfig | `/var/www/clients/?/web?/web` |
| Virtualmin | `/home/?/public_html/` |
| ISPmanager | `/var/www/?/data/` |
| Froxlor | `/var/customers/webs/` |
| Bitrix | `/home/bitrix/www/`, `/home/bitrix/ext_www/?/` |
| VestaCP / HestiaCP | `/home/?/web/?/public_html/` |
| DTC | `${conf_hosting_path}/` |

If monitor mode is active, daily scans are skipped and a daily report of monitoring events is issued instead.

For custom scan paths, use the hook file `/usr/local/maldetect/cron/custom.cron`. For configuration overrides specific to cron, use `/etc/sysconfig/maldet` (RHEL) or `/etc/default/maldet` (Debian) or `/usr/local/maldetect/cron/conf.maldet.cron`.

A weekly watchdog script (`/etc/cron.weekly/maldet-watchdog`) provides independent fallback signature updates when the primary cron is broken or stale.

---

## 7. Inotify Monitoring

Real-time file monitoring uses the kernel inotify subsystem to detect file creation, modification, and move events. Requires a kernel with `CONFIG_INOTIFY_USER` (standard on all modern kernels).

```bash
# Monitor all user home directories (UIDs >= inotify_minuid)
maldet -m users

# Monitor specific paths
maldet -m /home/mike,/home/ashton

# Monitor paths from a file
maldet -m /root/monitor_paths

# Stop monitoring
maldet -k
```

**How it works:**

1. `monitor_init()` sets up inotify watches on all files under monitored paths
2. File events are queued and batch-scanned every `inotify_sleep` seconds (default: 15)
3. Configuration is reloaded every `inotify_reloadtime` seconds (default: 3600)
4. Kernel `max_user_watches` and `max_user_instances` are auto-tuned for optimal performance

When using the `users` mode, only subdirectories matching `inotify_docroot` (default: `public_html,public_ftp`) are monitored, plus the system temp directories `/tmp`, `/var/tmp`, and `/dev/shm`.

Alerting in monitor mode uses daily digest reports via the cron job rather than per-file alerts.

---

## 8. Signature System

LMD ships with three signature types:

| Type | File | Format | Count |
|------|------|--------|-------|
| MD5 hashes | `sigs/md5v2.dat` | `HASH:SIZE:{MD5}sig.name.N` | ~14,801 |
| HEX patterns | `sigs/hex.dat` | `HEXSTRING:{HEX}sig.name.N` | ~2,054 |
| YARA rules | `sigs/rfxn.yara` | YARA syntax | ~783 rules |
| Compiled YARA | `sigs/compiled.yarc` | `yarac` output | optional |

ClamAV-compatible signatures are also maintained:
- `sigs/rfxn.hdb` — ClamAV MD5 format
- `sigs/rfxn.ndb` — ClamAV HEX format

**Signature naming convention:** `{TYPE}category.name.variant_number`

Categories include: `bin.` (binary), `c.` (C language), `exp.` (exploit), `php.` (PHP), `js.` (JavaScript), `perl.` (Perl), `html.` (phishing), `base64.inject.`, `gzbase64.`

**Hit prefixes in scan reports:**

| Prefix | Source |
|--------|--------|
| `{MD5}` | MD5 hash match (stage 1) |
| `{HEX}` | HEX pattern match (stage 2) |
| `{SA}` | Statistical analysis (string length) |
| `{YARA}` | Native YARA scan (`scan_yara=1`) |
| `{CAV}` | ClamAV engine (clamd/clamscan) |

### 8.1 Signature Updates

Signatures are updated daily via the cron job or manually:

```bash
maldet -u            # update signatures
maldet -u --force    # force update even if current
```

### 8.2 Custom Signatures

Custom signatures can be added in three formats, all preserved across upgrades:

| Type | File | Format |
|------|------|--------|
| Custom MD5 | `sigs/custom.md5.dat` | Same as `md5v2.dat` |
| Custom HEX | `sigs/custom.hex.dat` | Same as `hex.dat` |
| Custom YARA | `sigs/custom.yara` | YARA rule syntax |
| Custom YARA (drop-in) | `sigs/custom.yara.d/*.yar` | YARA rule files |
| Compiled YARA | `sigs/compiled.yarc` | `yarac` output (optional) |

Remote import URLs can be configured for automatic download during signature updates:

| Variable | Purpose |
|----------|---------|
| `import_custsigs_md5_url` | URL for custom MD5 signatures |
| `import_custsigs_hex_url` | URL for custom HEX signatures |
| `import_custsigs_yara_url` | URL for custom YARA rules |

---

## 9. Quarantine & Cleaning

Quarantined files are stored under `/usr/local/maldetect/quarantine/` with permissions set to `000`. Original path, owner, permissions, and modification time are recorded in `quarantine.hist` for full restoration.

```bash
# Quarantine all hits from a scan
maldet -q SCANID

# Restore all quarantined files from a scan
maldet -s SCANID

# Restore a specific file
maldet -s /usr/local/maldetect/quarantine/config.php.23754

# Clean (attempt malware removal) from a scan
maldet -n SCANID
```

**Quarantine file naming:** `YYYYMMDD-HH-SIGNATURE-SCANPID.INODE`

For non-root scans (e.g., ModSecurity2 upload scanning), quarantine data is stored under `/usr/local/maldetect/pub/USERNAME/quar/`. Use the `-U` flag to interact with non-root quarantine:

```bash
maldet -U nobody -s 112012-0032.13771
```

### 9.1 Cleaner Rules

The cleaner function looks for signature-named scripts under the `clean/` directory. Each script receives the infected file path as an argument and should strip the malicious content. After cleaning, the file is rescanned — if it still triggers a hit, the clean is marked FAILED.

To create a clean rule for signature `php.cmdshell.r57`, add a file `clean/php.cmdshell.r57` containing a command like `sed -i` with the appropriate pattern. Successful cleans restore the file to its original path, owner, and permissions.

The cleaner is a sub-function of quarantine — files must be quarantined (or use `-n`) for cleaning to execute.

---

## 10. ModSecurity2 Upload Scanning

LMD integrates with ModSecurity2's `inspectFile` hook for real-time HTTP upload scanning via the included `hookscan.sh` script.

**Setup:**

1. Enable user access scanning in `conf.maldet`:
   ```
   scan_user_access=1
   ```

2. Add to your ModSecurity2 configuration:
   ```apache
   SecRequestBodyAccess On
   SecRule FILES_TMPNAMES "@inspectFile /usr/local/maldetect/hookscan.sh" \
       "id:'999999',log,auditlog,deny,severity:2,phase:2,t:none"
   ```
   For ModSecurity >= 2.9, add `SecTmpSaveUploadedFiles On` before the rule.

3. Restart Apache.

Malicious uploads are rejected with a 406 status code and logged to the ModSecurity audit log. The default scan options enable quarantine and auto-detect ClamAV (if the `clamd` daemon is running, ClamAV is used; otherwise the native engine is used). YARA scanning is disabled by default. To customize scan options, create `conf.maldet.hookscan` in the install directory — it is sourced after the defaults and can override any scan variable.

Run `maldet --mkpubpaths` after enabling to create per-user data directories for non-root scan operations.

---

## 11. License

LMD is developed and supported on a volunteer basis by Ryan MacDonald [ryan@rfxn.com].

Linux Malware Detect (LMD) is distributed under the GNU General Public License (GPL) v2
without restrictions on usage or redistribution. The copyright statement and GNU GPL
are included in the `COPYING.GPL` file. Credit must be given for derivative works as
required under GNU GPL.

---

## 12. Support Information

The LMD source repository is at: https://github.com/rfxn/linux-malware-detect

Bugs, feature requests, and general questions can be filed as GitHub issues or sent to proj@rfxn.com.

The official project page is at: https://www.rfxn.com/projects/linux-malware-detect/
