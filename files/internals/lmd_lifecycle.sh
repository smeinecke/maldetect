#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck disable=SC1090,SC1091
##
# Linux Malware Detect v2.0.1
#             (C) 2002-2026, R-fx Networks <proj@rfxn.com>
#             (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
# Scan lifecycle management: kill, pause/unpause, stop/continue, list, meta, sentinel IPC

# Source guard
[[ -n "${_LMD_LIFECYCLE_LOADED:-}" ]] && return 0 2>/dev/null
_LMD_LIFECYCLE_LOADED=1

# shellcheck disable=SC2034
LMD_LIFECYCLE_VERSION="1.0.0"

# _lifecycle_write_meta scanid pid ppid path total_files workers engine hashtype stages options
# Writes $sessdir/scan.meta.$scanid with #LMD_META:v1 header.
# Atomic: writes to .tmp then renames.
_lifecycle_write_meta() {
	local _scanid="$1" _pid="$2" _ppid="$3" _path="$4"
	local _total_files="$5" _workers="$6" _engine="$7"
	local _hashtype="$8" _stages="$9"
	shift 9
	local _options="$1"
	local _meta_file="$sessdir/scan.meta.$_scanid"
	local _tmp_file="$_meta_file.tmp"
	local _started _started_hr _sig_ver

	_started=$(command date +%s)
	_started_hr=$(command date "+%b %d %Y %H:%M:%S %z")

	# Read sig version from on-disk file (first line), fallback to "unknown"
	if [ -f "$sigdir/maldet.sigs.ver" ]; then
		IFS= read -r _sig_ver < "$sigdir/maldet.sigs.ver"
	else
		_sig_ver="unknown"
	fi
	[ -z "$_sig_ver" ] && _sig_ver="unknown"

	command cat > "$_tmp_file" <<EOF
#LMD_META:v1
pid=$_pid
ppid=$_ppid
started=$_started
started_hr=$_started_hr
path=$_path
total_files=$_total_files
workers=$_workers
engine=$_engine
hashtype=$_hashtype
stages=$_stages
sig_version=$_sig_ver
options=$_options
state=running
EOF

	command mv -f "$_tmp_file" "$_meta_file"
}

# _lifecycle_update_meta scanid key value
# Appends key=value to existing meta file. Last-value-wins on read.
_lifecycle_update_meta() {
	local _scanid="$1" _key="$2" _value="$3"
	local _meta_file="$sessdir/scan.meta.$_scanid"

	[ -f "$_meta_file" ] || return 1

	printf '%s=%s\n' "$_key" "$_value" >> "$_meta_file"
}

# _lifecycle_read_meta scanid
# Parses scan.meta.$scanid into _meta_* variables in caller's scope.
# Last-value-wins: later lines override earlier ones for the same key.
# Returns 1 if meta file does not exist.
# shellcheck disable=SC2034
_lifecycle_read_meta() {
	local _scanid="$1"
	local _meta_file="$sessdir/scan.meta.$_scanid"
	local _key _value

	[ -f "$_meta_file" ] || return 1

	# Initialize all meta variables to empty (caller scope — no local)
	_meta_pid=""
	_meta_ppid=""
	_meta_started=""
	_meta_started_hr=""
	_meta_path=""
	_meta_total_files=""
	_meta_workers=""
	_meta_engine=""
	_meta_hashtype=""
	_meta_stages=""
	_meta_sig_version=""
	_meta_options=""
	_meta_state=""
	_meta_stage=""
	_meta_stage_started=""
	_meta_progress_pos=""
	_meta_progress_total=""
	_meta_hits=""
	_meta_stopped=""
	_meta_stopped_hr=""
	_meta_completed=""
	_meta_completed_hr=""
	_meta_elapsed=""

	while IFS='=' read -r _key _value; do
		# Skip comments and empty lines
		case "$_key" in
			"#"*|"") continue ;;
		esac
		case "$_key" in
			pid)             _meta_pid="$_value" ;;
			ppid)            _meta_ppid="$_value" ;;
			started)         _meta_started="$_value" ;;
			started_hr)      _meta_started_hr="$_value" ;;
			path)            _meta_path="$_value" ;;
			total_files)     _meta_total_files="$_value" ;;
			workers)         _meta_workers="$_value" ;;
			engine)          _meta_engine="$_value" ;;
			hashtype)        _meta_hashtype="$_value" ;;
			stages)          _meta_stages="$_value" ;;
			sig_version)     _meta_sig_version="$_value" ;;
			options)         _meta_options="$_value" ;;
			state)           _meta_state="$_value" ;;
			stage)           _meta_stage="$_value" ;;
			stage_started)   _meta_stage_started="$_value" ;;
			progress_pos)    _meta_progress_pos="$_value" ;;
			progress_total)  _meta_progress_total="$_value" ;;
			hits)            _meta_hits="$_value" ;;
			stopped)         _meta_stopped="$_value" ;;
			stopped_hr)      _meta_stopped_hr="$_value" ;;
			completed)       _meta_completed="$_value" ;;
			completed_hr)    _meta_completed_hr="$_value" ;;
			elapsed)         _meta_elapsed="$_value" ;;
		esac
	done < "$_meta_file"

	return 0
}

# _lifecycle_detect_state scanid
# Outputs state to stdout: running|paused|stopped|stale|killed|completed
# Returns 1 if meta file does not exist.
_lifecycle_detect_state() {
	local _scanid="$1"

	_lifecycle_read_meta "$_scanid" || return 1

	# Terminal states — trust the recorded state
	case "$_meta_state" in
		completed|killed|stopped)
			echo "$_meta_state"
			return 0
			;;
	esac

	# Check if process is alive (kill -0 works on FreeBSD too)
	if kill -0 "$_meta_pid" 2>/dev/null; then  # safe: kill -0 returns 1 if no such process
		# PID alive — check for pause sentinel
		if [ -f "$tmpdir/.pause.$_scanid" ]; then
			echo "paused"
		else
			echo "running"
		fi
	else
		# PID dead but state not terminal — stale
		echo "stale"
	fi

	return 0
}

##
# _lifecycle_check_sentinels(scanid)
#   Workers call this at natural boundaries (micro-chunk end, post-xargs,
#   per-file YARA) to detect abort/pause signals.
#   Returns: 0=continue, 1=abort(kill), 2=paused, 4=stop(checkpoint)
#   Distinguishes kill vs stop by reading first line of abort sentinel:
#     "stop" → return 4 (worker should checkpoint then exit)
#     anything else → return 1 (hard abort, no checkpoint)
#   Cost: one stat() + one read() when sentinel present — negligible (R1).
##
_lifecycle_check_sentinels() {
	local scanid="$1"
	# Abort/stop takes priority over pause (E15)
	if [ -f "$tmpdir/.abort.$scanid" ]; then
		local _sentinel_type
		IFS= read -r _sentinel_type < "$tmpdir/.abort.$scanid" 2>/dev/null  # safe: sentinel may vanish between check and read
		if [ "$_sentinel_type" = "stop" ]; then
			return 4
		fi
		return 1
	fi
	if [ -f "$tmpdir/.pause.$scanid" ]; then
		return 2
	fi
	return 0
}

##
# _lifecycle_format_elapsed(seconds)
#   Formats seconds into a human-readable string: Xh Ym
#   Returns via stdout.
##
_lifecycle_format_elapsed() {
	local _secs="$1"
	local _hours _mins
	[ -z "$_secs" ] || [ "$_secs" = "-" ] && _secs=0
	_hours=$((_secs / 3600))
	_mins=$(((_secs % 3600) / 60))
	printf '%dh %02dm' "$_hours" "$_mins"
}

##
# _lifecycle_list_active(format, verbose, single_scanid)
#   Enumerates $sessdir/scan.meta.* files, detects state for each, collects
#   active (non-terminal) scans. Dispatches to appropriate format renderer.
#   If no active scans found, outputs "No active scans." to stderr and returns 1.
#   When single_scanid is set, only that scan is considered.
##
_lifecycle_list_active() {
	local _format="${1:-text}" _verbose="${2:-0}" _single_scanid="${3:-}"
	local _scanid _state _found=0
	local _active_ids=""

	if [ -n "$_single_scanid" ]; then
		# Single scan mode
		if [ ! -f "$sessdir/scan.meta.$_single_scanid" ]; then
			echo "No active scans." >&2
			return 1
		fi
		_state=$(_lifecycle_detect_state "$_single_scanid" 2>/dev/null) || {  # safe: stderr suppressed; missing meta handled by return 1
			echo "No active scans." >&2
			return 1
		}
		case "$_state" in
			running|paused|stale)
				_active_ids="$_single_scanid"
				_found=1
				;;
			*)
				echo "No active scans." >&2
				return 1
				;;
		esac
	else
		# Enumerate all meta files
		local _meta_file
		for _meta_file in "$sessdir"/scan.meta.*; do
			[ -f "$_meta_file" ] || continue
			_scanid="${_meta_file##*scan.meta.}"
			# Skip .tmp files
			case "$_scanid" in
				*.tmp) continue ;;
			esac
			_state=$(_lifecycle_detect_state "$_scanid" 2>/dev/null) || continue  # safe: skip meta files that fail to parse
			case "$_state" in
				running|paused|stale)
					if [ -z "$_active_ids" ]; then
						_active_ids="$_scanid"
					else
						_active_ids="$_active_ids"$'\n'"$_scanid"
					fi
					_found=1
					;;
			esac
		done
	fi

	if [ "$_found" -eq 0 ]; then
		echo "No active scans." >&2
		return 1
	fi

	case "$_format" in
		json) _lifecycle_render_json_active "$_active_ids" ;;
		tsv)  _lifecycle_render_tsv_active "$_active_ids" ;;
		*)    _lifecycle_render_text_active "$_verbose" "$_active_ids" ;;
	esac
}

##
# _lifecycle_render_text_active(verbose, scanids_newline_separated)
#   Text format for terminal. Columnar output with optional verbose mode.
##
_lifecycle_render_text_active() {
	local _verbose="$1" _ids="$2"
	local _scanid _state _elapsed_str
	local _count=0
	[ -n "$_ids" ] && _count=$(printf '%s\n' "$_ids" | command grep -c '^.' || echo 0)

	printf 'Active scans (%s):\n' "$_count"
	if [ "$_verbose" = "1" ]; then
		printf '  %-22s %-10s %-7s %-8s %-10s %-6s %-10s %-8s %-12s %-12s %s\n' \
			"SCANID" "STATE" "PID" "ENGINE" "FILES" "HITS" "ELAPSED" "WORKERS" "SIG_VER" "PROGRESS" "PATH"
	else
		printf '  %-22s %-10s %-7s %-8s %-10s %-6s %-10s %s\n' \
			"SCANID" "STATE" "PID" "ENGINE" "FILES" "HITS" "ELAPSED" "PATH"
	fi

	while IFS= read -r _scanid; do
		[ -z "$_scanid" ] && continue
		_state=$(_lifecycle_detect_state "$_scanid" 2>/dev/null) || continue  # safe: skip unreadable meta
		_lifecycle_read_meta "$_scanid" || continue

		_elapsed_str=$(_lifecycle_format_elapsed "${_meta_elapsed:-0}")

		if [ "$_verbose" = "1" ]; then
			local _progress_str="-"
			if [ -n "$_meta_progress_pos" ] && [ -n "$_meta_progress_total" ] && \
			   [ "$_meta_progress_total" != "0" ] && [ "$_meta_progress_total" != "-" ]; then
				_progress_str="${_meta_progress_pos}/${_meta_progress_total}"
			fi
			printf '  %-22s %-10s %-7s %-8s %-10s %-6s %-10s %-8s %-12s %-12s %s\n' \
				"$_scanid" "$_state" "${_meta_pid:-?}" \
				"${_meta_engine:--}" "${_meta_total_files:--}" "${_meta_hits:-0}" \
				"$_elapsed_str" "${_meta_workers:--}" "${_meta_sig_version:--}" "$_progress_str" \
				"${_meta_path:--}"
		else
			printf '  %-22s %-10s %-7s %-8s %-10s %-6s %-10s %s\n' \
				"$_scanid" "$_state" "${_meta_pid:-?}" \
				"${_meta_engine:--}" "${_meta_total_files:--}" "${_meta_hits:-0}" \
				"$_elapsed_str" "${_meta_path:--}"
		fi
	done <<< "$_ids"

	return 0
}

##
# _lifecycle_render_json_active(scanids_newline_separated)
#   JSON array output. Build manually with printf (no jq dependency).
#   Integers are unquoted. Strings are JSON-escaped.
##
_lifecycle_render_json_active() {
	local _ids="$1"
	local _scanid _state _first=1

	printf '{\n  "active_scans": [\n'

	while IFS= read -r _scanid; do
		[ -z "$_scanid" ] && continue
		_state=$(_lifecycle_detect_state "$_scanid" 2>/dev/null) || continue  # safe: skip unreadable meta
		_lifecycle_read_meta "$_scanid" || continue

		if [ "$_first" -eq 1 ]; then
			_first=0
		else
			printf ',\n'
		fi

		# JSON-escape strings (backslash and double-quote)
		local _j_path="${_meta_path//\\/\\\\}"
		_j_path="${_j_path//\"/\\\"}"

		local _j_stages="${_meta_stages//\\/\\\\}"
		_j_stages="${_j_stages//\"/\\\"}"

		local _j_sig="${_meta_sig_version//\\/\\\\}"
		_j_sig="${_j_sig//\"/\\\"}"

		# Ensure integer fields default to 0
		local _i_pid="${_meta_pid:-0}"
		local _i_total="${_meta_total_files:-0}"
		local _i_hits="${_meta_hits:-0}"
		local _i_elapsed="${_meta_elapsed:-0}"
		local _i_workers="${_meta_workers:-0}"
		local _i_prog_pos="${_meta_progress_pos:-0}"
		local _i_prog_total="${_meta_progress_total:-0}"

		# Replace "-" sentinels with 0 for integer fields
		[ "$_i_pid" = "-" ] && _i_pid=0
		[ "$_i_total" = "-" ] && _i_total=0
		[ "$_i_hits" = "-" ] && _i_hits=0
		[ "$_i_elapsed" = "-" ] && _i_elapsed=0
		[ "$_i_workers" = "-" ] && _i_workers=0
		[ "$_i_prog_pos" = "-" ] && _i_prog_pos=0
		[ "$_i_prog_total" = "-" ] && _i_prog_total=0

		printf '    {\n'
		printf '      "scanid": "%s",\n' "$_scanid"
		printf '      "state": "%s",\n' "$_state"
		printf '      "pid": %s,\n' "$_i_pid"
		printf '      "path": "%s",\n' "$_j_path"
		printf '      "engine": "%s",\n' "${_meta_engine:--}"
		printf '      "total_files": %s,\n' "$_i_total"
		printf '      "hits": %s,\n' "$_i_hits"
		printf '      "elapsed": %s,\n' "$_i_elapsed"
		printf '      "workers": %s,\n' "$_i_workers"
		printf '      "stages": "%s",\n' "$_j_stages"
		printf '      "sig_version": "%s",\n' "$_j_sig"
		printf '      "progress": {\n'
		printf '        "position": %s,\n' "$_i_prog_pos"
		printf '        "total": %s\n' "$_i_prog_total"
		printf '      }\n'
		printf '    }'
	done <<< "$_ids"

	printf '\n  ]\n}\n'

	return 0
}

##
# _lifecycle_render_tsv_active(scanids_newline_separated)
#   TSV format with #LMD_SCANLIST:v1 header. Tab-separated fields.
##
_lifecycle_render_tsv_active() {
	local _ids="$1"
	local _scanid _state

	printf '#LMD_SCANLIST:v1\n'
	printf 'scanid\tstate\tpid\tpath\tengine\ttotal_files\thits\telapsed\n'

	while IFS= read -r _scanid; do
		[ -z "$_scanid" ] && continue
		_state=$(_lifecycle_detect_state "$_scanid" 2>/dev/null) || continue  # safe: skip unreadable meta
		_lifecycle_read_meta "$_scanid" || continue

		printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
			"$_scanid" "$_state" "${_meta_pid:--}" "${_meta_path:--}" \
			"${_meta_engine:--}" "${_meta_total_files:--}" "${_meta_hits:-0}" \
			"${_meta_elapsed:-0}"
	done <<< "$_ids"

	return 0
}

##
# _session_index_append(scanid, epoch, started_hr, elapsed, total_files, total_hits, total_cleaned, path)
#   Appends a tab-delimited record to $sessdir/session.index.
#   Creates file with #LMD_INDEX:v1 header if missing.
#   Lines are < 200 bytes (under PIPE_BUF for atomic append on all POSIX systems).
##
_session_index_append() {
	local _scanid="$1" _epoch="$2" _started_hr="$3" _elapsed="$4"
	local _total_files="$5" _total_hits="$6" _total_cleaned="$7" _path="$8"
	local _index_file="$sessdir/session.index"

	# Create with header if missing
	if [ ! -f "$_index_file" ]; then
		printf '#LMD_INDEX:v1\n' > "$_index_file"
	fi

	# Atomic append (< PIPE_BUF)
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"$_scanid" "$_epoch" "$_started_hr" "$_elapsed" \
		"$_total_files" "$_total_hits" "$_total_cleaned" "$_path" >> "$_index_file"
}

##
# _session_index_rebuild()
#   Full rebuild of session.index from session.tsv.* files.
#   Flock-gated to prevent concurrent rebuilds. Writes to .tmp, mv atomically.
##
_session_index_rebuild() {
	local _index_file="$sessdir/session.index"
	local _tmp_file="$_index_file.tmp"
	local _tsv_file _rid
	local _r_scanid _r_started_hr _r_elapsed _r_tot_files _r_tot_hits _r_tot_cl _r_path _r_epoch
	# Throwaway variables for TSV fields we do not use
	local _r_fmt _r_alert_type _r_hostname _r_days _r_end_hr _r_fl_et
	local _r_scanner_ver _r_sig_ver _r_hashtype _r_engine _r_quar _r_hostid

	# Flock to prevent concurrent rebuilds
	(
		if command -v flock >/dev/null 2>&1; then  # flock not available on FreeBSD
			flock -n 200 || return 0  # another rebuild running, skip
		fi

		printf '#LMD_INDEX:v1\n' > "$_tmp_file"

		for _tsv_file in "$sessdir"/session.tsv.[0-9]*; do
			[ -f "$_tsv_file" ] || continue
			_rid="${_tsv_file##*.tsv.}"
			# Read metadata from TSV header (first line, 19 tab-separated fields)
			IFS=$'\t' read -r _r_fmt _r_alert_type _r_scanid _r_hostname _r_path _r_days \
				_r_started_hr _r_end_hr _r_elapsed _r_fl_et \
				_r_tot_files _r_tot_hits _r_tot_cl \
				_r_scanner_ver _r_sig_ver _r_hashtype _r_engine _r_quar _r_hostid \
				< "$_tsv_file"
			[ -z "$_r_scanid" ] && continue
			# Compute epoch from started_hr; fall back to file mtime
			_r_epoch=$(command date -d "$_r_started_hr" "+%s" 2>/dev/null) || _r_epoch=0  # safe: date parse failure falls back to 0
			printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
				"$_r_scanid" "$_r_epoch" "$_r_started_hr" "${_r_elapsed:--}" \
				"${_r_tot_files:--}" "${_r_tot_hits:--}" "${_r_tot_cl:--}" "${_r_path:--}" \
				>> "$_tmp_file"
		done

		command mv -f "$_tmp_file" "$_index_file"
	) 200>"$_index_file.lock"
}

##
# _lifecycle_check_parent(ppid)
#   Workers call this to verify the parent scan process is still alive.
#   Uses kill -0 which works on FreeBSD (no /proc dependency).
#   Returns: 0=parent alive, 1=parent dead (orphaned worker)
##
_lifecycle_check_parent() {
	local ppid="$1"
	if kill -0 "$ppid" 2>/dev/null; then  # EPERM on other-user pid is still alive
		return 0
	fi
	return 1
}

##
# _lifecycle_kill(scanid)
#   Kill a running or paused scan.  Algorithm:
#     1. Read meta, validate state is running/paused/stale (E9)
#     2. Write abort sentinel
#     3. If paused: SIGCONT then SIGTERM; else SIGTERM
#     4. Wait up to 30s, SIGKILL fallback
#     5. Clean scan-scoped temp + sentinel files
#     6. Update meta state=killed
#   For daemon ClamAV (clamdscan), do NOT send SIGSTOP/SIGCONT — only
#   the abort sentinel approach works (E16).
##
_lifecycle_kill() {
	local _scanid="$1"
	local _state _is_paused=0

	# Validate meta exists
	_lifecycle_read_meta "$_scanid" || {
		echo "maldet($$): {lifecycle} scan $_scanid not found" >&2
		return 1
	}

	# Detect live state (handles stale detection)
	_state=$(_lifecycle_detect_state "$_scanid" 2>/dev/null) || {  # safe: detect_state only fails on missing meta
		echo "maldet($$): {lifecycle} scan $_scanid not found" >&2
		return 1
	}

	# Reject terminal states (E9)
	case "$_state" in
		completed)
			echo "maldet($$): {lifecycle} scan $_scanid already completed" >&2
			return 1
			;;
		killed)
			echo "maldet($$): {lifecycle} scan $_scanid already killed" >&2
			return 1
			;;
	esac

	if [ "$_state" = "paused" ]; then
		_is_paused=1
	fi

	# Write abort sentinel (E2: ENOSPC fallback below)
	if ! printf 'abort\n' > "$tmpdir/.abort.$_scanid" 2>/dev/null; then  # safe: suppress ENOSPC/EACCES — fallback below
		# ENOSPC — sentinel write failed, fall through to direct SIGTERM
		eout "{lifecycle} warning: could not write abort sentinel (disk full?), sending direct SIGTERM" 1
	fi

	local _pid="$_meta_pid"

	# If process is still alive, send signals
	if kill -0 "$_pid" 2>/dev/null; then  # safe: returns false if PID dead
		# If paused: SIGCONT first to un-pause (E15), then SIGTERM
		# Skip SIGCONT for daemon ClamAV — sentinel-only approach (E16)
		if [ "$_is_paused" -eq 1 ] && [ "$_meta_engine" != "clamdscan" ]; then
			kill -CONT "$_pid" 2>/dev/null  # safe: process may have exited between check and signal
		fi

		kill -TERM "$_pid" 2>/dev/null  # safe: process may have exited

		# Wait up to 30s for PID to exit
		local _waited=0
		while [ "$_waited" -lt 30 ]; do
			if ! kill -0 "$_pid" 2>/dev/null; then  # safe: checking liveness
				break
			fi
			command sleep 1
			_waited=$((_waited + 1))
		done

		# SIGKILL fallback if still alive
		if kill -0 "$_pid" 2>/dev/null; then  # safe: checking liveness
			kill -KILL "$_pid" 2>/dev/null  # safe: last resort
			# Brief wait for SIGKILL to take effect
			command sleep 1
		fi
	fi

	# Clean scan-scoped temp files: runtime sigs, sentinels
	command rm -f "$tmpdir"/.runtime.*."$_scanid".* \
		"$tmpdir/.abort.$_scanid" \
		"$tmpdir/.pause.$_scanid" \
		2>/dev/null  # safe: files may not exist

	# Update meta to killed state
	_lifecycle_update_meta "$_scanid" "state" "killed"

	eout "{lifecycle} scan $_scanid killed" 1

	return 0
}

##
# _lifecycle_orphan_sweep()
#   Enumerate all scan.meta.* in $sessdir, detect stale (PID dead but
#   state=running), mark state=stale.  Log each stale scan found.
##
_lifecycle_orphan_sweep() {
	local _meta_file _scanid _state

	for _meta_file in "$sessdir"/scan.meta.*; do
		[ -f "$_meta_file" ] || continue
		_scanid="${_meta_file##*scan.meta.}"
		# Skip .tmp files
		case "$_scanid" in
			*.tmp) continue ;;
		esac
		_state=$(_lifecycle_detect_state "$_scanid" 2>/dev/null) || continue  # safe: skip unparseable metas
		if [ "$_state" = "stale" ]; then
			# Read meta in caller scope to populate _meta_pid for log message
			_lifecycle_read_meta "$_scanid" || continue
			_lifecycle_update_meta "$_scanid" "state" "stale"
			eout "{lifecycle} orphan sweep: scan $_scanid marked stale (process $_meta_pid dead)" 1
			# Clean orphaned PID-scoped and scanid-scoped temp files
			local _stale_pid="$_meta_pid"
			command rm -f \
				"$tmpdir"/.hcb."$_stale_pid".* \
				"$tmpdir"/.hex_worker."$_stale_pid".* "$tmpdir"/.hex_chunk."$_stale_pid".* \
				"$tmpdir"/.md5_worker."$_stale_pid".* "$tmpdir"/.md5_chunk."$_stale_pid".* \
				"$tmpdir"/.sha256_worker."$_stale_pid".* "$tmpdir"/.sha256_chunk."$_stale_pid".* \
				"$tmpdir"/.runtime.*."$_scanid".* \
				2>/dev/null  # safe: files may not exist
			command rm -f \
				"$tmpdir/.abort.$_scanid" "$tmpdir/.pause.$_scanid" \
				"$tmpdir/.clamscan_pid.$_scanid" "$tmpdir/.yara_pid.$_scanid" \
				2>/dev/null  # safe: sentinels may not exist
			command rm -rf \
				"$tmpdir"/.md5_progress."$_stale_pid".* \
				"$tmpdir"/.sha256_progress."$_stale_pid".* \
				"$tmpdir"/.hex_progress."$_stale_pid".* \
				2>/dev/null  # safe: dirs may not exist
		fi
	done

	return 0
}

##
# _lifecycle_duplicate_guard(path)
#   Check running/paused metas for same path field.
#   E7: exact match only (overlapping paths allowed).
#   Returns 1 on conflict with error message to stderr.
##
_lifecycle_duplicate_guard() {
	local _check_path="$1"
	local _meta_file _scanid _state

	for _meta_file in "$sessdir"/scan.meta.*; do
		[ -f "$_meta_file" ] || continue
		_scanid="${_meta_file##*scan.meta.}"
		case "$_scanid" in
			*.tmp) continue ;;
		esac
		_state=$(_lifecycle_detect_state "$_scanid" 2>/dev/null) || continue  # safe: skip unparseable metas
		case "$_state" in
			running|paused)
				_lifecycle_read_meta "$_scanid" || continue
				if [ "$_meta_path" = "$_check_path" ]; then
					echo "maldet($$): {lifecycle} duplicate scan rejected: $_check_path already being scanned by $_scanid" >&2
					return 1
				fi
				;;
		esac
	done

	return 0
}

##
# _lifecycle_cleanup_stale_metas()
#   Remove completed/killed/stale meta files older than
#   $scan_meta_cleanup_age hours.  Uses find with -mmin.
#   Skip active/paused/stopped metas.  Disabled when age=0.
##
_lifecycle_cleanup_stale_metas() {
	local _age_hours="${scan_meta_cleanup_age:-24}"
	local _age_minutes _meta_file _scanid _state

	# Disabled when age=0
	[ "$_age_hours" = "0" ] && return 0

	_age_minutes=$((_age_hours * 60))

	for _meta_file in "$sessdir"/scan.meta.*; do
		[ -f "$_meta_file" ] || continue
		_scanid="${_meta_file##*scan.meta.}"
		case "$_scanid" in
			*.tmp) continue ;;
		esac
		_state=$(_lifecycle_detect_state "$_scanid" 2>/dev/null) || continue  # safe: skip unparseable metas
		case "$_state" in
			completed|killed|stale)
				# Check age via find -mmin
				if [ -n "$($find "$_meta_file" -maxdepth 0 -mmin +"$_age_minutes" 2>/dev/null)" ]; then  # safe: find may warn on race-deleted files
					command rm -f "$_meta_file"
					eout "{lifecycle} cleanup: removed stale meta for scan $_scanid" 1
				fi
				;;
		esac
	done

	return 0
}

##
# _rotate_history(filepath, threshold_bytes)
#   Cascade rotation: .2.gz→.3.gz, .1.gz→.2.gz; gzip active→.1.gz;
#   truncate active (inode preserved via :> redirect).
#   Only rotates if file exceeds threshold_bytes.
#   Returns 0 on success or skip (file missing/below threshold).
##
_rotate_history() {
	local _filepath="$1" _threshold="$2"
	local _filesize

	# Skip if file does not exist
	[ -f "$_filepath" ] || return 0

	# Check size — skip if below threshold
	_filesize=$(command wc -c < "$_filepath")
	[ "$_filesize" -le "$_threshold" ] && return 0

	# Cascade existing rotations: .2.gz → .3.gz
	if [ -f "$_filepath.2.gz" ]; then
		command mv -f "$_filepath.2.gz" "$_filepath.3.gz"
	fi

	# .1.gz → .2.gz
	if [ -f "$_filepath.1.gz" ]; then
		command mv -f "$_filepath.1.gz" "$_filepath.2.gz"
	fi

	# Gzip active → .1.gz (write to .tmp first for atomicity)
	command gzip -c "$_filepath" > "$_filepath.1.gz.tmp"
	command mv -f "$_filepath.1.gz.tmp" "$_filepath.1.gz"

	# Truncate active file — preserves inode
	:> "$_filepath"

	return 0
}

##
# _rotate_histories()
#   Rotate standard history files: hits.hist, quarantine.hist,
#   monitor.scanned.hist, inotify_log. After rotation, adjust
#   tlog cursors for files that have inotify cursors. Uses
#   threshold of 1MB (1048576 bytes).
##
_rotate_histories() {
	local _threshold=1048576
	local _file _rotated=0
	local _pre_size _post_size _delta

	# List of history files to rotate
	local _hist_files
	_hist_files="$quardir/hits.hist
$quardir/quarantine.hist
$quardir/monitor.scanned.hist
$inotify_log"

	while IFS= read -r _file; do
		[ -z "$_file" ] && continue
		[ -f "$_file" ] || continue

		# Capture pre-rotation size for cursor adjustment
		_pre_size=$(command wc -c < "$_file")

		_rotate_history "$_file" "$_threshold"

		# If file was rotated (now empty/smaller), adjust tlog cursor
		_post_size=$(command wc -c < "$_file")
		if [ "$_post_size" -lt "$_pre_size" ]; then
			_delta=$((_pre_size - _post_size))
			# Only inotify_log has a tlog cursor — use "inotify" name
			if [ "$_file" = "$inotify_log" ]; then
				tlog_adjust_cursor "inotify" "$tmpdir" "$_delta"
			fi
			_rotated=$((_rotated + 1))
			eout "{lifecycle} rotated history: $_file (${_pre_size} bytes)" 1
		fi
	done <<< "$_hist_files"

	if [ "$_rotated" -gt 0 ]; then
		eout "{lifecycle} rotated $_rotated history file(s)" 1
	fi

	return 0
}

##
# _session_compress(scanid)
#   Gzip $sessdir/session.tsv.$scanid if it exists and is not already
#   compressed. Creates .gz via atomic .tmp write, then removes original.
#   Returns 1 if session file does not exist (and no .gz either).
##
_session_compress() {
	local _scanid="$1"
	local _tsv_file="$sessdir/session.tsv.$_scanid"

	# Already compressed — nothing to do
	if [ -f "$_tsv_file.gz" ] && [ ! -f "$_tsv_file" ]; then
		return 0
	fi

	# No session file at all
	[ -f "$_tsv_file" ] || return 1

	# Compress: write to .tmp for atomicity
	command gzip -c "$_tsv_file" > "$_tsv_file.gz.tmp"
	command mv -f "$_tsv_file.gz.tmp" "$_tsv_file.gz"
	command rm -f "$_tsv_file"
}

##
# _lifecycle_pause(scanid, duration)
#   Pause a running scan.  Algorithm:
#     1. Read meta, validate state is running (not completed/killed/stopped/paused)
#     2. Daemon gate: clamdscan cannot be paused (E16)
#     3. Parse duration (optional): Ns/Nm/Nh or bare seconds; 0/empty = indefinite
#     4. Write pause sentinel with epoch + duration
#     5. SIGSTOP external processes (clamscan/yara PIDs) if PID files exist
#     6. Update meta state=paused
##
_lifecycle_pause() {
	local _scanid="$1"
	local _duration_arg="${2:-}"
	local _state _duration_secs=0 _epoch _dur_msg=""

	# Validate meta exists
	_lifecycle_read_meta "$_scanid" || {
		echo "maldet($$): {lifecycle} scan $_scanid not found" >&2
		return 1
	}

	# Detect live state
	_state=$(_lifecycle_detect_state "$_scanid" 2>/dev/null) || {  # safe: detect_state only fails on missing meta
		echo "maldet($$): {lifecycle} scan $_scanid not found" >&2
		return 1
	}

	# Reject terminal and non-running states
	case "$_state" in
		completed|killed|stopped)
			echo "maldet($$): {lifecycle} cannot pause scan $_scanid (state: $_state)" >&2
			return 1
			;;
		paused)
			echo "maldet($$): {lifecycle} scan $_scanid already paused" >&2
			return 1
			;;
		stale)
			echo "maldet($$): {lifecycle} cannot pause scan $_scanid (state: stale — process dead)" >&2
			return 1
			;;
	esac

	# Daemon gate (E16): clamdscan cannot be paused
	if [ "$_meta_engine" = "clamdscan" ]; then
		echo "maldet($$): {lifecycle} cannot pause daemon ClamAV scans (clamdscan) — use --kill to abort" >&2
		return 1
	fi

	# Parse duration if provided
	if [ -n "$_duration_arg" ]; then
		local _num _suffix
		_suffix="${_duration_arg: -1}"
		case "$_suffix" in
			s)
				_num="${_duration_arg%s}"
				;;
			m)
				_num="${_duration_arg%m}"
				;;
			h)
				_num="${_duration_arg%h}"
				;;
			[0-9])
				# Bare numeric — treat as seconds
				_num="$_duration_arg"
				_suffix="s"
				;;
			*)
				echo "maldet($$): {lifecycle} invalid duration format: $_duration_arg (use Ns, Nm, Nh, or bare seconds)" >&2
				return 1
				;;
		esac

		# Validate numeric part
		if ! [[ "$_num" =~ ^[0-9]+$ ]] || [ -z "$_num" ]; then
			echo "maldet($$): {lifecycle} invalid duration format: $_duration_arg (numeric part required)" >&2
			return 1
		fi

		# Convert to seconds
		case "$_suffix" in
			s) _duration_secs="$_num" ;;
			m) _duration_secs=$((_num * 60)) ;;
			h) _duration_secs=$((_num * 3600)) ;;
		esac
	fi

	# Get current epoch
	_epoch=$(command date +%s)

	# Write pause sentinel with epoch and duration
	printf 'epoch=%s\nduration=%s\n' "$_epoch" "$_duration_secs" > "$tmpdir/.pause.$_scanid"

	# SIGSTOP external processes if PID files exist
	local _ext_pid
	if [ -f "$tmpdir/.clamscan_pid.$_scanid" ]; then
		IFS= read -r _ext_pid < "$tmpdir/.clamscan_pid.$_scanid"
		if [ -n "$_ext_pid" ] && kill -0 "$_ext_pid" 2>/dev/null; then  # safe: PID may have exited
			kill -STOP "$_ext_pid" 2>/dev/null  # safe: race between check and signal
		fi
	fi
	if [ -f "$tmpdir/.yara_pid.$_scanid" ]; then
		IFS= read -r _ext_pid < "$tmpdir/.yara_pid.$_scanid"
		if [ -n "$_ext_pid" ] && kill -0 "$_ext_pid" 2>/dev/null; then  # safe: PID may have exited
			kill -STOP "$_ext_pid" 2>/dev/null  # safe: race between check and signal
		fi
	fi

	# Update meta state
	_lifecycle_update_meta "$_scanid" "state" "paused"

	# Build duration message for log
	if [ "$_duration_secs" -gt 0 ]; then
		_dur_msg=" for ${_duration_arg}"
	fi

	eout "{lifecycle} scan $_scanid paused${_dur_msg}" 1

	return 0
}

##
# _session_resolve_compressed(scanid)
#   Check $sessdir/session.tsv.$scanid.gz first, then monthly archive.
#   Outputs resolved path to stdout.  Returns 1 if not found.
##
_session_resolve_compressed() {
	local _scanid="$1"

	# Per-session .gz takes priority
	if [ -f "$sessdir/session.tsv.$_scanid.gz" ]; then
		echo "$sessdir/session.tsv.$_scanid.gz"
		return 0
	fi

	# Check monthly archive: extract YYMM from scanid (format YYMMDD-HHMM.PID)
	local _yymm
	_yymm="${_scanid:0:4}"
	if [ -f "$sessdir/session.archive.$_yymm.tsv.gz" ]; then
		echo "$sessdir/session.archive.$_yymm.tsv.gz"
		return 0
	fi

	return 1
}

##
# _lifecycle_unpause(scanid)
#   Unpause a paused scan.  Algorithm:
#     1. Validate state is paused
#     2. SIGCONT external processes (clamscan/yara PIDs) if PID files exist
#     3. Remove pause sentinel
#     4. Update meta state=running
##
_lifecycle_unpause() {
	local _scanid="$1"
	local _state

	# Validate meta exists
	_lifecycle_read_meta "$_scanid" || {
		echo "maldet($$): {lifecycle} scan $_scanid not found" >&2
		return 1
	}

	# Detect live state
	_state=$(_lifecycle_detect_state "$_scanid" 2>/dev/null) || {  # safe: detect_state only fails on missing meta
		echo "maldet($$): {lifecycle} scan $_scanid not found" >&2
		return 1
	}

	# Validate paused state
	if [ "$_state" != "paused" ]; then
		echo "maldet($$): {lifecycle} scan $_scanid not paused (state: $_state)" >&2
		return 1
	fi

	# SIGCONT external processes if PID files exist
	local _ext_pid
	if [ -f "$tmpdir/.clamscan_pid.$_scanid" ]; then
		IFS= read -r _ext_pid < "$tmpdir/.clamscan_pid.$_scanid"
		if [ -n "$_ext_pid" ] && kill -0 "$_ext_pid" 2>/dev/null; then  # safe: PID may have exited
			kill -CONT "$_ext_pid" 2>/dev/null  # safe: race between check and signal
		fi
	fi
	if [ -f "$tmpdir/.yara_pid.$_scanid" ]; then
		IFS= read -r _ext_pid < "$tmpdir/.yara_pid.$_scanid"
		if [ -n "$_ext_pid" ] && kill -0 "$_ext_pid" 2>/dev/null; then  # safe: PID may have exited
			kill -CONT "$_ext_pid" 2>/dev/null  # safe: race between check and signal
		fi
	fi

	# Remove pause sentinel
	command rm -f "$tmpdir/.pause.$_scanid"

	# Update meta state
	_lifecycle_update_meta "$_scanid" "state" "running"

	eout "{lifecycle} scan $_scanid unpaused" 1

	return 0
}

##
# _session_archive_month(YYMM)
#   Concatenate matching session.tsv.$YYMM* files (both plain and .gz)
#   into a single monthly archive $sessdir/session.archive.$YYMM.tsv.gz.
#   Removes originals after successful archiving.
#   Returns 0 on success or when no matching files are found.
##
_session_archive_month() {
	local _yymm="$1"
	local _tmp_concat _tmp_gz _final_archive
	local _file _count=0

	_final_archive="$sessdir/session.archive.$_yymm.tsv.gz"

	# Collect matching files — both plain and .gz
	# Use a temp file to accumulate content (avoids memory issues on large sets)
	_tmp_concat=$(command mktemp "$tmpdir/.archive_concat.XXXXXX")

	# Pass 1: plain TSV session files matching YYMM prefix
	for _file in "$sessdir"/session.tsv."$_yymm"*; do
		[ -f "$_file" ] || continue
		# Skip .gz files (handled in pass 2)
		case "$_file" in *.gz) continue ;; esac
		# Skip monthly archive files themselves
		case "$_file" in *session.archive.*) continue ;; esac
		command cat "$_file" >> "$_tmp_concat"
		_count=$((_count + 1))
	done

	# Pass 2: compressed .gz session files matching YYMM prefix
	for _file in "$sessdir"/session.tsv."$_yymm"*.gz; do
		[ -f "$_file" ] || continue
		# Skip monthly archive files themselves
		case "$_file" in *session.archive.*) continue ;; esac
		command gzip -dc "$_file" >> "$_tmp_concat"
		_count=$((_count + 1))
	done

	# Nothing to archive
	if [ "$_count" -eq 0 ]; then
		command rm -f "$_tmp_concat"
		return 0
	fi

	# Gzip concatenated content to temp, then atomic move
	_tmp_gz="$_final_archive.tmp"
	command gzip -c "$_tmp_concat" > "$_tmp_gz"
	command mv -f "$_tmp_gz" "$_final_archive"
	command rm -f "$_tmp_concat"

	# Remove originals only after successful archive creation
	for _file in "$sessdir"/session.tsv."$_yymm"*; do
		[ -f "$_file" ] || continue
		# Do not remove the archive we just created
		case "$_file" in *session.archive.*) continue ;; esac
		command rm -f "$_file"
	done

	eout "{lifecycle} archived $_count sessions for month $_yymm" 1

	return 0
}

##
# _lifecycle_stop(scanid)
#   Stop a running or paused scan with a stage-granularity checkpoint.
#   Algorithm:
#     1. Read meta, validate state is running or paused
#     2. Daemon gate: clamdscan cannot be checkpointed
#     3. Write abort sentinel (workers check this at stage boundaries)
#     4. If paused: SIGCONT first to un-freeze, then wait for PID exit
#     5. Wait up to 30s for PID to exit, SIGKILL fallback
#     6. Write checkpoint atomically (.tmp -> mv)
#     7. Update meta state=stopped
#     8. Clean abort/pause sentinels (but NOT session hits)
##
_lifecycle_stop() {
	local _scanid="$1"
	local _state _is_paused=0

	# Validate meta exists
	_lifecycle_read_meta "$_scanid" || {
		echo "maldet($$): {lifecycle} scan $_scanid not found" >&2
		return 1
	}

	# Detect live state (handles stale detection)
	_state=$(_lifecycle_detect_state "$_scanid" 2>/dev/null) || {  # safe: detect_state only fails on missing meta
		echo "maldet($$): {lifecycle} scan $_scanid not found" >&2
		return 1
	}

	# Reject terminal states
	case "$_state" in
		completed|killed)
			echo "maldet($$): {lifecycle} scan $_scanid not running (state: $_state)" >&2
			return 1
			;;
		stopped)
			echo "maldet($$): {lifecycle} scan $_scanid already stopped" >&2
			return 1
			;;
		stale)
			# Stale = PID dead but not terminal — treat as stoppable (just write checkpoint)
			;;
	esac

	if [ "$_state" = "paused" ]; then
		_is_paused=1
	fi

	# Daemon gate: clamdscan cannot be checkpointed (no stage granularity)
	if [ "$_meta_engine" = "clamdscan" ]; then
		echo "maldet($$): {lifecycle} cannot checkpoint daemon ClamAV scans (clamdscan) — use --kill to abort" >&2
		return 1
	fi

	# Write abort sentinel (E2: workers check at stage boundaries)
	if ! printf 'stop\n' > "$tmpdir/.abort.$_scanid" 2>/dev/null; then  # safe: suppress ENOSPC/EACCES — fallback below
		eout "{lifecycle} warning: could not write abort sentinel (disk full?), sending direct SIGTERM" 1
	fi

	local _pid="$_meta_pid"

	# If process is still alive, send signals
	if kill -0 "$_pid" 2>/dev/null; then  # safe: returns false if PID dead
		# If paused: SIGCONT first to un-freeze (E15), then SIGTERM
		if [ "$_is_paused" -eq 1 ]; then
			kill -CONT "$_pid" 2>/dev/null  # safe: process may have exited between check and signal
			# Also SIGCONT external processes
			local _ext_pid
			if [ -f "$tmpdir/.clamscan_pid.$_scanid" ]; then
				IFS= read -r _ext_pid < "$tmpdir/.clamscan_pid.$_scanid"
				if [ -n "$_ext_pid" ] && kill -0 "$_ext_pid" 2>/dev/null; then  # safe: PID may have exited
					kill -CONT "$_ext_pid" 2>/dev/null  # safe: race between check and signal
				fi
			fi
			if [ -f "$tmpdir/.yara_pid.$_scanid" ]; then
				IFS= read -r _ext_pid < "$tmpdir/.yara_pid.$_scanid"
				if [ -n "$_ext_pid" ] && kill -0 "$_ext_pid" 2>/dev/null; then  # safe: PID may have exited
					kill -CONT "$_ext_pid" 2>/dev/null  # safe: race between check and signal
				fi
			fi
		fi

		kill -TERM "$_pid" 2>/dev/null  # safe: process may have exited

		# Wait up to 30s for PID to exit
		local _waited=0
		while [ "$_waited" -lt 30 ]; do
			if ! kill -0 "$_pid" 2>/dev/null; then  # safe: checking liveness
				break
			fi
			command sleep 1
			_waited=$((_waited + 1))
		done

		# SIGKILL fallback if still alive
		if kill -0 "$_pid" 2>/dev/null; then  # safe: checking liveness
			kill -KILL "$_pid" 2>/dev/null  # safe: last resort
			command sleep 1
		fi
	fi

	# Read current stage and hits from meta (may have been updated during scan)
	_lifecycle_read_meta "$_scanid" || true  # safe: re-read for latest stage/hits values

	local _ckpt_stage="${_meta_stage:-unknown}"
	local _ckpt_hits="${_meta_hits:-0}"
	[ "$_ckpt_hits" = "-" ] && _ckpt_hits=0
	local _ckpt_workers="${_meta_workers:-1}"
	local _ckpt_total="${_meta_total_files:-0}"
	local _ckpt_options="${_meta_options:-}"

	# Read sig version from on-disk file
	local _ckpt_sig_ver
	if [ -f "$sigdir/maldet.sigs.ver" ]; then
		IFS= read -r _ckpt_sig_ver < "$sigdir/maldet.sigs.ver"
	else
		_ckpt_sig_ver="unknown"
	fi
	[ -z "$_ckpt_sig_ver" ] && _ckpt_sig_ver="unknown"

	# Timestamps
	local _stopped _stopped_hr
	_stopped=$(command date +%s)
	_stopped_hr=$(command date "+%b %d %Y %H:%M:%S %z")

	# Write checkpoint atomically (.tmp -> mv)
	local _ckpt_file="$sessdir/scan.checkpoint.$_scanid"
	local _ckpt_tmp="$_ckpt_file.tmp"

	command cat > "$_ckpt_tmp" <<EOF
#LMD_CHECKPOINT:v1
scanid=$_scanid
stopped=$_stopped
stopped_hr=$_stopped_hr
stage=$_ckpt_stage
sig_version=$_ckpt_sig_ver
workers=$_ckpt_workers
total_files=$_ckpt_total
hits_so_far=$_ckpt_hits
options=$_ckpt_options
EOF

	command mv -f "$_ckpt_tmp" "$_ckpt_file"

	# Update meta to stopped state
	_lifecycle_update_meta "$_scanid" "state" "stopped"
	_lifecycle_update_meta "$_scanid" "stopped" "$_stopped"
	_lifecycle_update_meta "$_scanid" "stopped_hr" "$_stopped_hr"

	# Clean sentinels but NOT session data (session.hits preserved for continue)
	command rm -f "$tmpdir/.abort.$_scanid" \
		"$tmpdir/.pause.$_scanid" \
		2>/dev/null  # safe: files may not exist

	eout "{lifecycle} scan $_scanid stopped at stage $_ckpt_stage" 1

	return 0
}

##
# _lifecycle_continue(scanid)
#   Resume a stopped scan from its checkpoint.
#   Algorithm:
#     1. Read and validate checkpoint file (#LMD_CHECKPOINT:v1 header)
#     2. Compare sig_version with current — warn if different
#     3. Parse checkpoint options, apply as config overrides
#     4. Check for paused state (reject with hint to use --unpause)
#     5. Report stage skip and sig drift info
#   Note: Full scan resumption (gensigs, filelist rebuild, stage skip) requires
#   integration with the scan() function. This function validates the checkpoint
#   and prepares the environment; the dispatcher integrates with scan orchestration.
##
_lifecycle_continue() {
	local _scanid="$1"
	local _ckpt_file="$sessdir/scan.checkpoint.$_scanid"

	# Validate checkpoint exists
	if [ ! -f "$_ckpt_file" ]; then
		echo "maldet($$): {lifecycle} checkpoint not found for scan $_scanid" >&2
		return 1
	fi

	# Validate header
	local _header
	IFS= read -r _header < "$_ckpt_file"
	if [ "$_header" != "#LMD_CHECKPOINT:v1" ]; then
		echo "maldet($$): {lifecycle} corrupt checkpoint for scan $_scanid (invalid header)" >&2
		return 1
	fi

	# Check if scan is currently paused (user should use --unpause instead)
	if [ -f "$tmpdir/.pause.$_scanid" ]; then
		# Also check meta state
		if _lifecycle_read_meta "$_scanid" 2>/dev/null; then  # safe: meta may not exist for old scans
			if [ "$_meta_state" = "paused" ]; then
				echo "maldet($$): {lifecycle} scan $_scanid is paused — use --unpause to resume" >&2
				return 1
			fi
		fi
		# Sentinel exists but meta not paused — stale sentinel, clean it
		command rm -f "$tmpdir/.pause.$_scanid"
	fi

	# Parse checkpoint into _ckpt_* variables
	local _key _value
	local _ckpt_scanid="" _ckpt_stopped="" _ckpt_stopped_hr=""
	local _ckpt_stage="" _ckpt_sig_version="" _ckpt_workers=""
	local _ckpt_total_files="" _ckpt_hits_so_far="" _ckpt_options=""

	while IFS='=' read -r _key _value; do
		case "$_key" in
			"#"*|"") continue ;;
		esac
		case "$_key" in
			scanid)       _ckpt_scanid="$_value" ;;
			stopped)      _ckpt_stopped="$_value" ;;
			stopped_hr)   _ckpt_stopped_hr="$_value" ;;
			stage)        _ckpt_stage="$_value" ;;
			sig_version)  _ckpt_sig_version="$_value" ;;
			workers)      _ckpt_workers="$_value" ;;
			total_files)  _ckpt_total_files="$_value" ;;
			hits_so_far)  _ckpt_hits_so_far="$_value" ;;
			options)      _ckpt_options="$_value" ;;
		esac
	done < "$_ckpt_file"

	# Compare sig version with current on-disk version
	local _cur_sig_ver
	if [ -f "$sigdir/maldet.sigs.ver" ]; then
		IFS= read -r _cur_sig_ver < "$sigdir/maldet.sigs.ver"
	else
		_cur_sig_ver="unknown"
	fi
	[ -z "$_cur_sig_ver" ] && _cur_sig_ver="unknown"

	if [ "$_ckpt_sig_version" != "$_cur_sig_ver" ] && \
	   [ "$_ckpt_sig_version" != "unknown" ] && [ "$_cur_sig_ver" != "unknown" ]; then
		eout "{lifecycle} warning: signature version changed since checkpoint (was: $_ckpt_sig_version, now: $_cur_sig_ver)" 1
	fi

	# Apply checkpoint options as config overrides
	if [ -n "$_ckpt_options" ]; then
		local _opt
		local _saved_ifs="$IFS"
		IFS=','
		for _opt in $_ckpt_options; do
			IFS="$_saved_ifs"
			# Each _opt is "key=value" — apply to shell environment
			local _opt_key="${_opt%%=*}"
			local _opt_val="${_opt#*=}"
			# Validate key is a safe identifier (word chars only) to prevent eval injection
			if [ -n "$_opt_key" ] && [[ "$_opt_key" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
				eval "$_opt_key=\"\$_opt_val\""
			fi
		done
		IFS="$_saved_ifs"
	fi

	eout "{lifecycle} resuming scan $_ckpt_scanid from stage $_ckpt_stage (checkpoint: ${_ckpt_stopped_hr:-unknown})" 1
	if [ -n "$_ckpt_hits_so_far" ] && [ "$_ckpt_hits_so_far" != "0" ]; then
		eout "{lifecycle} prior hits: $_ckpt_hits_so_far" 1
	fi

	# Export checkpoint data for scan orchestration to consume
	# shellcheck disable=SC2034
	_continue_scanid="$_ckpt_scanid"
	# shellcheck disable=SC2034
	_continue_stage="$_ckpt_stage"
	# shellcheck disable=SC2034
	_continue_workers="$_ckpt_workers"
	# shellcheck disable=SC2034
	_continue_total_files="$_ckpt_total_files"
	# shellcheck disable=SC2034
	_continue_hits_so_far="$_ckpt_hits_so_far"
	# shellcheck disable=SC2034
	_continue_options="$_ckpt_options"

	# Read per-worker chunk checkpoints (Phase 14)
	# Only meaningful when checkpoint stage is "hex" (HEX workers write per-worker .wp files)
	# shellcheck disable=SC2034
	_continue_chunk_skips=""
	if [ "$_ckpt_stage" = "hex" ]; then
		local _wp_count=0 _wp_file _wp_header _wp_valid=1
		local _wp_chunks_list=""

		# Count and validate per-worker checkpoint files
		for _wp_file in "$sessdir"/scan.wp."$_ckpt_scanid".*; do
			[ -f "$_wp_file" ] || continue
			# Validate #LMD_WP:v1 header
			IFS= read -r _wp_header < "$_wp_file"
			if [ "$_wp_header" != "#LMD_WP:v1" ]; then
				_wp_valid=0
				break
			fi
			# Parse chunks_completed value
			local _wp_chunks=0 _wp_key _wp_val
			while IFS='=' read -r _wp_key _wp_val; do
				case "$_wp_key" in
					"#"*|"") continue ;;
					chunks_completed) _wp_chunks="$_wp_val" ;;
				esac
			done < "$_wp_file"
			if [ -z "$_wp_chunks_list" ]; then
				_wp_chunks_list="$_wp_chunks"
			else
				_wp_chunks_list="$_wp_chunks_list $_wp_chunks"
			fi
			_wp_count=$((_wp_count + 1))
		done

		if [ "$_wp_count" -gt 0 ]; then
			if [ "$_wp_valid" -eq 0 ] || [ "$_wp_count" != "$_ckpt_workers" ]; then
				# Worker count mismatch or invalid wp file: fall back to stage-granularity
				eout "{lifecycle} warning: worker count mismatch (checkpoint: $_ckpt_workers, found: $_wp_count wp files) — falling back to stage-granularity resume" 1
				# shellcheck disable=SC2034
				_continue_chunk_skips=""
			else
				# All workers matched — export chunk-skip counts
				# shellcheck disable=SC2034
				_continue_chunk_skips="$_wp_chunks_list"
			fi
		fi
	fi

	return 0
}
