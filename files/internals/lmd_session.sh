#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck disable=SC1090,SC1091
##
# Linux Malware Detect v2.0.1
#             (C) 2002-2026, R-fx Networks <proj@rfxn.com>
#             (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
# Session format, report rendering, and log management

# Source guard
[[ -n "${_LMD_SESSION_LOADED:-}" ]] && return 0 2>/dev/null
_LMD_SESSION_LOADED=1

# shellcheck disable=SC2034
LMD_SESSION_VERSION="1.0.0"

# _session_is_tsv file — returns 0 if file is TSV format (line 1 starts with #LMD:v1)
_session_is_tsv() {
	local _file="$1"
	[ -f "$_file" ] || return 1
	local _first_line
	IFS= read -r _first_line < "$_file"
	case "$_first_line" in
		"#LMD:v1"*) return 0 ;;
		*) return 1 ;;
	esac
}

# _session_read_meta file — read TSV metadata header into caller's variables
# Sets: _fmt _alert_type scanid _hostname hrspath days
#       scan_start_hr scan_end_hr scan_et file_list_et
#       tot_files tot_hits tot_cl
#       _scanner_ver _sig_ver _hashtype _engine _quar_enabled _hostid
# The "-" sentinel in any field is preserved as literal "-".
# Callers must check for "-" before using numeric fields.
# shellcheck disable=SC2034
_session_read_meta() {
	local _file="$1"
	[ -f "$_file" ] || return 1
	# Single read of line 1 — avoids here-string temp file on bash 4.1
	IFS=$'\t' read -r _fmt _alert_type scanid _hostname hrspath days \
		scan_start_hr scan_end_hr scan_et file_list_et \
		tot_files tot_hits tot_cl \
		_scanner_ver _sig_ver _hashtype _engine _quar_enabled _hostid \
		< "$_file"
	# Derive datestamp from scanid (portion before the dot-separated PID)
	datestamp="${scanid%%.*}"
}

# _session_write_header file alert_type — write 19-field TSV metadata header
# Reads from scan context variables set by the calling context.
# Unknown fields use "-" sentinel (monitor mode partial header).
_session_write_header() {
	local _file="$1" _alert_type="$2"
	local _hostname _hostid_val _sig_ver_val _engine_val
	_hostname=$(hostname)
	_hostid_val="${hostid:--}"
	_sig_ver_val="${sig_version:-$(cat "$sigdir/maldet.sigs.ver" 2>/dev/null || echo "-")}"  # safe: fallback provides sentinel when sigs.ver missing
	# Determine engine — scan_clamscan=1 means ClamAV was used as the primary engine.
	# Native engine always runs hash+hex passes; ClamAV replaces them when enabled.
	# Both never run simultaneously in current architecture.
	if [ "$scan_clamscan" == "1" ]; then
		_engine_val="clamav"
	else
		_engine_val="native"
	fi
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"#LMD:v1" \
		"$_alert_type" \
		"${scanid:-$datestamp.$$}" \
		"$_hostname" \
		"${hrspath:--}" \
		"${days:--}" \
		"${scan_start_hr:--}" \
		"${scan_end_hr:--}" \
		"${scan_et:--}" \
		"${file_list_et:--}" \
		"${tot_files:--}" \
		"${tot_hits:--}" \
		"${tot_cl:--}" \
		"${lmd_version:--}" \
		"$_sig_ver_val" \
		"${_effective_hashtype:--}" \
		"$_engine_val" \
		"${quarantine_hits:-0}" \
		"$_hostid_val" \
		> "$_file"
}

# _session_resolve scanid — return path to session data file for a scan ID
# Checks session.tsv.$scanid first, falls back to session.hits.$scanid
# (pre-upgrade scans), returns "" if neither exists.
# Usage: local _datafile; _datafile=$(_session_resolve "$rid")
_session_resolve() {
	local _sid="$1"
	if [ -f "$sessdir/session.tsv.$_sid" ]; then
		echo "$sessdir/session.tsv.$_sid"
	elif [ -f "$sessdir/session.hits.$_sid" ]; then
		echo "$sessdir/session.hits.$_sid"
	fi
}

# _session_legacy_check — determine whether to generate legacy plaintext files
# Returns: sets _session_legacy_active to 0 or 1
# Cache: $sessdir/.session_format (check-once, purge resets)
_session_legacy_check() {
	_session_legacy_active=0
	case "${session_legacy_compat:-auto}" in
		0) _session_legacy_active=0; return ;;
		1) _session_legacy_active=1; return ;;
	esac
	# auto mode: check cache first
	if [ -f "$sessdir/.session_format" ]; then
		local _cached
		_cached=$(cat "$sessdir/.session_format")
		case "$_cached" in
			v1)     _session_legacy_active=0; return ;;
			legacy) _session_legacy_active=1; return ;;
		esac
	fi
	# No cache: check most recent session file
	local _latest _latest_file=""
	for _latest in "$sessdir"/session.[0-9]*; do
		[ -f "$_latest" ] || continue
		# Skip .tsv. and .hits. variants
		case "$_latest" in
			*.tsv.*|*.hits.*) continue ;;
		esac
		_latest_file="$_latest"
	done
	if [ -n "$_latest_file" ] && ! _session_is_tsv "$_latest_file"; then
		echo "legacy" > "$sessdir/.session_format"
		_session_legacy_active=1
	else
		echo "v1" > "$sessdir/.session_format"
		_session_legacy_active=0
	fi
}

# _parse_session_metadata session_file — parse text session header into shell vars
# Populates scan metadata variables (scanid, scan_start_hr, scan_end_hr, scan_et,
# file_list_et, hrspath, days, tot_files, tot_hits, tot_cl) from a previously
# rendered text session file. Called before on-demand HTML rendering so that
# _lmd_set_global_vars() has the data it needs.
# shellcheck disable=SC2034
_parse_session_metadata() {
	local _sess_file="$1"
	[ -f "$_sess_file" ] || return 1
	local _line _key _val
	while IFS= read -r _line; do
		# Stop at the first hit entry (sig : filepath) or FILE HIT LIST marker
		case "$_line" in
			"FILE HIT LIST:"*) break ;;
			*" : "*)           break ;;
		esac
		# Strip leading/trailing whitespace from value after the label
		_key="${_line%%:*}"
		_val="${_line#*:}"
		# Trim leading spaces from value
		_val="${_val#"${_val%%[![:space:]]*}"}"
		case "$_key" in
			"SCAN ID")
				scanid="$_val"
				# Derive datestamp (portion before the dot-separated PID)
				datestamp="${scanid%%.*}"
				;;
			"STARTED")   scan_start_hr="$_val" ;;
			"COMPLETED") scan_end_hr="$_val" ;;
			"ELAPSED")
				# Format: "285s [find: 1s]"
				local _elapsed_pat='^([0-9]+)s[[:space:]]*\[find:[[:space:]]*([0-9]+)s\]'
				if [[ "$_val" =~ $_elapsed_pat ]]; then
					scan_et="${BASH_REMATCH[1]}"
					file_list_et="${BASH_REMATCH[2]}"
				fi
				;;
			"PATH")          hrspath="$_val" ;;
			"RANGE")
				# Strip trailing non-numeric (e.g., "1 days" -> "1")
				days="${_val%% *}"
				;;
			"TOTAL FILES")   tot_files="$_val" ;;
			"TOTAL HITS")    tot_hits="$_val" ;;
			"TOTAL CLEANED") tot_cl="$_val" ;;
		"HOST")          _hostname="$_val" ;;
		esac
	done < "$_sess_file"
}

# _resolve_html_for_session session_file — render HTML on-demand from current templates
# Sets caller's _html to a temp file path, or "" if text session unavailable.
# Always renders fresh using current templates (no persistent HTML storage).
# Handles both clean scans (empty manifest) and dirty scans (hits in manifest).
# Accepts plaintext session, TSV session, or legacy hits file.
# Usage: local _html=""; _resolve_html_for_session "$sessdir/session.$rid"
_resolve_html_for_session() {
	local _sess="$1"
	_html=""
	if [ ! -f "$_sess" ]; then
		return 0
	fi
	# Extract scan ID from filename, handling both legacy and TSV naming
	local _sid _basename
	_basename="${_sess##*/}"
	case "$_basename" in
		session.tsv.*)  _sid="${_basename#session.tsv.}" ;;
		session.hits.*) _sid="${_basename#session.hits.}" ;;
		session.*)      _sid="${_basename#session.}" ;;
	esac
	# Populate scan metadata: TSV uses _session_read_meta, text uses _parse_session_metadata
	if _session_is_tsv "$_sess"; then
		_session_read_meta "$_sess"
	else
		_parse_session_metadata "$_sess"
	fi
	# Resolve hits data file: session.tsv.* (TSV) or session.hits.* (legacy)
	local _hits
	_hits=$(_session_resolve "$_sid")
	# If no separate hits file found, the input itself may contain hits
	if [ -z "$_hits" ] && [ -f "$_sess" ]; then
		_hits="$_sess"
	fi
	local _manifest _tpl_dir
	_tpl_dir="${ALERT_TEMPLATE_DIR:-$libpath/alert}"
	_manifest=$(mktemp "$tmpdir/.alert_manifest.XXXXXX")
	# Parse hits if available (empty manifest for clean scans is valid)
	if [ -n "$_hits" ] && [ -f "$_hits" ] && [ -s "$_hits" ]; then
		_lmd_parse_hitlist "$_hits" > "$_manifest"
	fi
	# Render HTML to temp file — clean scans get celebration, dirty get stat blocks
	_html=$(mktemp "$tmpdir/.alert_html.XXXXXX")
	_lmd_render_html "$_manifest" "scan" "$_tpl_dir" > "$_html"
	rm -f "$_manifest"
}

view_report() {
	local rid="$1"

	# --- LIST MODE ---
	if [ "$rid" == "list" ]; then
		if [ "${_report_format:-}" = "json" ]; then
			_lmd_render_json_list
			exit 0
		fi
		tmpf=$(mktemp "$tmpdir/.areps.XXXXXX")
		local _seen_ids=""
		# Pass 1: TSV session files (preferred format)
		for file in "$sessdir"/session.tsv.[0-9]*; do
			[ -f "$file" ] || continue
			local _sid="${file##*session.tsv.}"
			_session_read_meta "$file"
			if [ -n "$scanid" ] && [ "$scan_start_hr" != "-" ]; then
				local _time_u _etime
				_time_u=$(date -d "$scan_start_hr" "+%s" 2>/dev/null)
				_etime="RUNTIME: ${scan_et:--}s"
				echo "$_time_u | $scan_start_hr | SCANID: $scanid | $_etime | FILES: ${tot_files:--} | HITS: ${tot_hits:--} | CLEANED: ${tot_cl:-0}" >> "$tmpf"
				_seen_ids="$_seen_ids $_sid"
			fi
		done
		# Pass 2: Legacy plaintext session files (skip if TSV exists)
		for file in "$sessdir"/session.[0-9]*; do
			[ -f "$file" ] || continue
			case "$file" in *.tsv.*|*.hits.*) continue ;; esac
			local _sid="${file##*session.}"
			case "$_seen_ids" in *" $_sid"*) continue ;; esac
			_meta=$(grep -E "^SCAN ID|^TOTAL FILES|^TOTAL HITS|^TOTAL CLEANED|^TIME:|^STARTED:|^ELAPSED" "$file")
			SCANID=$(grep "SCAN ID" <<< "$_meta" | sed 's/SCAN ID/SCANID/')
			FILES=$(grep "TOTAL FILES" <<< "$_meta" | sed 's/TOTAL //')
			HITS=$(grep "TOTAL HITS" <<< "$_meta" | sed 's/TOTAL //')
			CLEAN=$(grep "TOTAL CLEANED" <<< "$_meta" | sed 's/TOTAL //')
			TIME=$(grep -E "^TIME|^STARTED" <<< "$_meta" | sed -e 's/TIME: //' -e 's/STARTED: //' | awk '{print$1,$2,$3,$4}')
			TIME_U=$(date -d "$TIME" "+%s" 2>/dev/null)
			ETIME=$(grep "ELAPSED" <<< "$_meta" | awk '{print$1,$2}' | sed 's/ELAPSED/RUNTIME/')
			if [ -z "$ETIME" ]; then
				ETIME="RUNTIME: unknown"
			fi
			if [ -n "$SCANID" ] && [ -n "$TIME" ]; then
				clean_zero=$(echo $CLEAN | awk '{print$2}')
				if [ -z "$clean_zero" ]; then
					CLEAN="CLEANED:  0"
				fi
				echo "$TIME_U | $TIME | $SCANID | $ETIME | $FILES | $HITS | $CLEAN" >> "$tmpf"
			fi
		done
		if [ -f "$tmpf" ]; then
			if [ "$os_freebsd" == "1" ]; then
				sort -k1 -n "$tmpf" | cut -d'|' -f2-7 | column -t | more
			else
				sort -k1 -n "$tmpf" | tac | cut -d'|' -f2-7 | column -t | more
			fi
			rm -f "$tmpf" 2> /dev/null
			exit 0
		else
			eout "{report} no report data found" 1
			exit 1
		fi
	fi

	# --- RESOLVE RID (newest/empty) ---
	if [ "$rid" == "newest" ] || [ "$rid" == "" ]; then
		if [ -f "$sessdir/session.last" ]; then
			rid=$(cat "$sessdir/session.last")
		else
			eout "{report} no recent scan session found" 1
			exit 1
		fi
	fi

	# --- DETERMINE EMAIL TARGET ---
	local _mailto="${_report_mailto:-}"
	[ -z "$_mailto" ] && [[ "${2:-}" == *@* ]] && _mailto="$2"

	# --- JSON FORMAT (early exit, TSV-first resolution) ---
	if [ "${_report_format:-}" = "json" ]; then
		local _json_tmp
		_json_tmp=$(mktemp "$tmpdir/.json_report.XXXXXX")
		if [ -f "$sessdir/session.tsv.$rid" ]; then
			_lmd_render_json "$sessdir/session.tsv.$rid" > "$_json_tmp"
		elif [ -f "$sessdir/session.$rid" ] || [ -f "$sessdir/session.hits.$rid" ]; then
			local _sess="" _hits=""
			[ -f "$sessdir/session.$rid" ] && _sess="$sessdir/session.$rid"
			[ -f "$sessdir/session.hits.$rid" ] && _hits="$sessdir/session.hits.$rid"
			_lmd_render_json_legacy "$_sess" "$_hits" > "$_json_tmp"
		else
			command rm -f "$_json_tmp"
			local _safe_rid="${rid//\"/\\\"}"
			echo '{"error": "no report found for scan ID '"$_safe_rid"'"}' >&2
			exit 1
		fi
		if [ -n "$_mailto" ]; then
			_alert_deliver_email "$_mailto" "$email_subj" "$_json_tmp" "" "text"
			eout "{report} JSON report ID $rid sent to $_mailto" 1
		else
			cat "$_json_tmp"
		fi
		command rm -f "$_json_tmp"
		exit 0
	fi

	# --- RESOLVE SESSION FILE (text/html, legacy-first) ---
	local _report_file=""
	if [ -f "$sessdir/session.$rid" ]; then
		_report_file="$sessdir/session.$rid"
	elif [ -f "$sessdir/session.tsv.$rid" ]; then
		_report_file="$sessdir/session.tsv.$rid"
	else
		eout "{report} no report found for scan ID $rid" 1
		exit 1
	fi

	# --- EMAIL DISPATCH ---
	if [ -n "$_mailto" ]; then
		local _html="" _fmt="${_report_format:-${email_format:-html}}"
		# Save _fmt before _resolve_html_for_session — _session_read_meta
		# clobbers _fmt when reading TSV headers
		local _save_fmt="$_fmt"
		_resolve_html_for_session "$_report_file"
		_fmt="$_save_fmt"
		# Downgrade format when HTML unavailable and cannot be rendered
		if [ -z "$_html" ] && [ "$_fmt" != "text" ]; then
			eout "{report} HTML rendering unavailable, sending text format" 1
			_fmt="text"
		fi
		if ! _alert_deliver_email "$_mailto" "$email_subj" "$_report_file" "$_html" "$_fmt"; then
			eout "{report} no \$mail or \$sendmail binaries found, e-mail alerts disabled." 1
			exit 1
		fi
		eout "{report} report ID $rid sent to $_mailto" 1
		exit 0
	fi

	# --- TERMINAL DISPLAY ---
	if [ "${_report_format:-}" = "html" ]; then
		local _html=""
		_resolve_html_for_session "$_report_file"
		if [ -n "$_html" ]; then
			cat "$_html"
			command rm -f "$_html"
		else
			eout "{report} HTML rendering unavailable" 1
			exit 1
		fi
	elif _session_is_tsv "$_report_file"; then
		# TSV: render text on-demand
		local _manifest _tpl_dir
		_tpl_dir="${ALERT_TEMPLATE_DIR:-$libpath/alert}"
		_manifest=$(mktemp "$tmpdir/.report_manifest.XXXXXX")
		_session_read_meta "$_report_file"
		_lmd_parse_hitlist "$_report_file" > "$_manifest"
		_lmd_set_global_vars "scan"
		_lmd_compute_summary "$_manifest"
		_lmd_render_text "$_manifest" "scan" "$_tpl_dir"
		command rm -f "$_manifest"
	else
		cat "$_report_file"
	fi
	exit 0
}

dump_report() {
	view_report "$1"
}

# view_report_json [SCANID|list|newest] — output scan report as JSON
# Thin wrapper: sets _report_format=json and delegates to view_report().
# Retained for backward compatibility with --json-report case handler.
# shellcheck disable=SC2154
view_report_json() {
	_report_format="json"
	view_report "$1"
}

view() {
	echo "Viewing last 50 lines from $maldet_log:"
	tail -n 50 "$maldet_log"
}

_inotify_trim_log() {
	local _trim="$1"
	local bytes_removed
	bytes_removed=$(head -n "$_trim" "$inotify_log" 2>/dev/null | $wc -c)
	tlog_adjust_cursor "inotify" "$tmpdir" "$bytes_removed"
	local tmplog
	tmplog=$(mktemp "${inotify_log}.trim.XXXXXX")
	tail -n +"$((_trim + 1))" "$inotify_log" > "$tmplog" 2>/dev/null
	cat "$tmplog" > "$inotify_log" 2>/dev/null
	rm -f "$tmplog"
	eout "{mon} inotify log file trimmed"
}

purge() {
	:> "$maldet_log"
	if [ -f "$inotify_log" ]; then
		log_size=$($wc -l < "$inotify_log")
		if [ "$inotify_trim" ] && [ "$log_size" -ge "$inotify_trim" ]; then
			_inotify_trim_log "$(($log_size - 1000))"
		fi
	fi
	rm -f "$tmpdir"/* "$quardir"/* "$sessdir"/* 2> /dev/null
	command rm -f "$sessdir/.session_format"  # reset legacy compat auto-detection cache
	eout "{glob} logs and quarantine data cleared by user request (-p)" 1
}

# _session_render_legacy_text tsv_file outfile — conditionally render legacy plaintext
# Gated by session_legacy_compat (auto/0/1). When active, converts 11-field TSV
# hit records to 6-field manifest, then renders via _lmd_render_text.
_session_render_legacy_text() {
	local _tsv="$1" _outfile="$2"
	_session_legacy_check
	if [ "$_session_legacy_active" != "1" ]; then
		return 0
	fi
	local _manifest _tpl_dir
	_manifest=$(mktemp "$tmpdir/.alert_manifest.XXXXXX")
	_tpl_dir="${ALERT_TEMPLATE_DIR:-$libpath/alert}"
	# Parse TSV hit records (skip header) into the 6-field manifest format
	# that _lmd_render_text expects: sig filepath quarpath hit_type color hit_type_label
	awk -F'\t' '!/^#/{
		sig=$1; fp=$2; qp=$3; ht=$4; htl=$5
		if (sig == "") next
		if (qp == "-") qp = ""
		# Hit type color registry (matches _lmd_parse_hitlist)
		ht_color["MD5"]  = "#0891b2"; ht_color["HEX"]  = "#dc2626"
		ht_color["YARA"] = "#d97706"; ht_color["SA"]   = "#16a34a"
		ht_color["CAV"]  = "#7c3aed"; ht_color["CSIG"] = "#ea580c"
		ht_color["SHA256"] = "#0d9488"
		color = (ht in ht_color) ? ht_color[ht] : "#0891b2"
		printf "%s\t%s\t%s\t%s\t%s\t%s\n", sig, fp, (qp=="" ? "-" : qp), ht, color, htl
	}' "$_tsv" > "$_manifest"
	_lmd_render_text "$_manifest" "scan" "$_tpl_dir" > "$_outfile"
	command rm -f "$_manifest"
}

# _scan_finalize_session — write TSV session file from in-flight scan_session
# Creates session.tsv.$datestamp.$$ with metadata header + hit records,
# renders legacy text session, posts to ELK, and removes scan_session.
_scan_finalize_session() {
	if [ ! -f "$scan_session" ]; then
		return
	fi
	# Count hits (skip header if present — header starts with #)
	tot_hits=$(awk '!/^#/' "$scan_session" | $wc -l)
	nsess_hits="$sessdir/session.tsv.$datestamp.$$"
	echo "$datestamp.$$" > "$sessdir/session.last"
	nsess="$sessdir/session.$datestamp.$$"

	# Write header + hit data to TSV
	_session_write_header "$nsess_hits" "scan"
	# Append hit records (scan_session has no header during in-flight scan)
	cat "$scan_session" >> "$nsess_hits"

	# ELK posting (reads TSV directly, skipping header)
	_lmd_elk_post_hits "$nsess_hits"

	# Legacy plaintext rendering (conditional on session_legacy_compat)
	_session_render_legacy_text "$nsess_hits" "$nsess"

	# If legacy compat did not produce a plaintext file, point nsess at
	# the TSV file so downstream consumers (genalert, --report) have a
	# valid file path.
	if [ ! -f "$nsess" ]; then
		nsess="$nsess_hits"
	fi

	# Remove in-flight scan_session — all data now in nsess_hits
	command rm -f "$scan_session"
}
