#!/usr/bin/env bash
#
##
# Linux Malware Detect v2.0.1
#             (C) 2002-2026, R-fx Networks <proj@rfxn.com>
#             (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#
# This file is sourced by maldet after the shared alert_lib.sh.
# It provides LMD-specific alert functions: data preparation, rendering
# pipeline, and wrappers for the shared library's delivery API.

# Source guard — prevent double-sourcing
[[ -n "${_LMD_ALERT_LOADED:-}" ]] && return 0 2>/dev/null
_LMD_ALERT_LOADED=1

# shellcheck disable=SC2034
LMD_ALERT_VERSION="1.0.0"

# ---------------------------------------------------------------------------
# Data Preparation
# ---------------------------------------------------------------------------

# _lmd_parse_hitlist hitlist_file — parse raw hit list to tab-delimited manifest
# Input format:  {TYPE}sig.name : /path/to/file
#            or: {TYPE}sig.name : /path/to/file => /quarantine/path
# Output format: sig\tfilepath\tquarpath\thit_type\thit_type_color\thit_type_label
# Single-pass awk; extracts {TYPE} prefix to determine hit_type, resolves
# display color and label from the hit type registry in the BEGIN block.
# Output goes to stdout.
_lmd_parse_hitlist() {
	local hitlist_file="$1"
	if [ ! -f "$hitlist_file" ] || [ ! -s "$hitlist_file" ]; then
		return 1
	fi
	awk -F' : ' '
	BEGIN {
		# Hit type registry: type key -> display color and label
		ht_color["MD5"]  = "#0891b2"; ht_label["MD5"]  = "MD5 Hash"
		ht_color["HEX"]  = "#dc2626"; ht_label["HEX"]  = "HEX Pattern"
		ht_color["YARA"] = "#d97706"; ht_label["YARA"] = "YARA Rule"
		ht_color["SA"]   = "#16a34a"; ht_label["SA"]   = "String Analysis"
		ht_color["CAV"]  = "#7c3aed"; ht_label["CAV"]  = "ClamAV"
		default_color = "#0891b2"
	}
	{
		sig = $1
		rest = $2
		# Extract hit type from {TYPE} prefix
		hit_type = ""
		if (match(sig, /^\{[A-Z][A-Z0-9]*\}/)) {
			hit_type = substr(sig, 2, RLENGTH - 2)
		}
		# Split rest into filepath and quarpath on " => "
		quarpath = ""
		filepath = rest
		idx = index(rest, " => ")
		if (idx > 0) {
			filepath = substr(rest, 1, idx - 1)
			quarpath = substr(rest, idx + 4)
		}
		# Trim whitespace
		gsub(/^[[:space:]]+|[[:space:]]+$/, "", sig)
		gsub(/^[[:space:]]+|[[:space:]]+$/, "", filepath)
		gsub(/^[[:space:]]+|[[:space:]]+$/, "", quarpath)
		if (filepath != "") {
			# Use "-" sentinel for empty quarpath to prevent IFS tab-collapsing
			# in bash read; consecutive tabs (\t\t) are collapsed by read,
			# shifting hit_type into quarpath field
			if (quarpath == "") quarpath = "-"
			color = (hit_type in ht_color) ? ht_color[hit_type] : default_color
			label = (hit_type in ht_label) ? ht_label[hit_type] : hit_type
			printf "%s\t%s\t%s\t%s\t%s\t%s\n", sig, filepath, quarpath, hit_type, color, label
		}
	}' "$hitlist_file"
}

# _lmd_set_global_vars alert_type — export global template variables to ENVIRON
# alert_type: scan, digest, or panel
# Reads from shell variables set by the calling context (gen_report/genalert).
# shellcheck disable=SC2154
_lmd_set_global_vars() {
	local alert_type="$1"

	export HOSTNAME; HOSTNAME=$(hostname)
	export TIMESTAMP; TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
	export TIMESTAMP_ISO; TIMESTAMP_ISO=$(date +"%Y-%m-%dT%H:%M:%S%z")
	export TIME_ZONE; TIME_ZONE=$(date +"%z")
	export LMD_VERSION="${lmd_version:-}"
	export ALERT_TYPE="$alert_type"

	# Scan metadata
	export SCAN_ID="${scanid:-}"
	export SCAN_STARTED="${scan_start_hr:-}"
	export SCAN_COMPLETED="${scan_end_hr:-}"
	export SCAN_ELAPSED="${scan_et:-}"
	export FILELIST_ELAPSED="${file_list_et:-}"
	export SCAN_PATH="${hrspath:-}"
	export SCAN_RANGE="${days:-}"
	export TOTAL_FILES="${tot_files:-0}"
	export TOTAL_HITS="${tot_hits:-0}"
	export TOTAL_CLEANED="${tot_cl:-0}"

	# Conditional: quarantine warning
	export QUARANTINE_WARNING_TEXT=""
	export QUARANTINE_WARNING_HTML=""
	if [ "${quarantine_hits:-0}" = "0" ] && [ "${tot_hits:-0}" != "0" ]; then
		QUARANTINE_WARNING_TEXT="WARNING: Automatic quarantine is currently disabled, detected threats are still accessible to users!
To enable, set quarantine_hits=1 and/or to quarantine hits from this scan run:
/usr/local/sbin/maldet -q ${datestamp:-}.$$
"
		QUARANTINE_WARNING_HTML="<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" width=\"100%\" style=\"margin-bottom:16px;background-color:#fefce8;border:1px solid #fde68a;border-radius:8px;overflow:hidden;\">
<tr><td style=\"background-color:#d97706;height:3px;font-size:0;line-height:0;\">&nbsp;</td></tr>
<tr><td style=\"padding:12px 16px;color:#92400e;font-size:13px;\">
<strong>Warning:</strong> Automatic quarantine is disabled. Detected threats are still accessible to users.<br>
To enable, set <code style=\"font-family:'Courier New',Courier,monospace;font-size:12px;\">quarantine_hits=1</code> or quarantine this scan: <code style=\"font-family:'Courier New',Courier,monospace;font-size:12px;\">maldet -q ${datestamp:-}.$$</code>
</td></tr></table>"
	fi

	# Conditional: cleaned section
	export CLEANED_SECTION_TEXT=""
	export CLEANED_SECTION_HTML=""
	if [ "${quarantine_clean:-0}" = "1" ]; then
		local _clist=""
		if [ "$alert_type" = "scan" ] && [ -s "${sessdir:-}/clean.$$" ]; then
			_clist="${sessdir}/clean.$$"
		elif [ "$alert_type" = "digest" ] && [ -f "${tmpdir:-}/.digest.clean.hits" ] && [ "${tot_cl:-0}" != "0" ]; then
			_clist="${tmpdir}/.digest.clean.hits"
		fi
		if [ -f "$_clist" ]; then
			CLEANED_SECTION_TEXT="CLEANED & RESTORED FILES:
$(cat "$_clist")
"
			local _clist_html
			_clist_html=$(_alert_html_escape "$(cat "$_clist")")
			CLEANED_SECTION_HTML="<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" width=\"100%\" style=\"margin-bottom:12px;\">
<tr><td style=\"color:#71717a;font-size:12px;text-transform:uppercase;letter-spacing:1px;padding-bottom:6px;\">Cleaned &amp; Restored Files</td></tr>
<tr><td style=\"font-family:'Courier New',Courier,monospace;font-size:12px;color:#09090b;background-color:#f4f4f5;padding:8px 12px;border-radius:4px;border:1px solid #d4d4d8;word-break:break-all;\">${_clist_html//$'\n'/<br>}</td></tr></table>"
		fi
	fi

	# Conditional: suspended section
	export SUSPENDED_SECTION_TEXT=""
	export SUSPENDED_SECTION_HTML=""
	if [ "${quarantine_suspend_user:-0}" = "1" ]; then
		local _slist=""
		if [ -s "${sessdir:-}/suspend.users.$$" ]; then
			_slist="${sessdir}/suspend.users.$$"
		elif [ "$alert_type" = "digest" ] && [ -f "${tmpdir:-}/.digest.susp.hits" ] && [ "${tot_susp:-0}" != "0" ]; then
			_slist="${tmpdir}/.digest.susp.hits"
		fi
		if [ -f "$_slist" ]; then
			SUSPENDED_SECTION_TEXT="SUSPENDED ACCOUNTS:
$(cat "$_slist")
"
			local _slist_html
			_slist_html=$(_alert_html_escape "$(cat "$_slist")")
			SUSPENDED_SECTION_HTML="<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" width=\"100%\" style=\"margin-bottom:12px;\">
<tr><td style=\"color:#71717a;font-size:12px;text-transform:uppercase;letter-spacing:1px;padding-bottom:6px;\">Suspended Accounts</td></tr>
<tr><td style=\"font-family:'Courier New',Courier,monospace;font-size:12px;color:#09090b;background-color:#f4f4f5;padding:8px 12px;border-radius:4px;border:1px solid #d4d4d8;\">${_slist_html//$'\n'/<br>}</td></tr></table>"
		fi
	fi

	# Digest-specific
	export MONITOR_RUNTIME="${inotify_run_time:-}"
	export TOTAL_SCANNED="${tot_files:-0}"

	# Panel-specific (set by caller before invoking render)
	export PANEL_USER="${sys_user:-}"
	export USER_TOTAL_HITS="${user_tot_hits:-0}"
	export USER_TOTAL_CLEANED="${user_tot_cl:-0}"
}

# _lmd_compute_summary manifest_file — compute summary variables from manifest
# Single-pass awk over tab-delimited manifest (6-field: sig through hit_type_label).
# Exports SUMMARY_* variables. For empty manifests, sets all tokens to zero.
_lmd_compute_summary() {
	local manifest_file="$1"
	if [ ! -f "$manifest_file" ] || [ ! -s "$manifest_file" ]; then
		export SUMMARY_TOTAL_HITS="0"
		export SUMMARY_TOTAL_QUARANTINED="0"
		export SUMMARY_BY_TYPE=""
		export SUMMARY_BY_TYPE_HTML=""
		export SUMMARY_QUARANTINE_STATUS=""
		export SUMMARY_TOTAL_CLEANED="${tot_cl:-0}"
		return 0
	fi

	local _summary
	_summary=$(awk -F'\t' '
	{
		total++
		type = $4
		if (type != "") types[type]++
		if ($3 != "" && $3 != "-") quarantined++
	}
	END {
		# Build type breakdown
		by_type = ""
		by_type_html = ""
		for (t in types) {
			if (by_type != "") { by_type = by_type ", "; by_type_html = by_type_html " " }
			by_type = by_type t "(" types[t] ")"
			by_type_html = by_type_html t "(" types[t] ")"
		}
		# Quarantine status
		if (quarantined == total && total > 0) {
			qstatus = "All threats quarantined"
		} else if (quarantined > 0) {
			qstatus = quarantined " of " total " quarantined"
		} else {
			qstatus = "None quarantined"
		}
		printf "%d\n%d\n%s\n%s\n%s\n", total, quarantined, by_type, by_type_html, qstatus
	}' "$manifest_file")

	local _line=0
	while IFS= read -r _val; do
		case $_line in
			0) export SUMMARY_TOTAL_HITS="$_val" ;;
			1) export SUMMARY_TOTAL_QUARANTINED="$_val" ;;
			2) export SUMMARY_BY_TYPE="$_val" ;;
			3) export SUMMARY_BY_TYPE_HTML="$_val" ;;
			4) export SUMMARY_QUARANTINE_STATUS="$_val" ;;
		esac
		_line=$((_line + 1))
	done <<< "$_summary"
	export SUMMARY_TOTAL_CLEANED="${tot_cl:-0}"
}

# _lmd_elk_post_hits manifest_file — post hits to ELK stack
# Posts each hit from the tab-delimited manifest to the configured ELK endpoint.
# shellcheck disable=SC2154
_lmd_elk_post_hits() {
	local manifest_file="$1"
	if [ "${enable_statistic:-0}" != "1" ] || [ -z "${elk_host:-}" ] || \
	   [ -z "${elk_port:-}" ] || [ -z "${curl:-}" ]; then
		return 0
	fi
	if [ ! -f "$manifest_file" ] || [ ! -s "$manifest_file" ]; then
		return 0
	fi

	local elk_url="${elk_host}:${elk_port}"
	if [ -n "${elk_index:-}" ]; then
		elk_url="${elk_url}/${elk_index}/message"
	fi
	local elk_date elk_hostname
	elk_date=$(date +%s)
	elk_hostname=$(hostname)

	local _sig _filepath _quarpath _hit_type _htcolor _htlabel
	while IFS=$'\t' read -r _sig _filepath _quarpath _hit_type _htcolor _htlabel; do
		[ -z "$_sig" ] && continue
		[ "$_quarpath" = "-" ] && _quarpath=""
		_sig=$(_alert_json_escape "$_sig")
		_filepath=$(_alert_json_escape "$_filepath")
		$curl --output /dev/null --silent --show-error \
			-XPOST "$elk_url" \
			-H 'Content-Type: application/json' \
			-d "{\"date\":\"$elk_date\",\"hit\":\"$_sig\",\"file\":\"$_filepath\",\"hostname\":\"$elk_hostname\"}"
	done < "$manifest_file"
}

# _lmd_render_entries template_file manifest_file total — render all entries in one awk pass
# Reads template into memory (first file), iterates manifest (second file),
# computes per-entry tokens (html/json escaping, quarantine status, type labels),
# substitutes {{TOKENS}} in the template, outputs rendered entries to stdout.
# Falls back to ENVIRON for tokens not in the per-entry set (supports global
# tokens in custom.d/ entry template overrides).
_lmd_render_entries() {
	local template_file="$1" manifest_file="$2" total="$3"
	if [ ! -f "$template_file" ] || [ ! -f "$manifest_file" ]; then
		return 0
	fi
	awk -F'\t' -v total="$total" -v SQ="'" '
	function html_escape(s) {
		gsub(/&/, "\\&amp;", s)
		gsub(/</, "\\&lt;", s)
		gsub(/>/, "\\&gt;", s)
		gsub(/"/, "\\&quot;", s)
		gsub(SQ, "\\&#39;", s)
		return s
	}
	function json_escape(s,    out, i, c, n) {
		out = ""
		n = length(s)
		for (i = 1; i <= n; i++) {
			c = substr(s, i, 1)
			if (c == "\\") out = out "\\\\"
			else if (c == "\"") out = out "\\\""
			else if (c == "\n") out = out "\\n"
			else if (c == "\t") out = out "\\t"
			else if (c == "\r") out = out "\\r"
			else out = out c
		}
		return out
	}
	NR == FNR {
		tpl[FNR] = $0
		tpl_lines = FNR
		next
	}
	{
		sig = $1; filepath = $2; quarpath = $3
		hit_type_color = $5; hit_type_label = $6
		if (sig == "") next
		if (quarpath == "-") quarpath = ""
		n++

		# Per-entry token map
		tokens["ENTRY_NUM"] = n
		tokens["ENTRY_TOTAL"] = total
		tokens["HIT_SIGNATURE"] = sig
		tokens["HIT_FILE"] = filepath
		tokens["HIT_TYPE"] = $4
		tokens["HIT_TYPE_LABEL"] = hit_type_label
		tokens["HIT_TYPE_COLOR"] = hit_type_color
		if (quarpath != "") {
			tokens["QUARANTINE_STATUS"] = "Quarantined"
			tokens["QUARANTINE_ENTRY_TEXT"] = " => " quarpath
			tokens["QUARANTINE_STATUS_HTML"] = "<span style=\"color:#16a34a;\">&#x2713; Quarantined</span>"
		} else {
			tokens["QUARANTINE_STATUS"] = "Not quarantined"
			tokens["QUARANTINE_ENTRY_TEXT"] = ""
			tokens["QUARANTINE_STATUS_HTML"] = "<span style=\"color:#dc2626;\">&#x2717; Not quarantined</span>"
		}
		tokens["HIT_FILE_HTML"] = html_escape(filepath)
		tokens["HIT_SIGNATURE_HTML"] = html_escape(sig)
		tokens["HIT_FILE_JSON"] = json_escape(filepath)
		tokens["HIT_SIGNATURE_JSON"] = json_escape(sig)

		# Render template with token substitution
		for (i = 1; i <= tpl_lines; i++) {
			line = tpl[i]
			while (match(line, /\{\{[A-Z_][A-Z0-9_]*\}\}/)) {
				token = substr(line, RSTART + 2, RLENGTH - 4)
				if (token in tokens) {
					val = tokens[token]
				} else {
					val = ENVIRON[token]
				}
				line = substr(line, 1, RSTART - 1) val substr(line, RSTART + RLENGTH)
			}
			print line
		}
	}
	' "$template_file" "$manifest_file"
}

# ---------------------------------------------------------------------------
# Rendering Pipeline
# ---------------------------------------------------------------------------

# _lmd_render format manifest_file alert_type template_dir — render report
# Renders header -> entries -> summary -> footer using the given format
# ("text" or "html") to select template filenames. Entry rendering uses a
# single-pass awk (_lmd_render_entries) for O(1) process forks regardless
# of hit count. Output goes to stdout.
# shellcheck disable=SC2154
_lmd_render() {
	local format="$1" manifest_file="$2" alert_type="$3" template_dir="$4"
	local total

	total=$(awk 'END{print NR}' "$manifest_file")

	_lmd_set_global_vars "$alert_type"

	# Compute summary before header — HTML headers embed summary data;
	# always compute even for single-hit reports (header needs the tokens)
	_lmd_compute_summary "$manifest_file"

	# Build scan result section for HTML — pre-render result-clean or
	# result-dirty template into SCAN_RESULT_HTML token for header embedding
	if [ "$format" = "html" ]; then
		if [ "$total" -eq 0 ]; then
			export THREAT_BADGE_HTML="<span style=\"display:inline-block;background-color:#16a34a;color:#ffffff;padding:2px 10px;border-radius:10px;font-weight:bold;font-family:'Courier New',Courier,monospace;\">&#x2713; All Clear</span>"
			_alert_tpl_resolve "$template_dir" "${alert_type}.${format}.result-clean.tpl"
		else
			export THREAT_BADGE_HTML="<span style=\"display:inline-block;background-color:#dc2626;color:#ffffff;padding:2px 10px;border-radius:10px;font-weight:bold;font-family:'Courier New',Courier,monospace;\">${total} threat(s)</span>"
			_alert_tpl_resolve "$template_dir" "${alert_type}.${format}.result-dirty.tpl"
		fi
		if [ -f "$_ALERT_TPL_RESOLVED" ]; then
			export SCAN_RESULT_HTML
			SCAN_RESULT_HTML=$(_alert_tpl_render "$_ALERT_TPL_RESOLVED")
		fi
	fi

	_alert_tpl_resolve "$template_dir" "${alert_type}.${format}.header.tpl"
	_alert_tpl_render "$_ALERT_TPL_RESOLVED"

	# Entry rendering: single-pass awk over manifest (O(1) forks)
	_alert_tpl_resolve "$template_dir" "${alert_type}.${format}.entry.tpl"
	_lmd_render_entries "$_ALERT_TPL_RESOLVED" "$manifest_file" "$total"

	# Text format: render summary at bottom for multi-hit reports
	# HTML format: summary content is already in the header, skip
	if [ "$total" -gt 1 ] && [ "$format" != "html" ]; then
		_alert_tpl_resolve "$template_dir" "${alert_type}.${format}.summary.tpl"
		if [ -f "$_ALERT_TPL_RESOLVED" ]; then
			_alert_tpl_render "$_ALERT_TPL_RESOLVED"
		fi
	fi

	_alert_tpl_resolve "$template_dir" "${alert_type}.${format}.footer.tpl"
	_alert_tpl_render "$_ALERT_TPL_RESOLVED"
}

# _lmd_render_text manifest_file alert_type template_dir — render text report
_lmd_render_text() {
	_lmd_render "text" "$@"
}

# _lmd_render_html manifest_file alert_type template_dir — render HTML report
_lmd_render_html() {
	_lmd_render "html" "$@"
}

# _lmd_render_messaging manifest_file subject template_dir [attachment]
# Builds per-entry blocks for each channel, computes summary, renders outer templates.
# Uses _lmd_render_entries for O(1) forks per channel regardless of hit count.
# Optional attachment is the scan report file for Slack/Telegram file uploads.
# shellcheck disable=SC2154
_lmd_render_messaging() {
	local manifest_file="$1" subject="$2" template_dir="$3" attachment="${4:-}"
	local _any_enabled=0 _ch
	for _ch in slack telegram discord; do
		if alert_channel_enabled "$_ch"; then
			_any_enabled=1; break
		fi
	done
	[ "$_any_enabled" = "1" ] || return 0

	local total
	total=$(awk 'END{print NR}' "$manifest_file")

	_lmd_set_global_vars "scan"

	# Build per-entry blocks for each channel — one awk pass each
	local _slack_blocks="" _telegram_blocks="" _discord_fields=""

	if alert_channel_enabled "slack"; then
		_alert_tpl_resolve "$template_dir" "slack.entry.tpl"
		if [ -f "$_ALERT_TPL_RESOLVED" ]; then
			_slack_blocks=$(_lmd_render_entries "$_ALERT_TPL_RESOLVED" "$manifest_file" "$total")
		fi
	fi

	if alert_channel_enabled "telegram"; then
		_alert_tpl_resolve "$template_dir" "telegram.entry.tpl"
		if [ -f "$_ALERT_TPL_RESOLVED" ]; then
			_telegram_blocks=$(_lmd_render_entries "$_ALERT_TPL_RESOLVED" "$manifest_file" "$total")
		fi
	fi

	if alert_channel_enabled "discord"; then
		_alert_tpl_resolve "$template_dir" "discord.entry.tpl"
		if [ -f "$_ALERT_TPL_RESOLVED" ]; then
			_discord_fields=$(_lmd_render_entries "$_ALERT_TPL_RESOLVED" "$manifest_file" "$total")
		fi
	fi

	# Compute summary for message templates — unconditional because
	# outer message templates reference SUMMARY_* tokens regardless of hit count
	_lmd_compute_summary "$manifest_file"

	# Export accumulated blocks for message templates
	export ENTRY_BLOCKS_SLACK="$_slack_blocks"
	export ENTRY_BLOCKS_TELEGRAM="$_telegram_blocks"
	export ENTRY_FIELDS_DISCORD="$_discord_fields"
	export SUBJECT="$subject"

	# Render and dispatch per channel
	local rc=0

	local _ch_err
	if alert_channel_enabled "slack"; then
		export ENTRY_BLOCKS="$_slack_blocks"
		_alert_tpl_resolve "$template_dir" "slack.message.tpl"
		if [ -f "$_ALERT_TPL_RESOLVED" ]; then
			local _slack_payload
			_slack_payload=$(mktemp "${tmpdir}/.slack_msg.XXXXXX")
			_alert_tpl_render "$_ALERT_TPL_RESOLVED" > "$_slack_payload"
			_ch_err=$(_alert_handle_slack "$subject" "$_slack_payload" "" "$attachment" 2>&1 1>/dev/null) || {
				eout "{alert} slack delivery failed${_ch_err:+: $_ch_err}"
				rc=1
			}
			rm -f "$_slack_payload"
		fi
	fi

	if alert_channel_enabled "telegram"; then
		export ENTRY_BLOCKS="$_telegram_blocks"
		_alert_tpl_resolve "$template_dir" "telegram.message.tpl"
		if [ -f "$_ALERT_TPL_RESOLVED" ]; then
			local _tg_payload
			_tg_payload=$(mktemp "${tmpdir}/.telegram_msg.XXXXXX")
			_alert_tpl_render "$_ALERT_TPL_RESOLVED" > "$_tg_payload"
			_ch_err=$(_alert_handle_telegram "$subject" "$_tg_payload" "" "$attachment" 2>&1 1>/dev/null) || {
				eout "{alert} telegram delivery failed${_ch_err:+: $_ch_err}"
				rc=1
			}
			rm -f "$_tg_payload"
		fi
	fi

	if alert_channel_enabled "discord"; then
		export ENTRY_FIELDS="$_discord_fields"
		_alert_tpl_resolve "$template_dir" "discord.message.tpl"
		if [ -f "$_ALERT_TPL_RESOLVED" ]; then
			local _dc_payload
			_dc_payload=$(mktemp "${tmpdir}/.discord_msg.XXXXXX")
			_alert_tpl_render "$_ALERT_TPL_RESOLVED" > "$_dc_payload"
			_ch_err=$(_alert_handle_discord "$subject" "$_dc_payload" "" "$attachment" 2>&1 1>/dev/null) || {
				eout "{alert} discord delivery failed${_ch_err:+: $_ch_err}"
				rc=1
			}
			rm -f "$_dc_payload"
		fi
	fi

	return $rc
}
