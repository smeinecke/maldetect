#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck disable=SC1090,SC1091
##
# Linux Malware Detect v2.0.1
#             (C) 2002-2026, R-fx Networks <proj@rfxn.com>
#             (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
# Configuration import and validation functions

# Source guard
[[ -n "${_LMD_CONFIG_LOADED:-}" ]] && return 0 2>/dev/null
_LMD_CONFIG_LOADED=1

# shellcheck disable=SC2034
LMD_CONFIG_VERSION="1.0.0"

detect_control_panel() {
	if [[ -d /usr/local/interworx ]]; then
		iworx_db_ps=$(ps -u iworx | grep iworx-db)
		iworx_web_ps=$(ps -u iworx-web | grep iworx-web)
		pex_script=$(readlink -e /usr/local/interworx/bin/listaccounts.pex)
		siteworx=$(command -v siteworx)

		# Check that Iworx services are running
		if [[ -z "$iworx_db_ps" || -z "$iworx_web_ps" ]]; then
			control_panel="error"
			eout "{panel} Interworx found, but not running. Panel user alerts will not be sent."
		# Verify pex script exists and is executable
		elif ! [[ -x "$pex_script" ]]; then
			control_panel="error"
			eout "{panel} Interworx found, but scripts are missing or not executable. Panel user alerts will not be sent."
		# Ensure /usr/bin/siteworx is executable
		elif ! [[ -x "$siteworx" ]]; then
			control_panel="error"
			eout "{panel} Interworx found, but Siteworx CLI is missing or not executable. Panel user alerts will not be sent."
		else
			control_panel="interworx"
		fi
	elif [[ -d /usr/local/cpanel ]]; then
		cpanel_ps=$(ps -u root | grep [c]psrvd)
		cpapi=$(command -v cpapi2)
		apitool=$(readlink -e ${cpapi})

		# Ensure cpanel service is running
		if [[ -z ${cpanel_ps} ]]; then
			control_panel="error"
			eout "{panel} cPanel found, but services are not running. Panel user alerts will not be sent."
		# Verify apitool is executable
		elif ! [[ -x ${apitool} ]]; then
			control_panel="error"
			eout "{panel} cPanel found, but apitool is missing or not found. Panel user alerts will not be sent."
		else
			control_panel="cpanel"
		fi
	else
		control_panel="unknown"
	fi
}

get_panel_contacts() {
	local panel="$1"
	local user="$2"
	case "$panel" in
		"cpanel")
			if [ -f /var/cpanel/users/${user} ]; then
				contact_emails=$(awk -F '=' '/^CONTACTEMAIL/{print $2}'  /var/cpanel/users/${user} | sed '/^ *$/d' | tr '\n' ',' | sed 's/,$//')
			else
				contact_emails=$(cpapi2 --user=${user} --output=xml CustInfo contactemails | grep -o 'value>.*</value' | sed -E 's,(</)?value>?,,g;/^$/d' | tr '\n' ',' | sed 's/,$//')
			fi
		;;
		"interworx")
			master_domain=$(/usr/local/interworx/bin/listaccounts.pex | grep "${user}" | awk '{print $2}')
			if [ -n "$master_domain" ]; then
				# Parse siteworx JSON output with awk (portable, no python dependency)
				# Accumulates email+user_status per object, prints at } boundary;
				# handles any field ordering in both compact and formatted JSON
				contact_emails=$(siteworx -un --login_domain "${master_domain}" -c Users -a listUsers -o json | \
					awk -F'"' '
						/"user_status"/ { for (i=1; i<=NF; i++) if ($i == "user_status") { ustatus=$(i+2); break } }
						/"email"/ { for (i=1; i<=NF; i++) if ($i == "email") { em=$(i+2); break } }
						/\}/ { if (ustatus == "active" && em != "") printf "%s,", em; ustatus=""; em="" }
					' | sed 's/,$//')
			fi
		;;
	esac
}

_grf_tmpfiles=()
_grf_cleanup() {
	# Remove temp files created by get_remote_file() calls without save_path
	local _f
	for _f in "${_grf_tmpfiles[@]}"; do
		[ -f "$_f" ] && command rm -f "$_f"
	done
	_grf_tmpfiles=()
}

get_remote_file() {
	# $1 = URI, $2 = local service identifier, $3 boolean verbose
	local get_uri="$1"
	local service="$2"
	local verbose="$3"
	local save_path="$4"
	local grf_svc get_type get_bin get_opts get_output_arg get_proxy_arg
	local get_file id tmpf
	unset return_file
	if [ "$hscan" ]; then
		unset verbose
	fi
	if [ -z "$get_uri" ]; then
		eout "{internal} missing or invalid URI passed to get_remote_file()" 1
		return 1
	fi
	if [ -z "$service" ]; then
		grf_svc="internal"
	else
		grf_svc="$service"
	fi

	if [ -n "$curl" ]; then
		get_type="curl"
		get_bin="$curl"
	elif [ -n "$wget" ]; then
		get_type="wget"
		get_bin="$wget"
	else
		eout "{internal} could not find curl or wget binaries for remote file downloads, fatal error!"
		exit 1
	fi

	if [ "$lmd_referer" ] && [ "$get_type" == "curl" ]; then
		id="--referer ${lmd_referer}:curl"
	elif [ "$lmd_referer" ] && [ "$get_type" == "wget" ]; then
		id="--referer=${lmd_referer}:wget"
	fi

	if [ "$get_type" == "curl" ]; then
		if [ "$web_proxy" ]; then
			get_proxy_arg="-x http://$web_proxy"
		fi
		get_opts="-sf $get_proxy_arg --connect-timeout $remote_uri_timeout --retry $remote_uri_retries $id"
		get_output_arg='-o'
	elif [ "$get_type" == "wget" ]; then
		if [ "$web_proxy" ]; then
			get_proxy_arg="-e http_proxy=$web_proxy -e https_proxy=$web_proxy"
		fi
		get_opts="-q $get_proxy_arg --timeout=$remote_uri_timeout --tries=$remote_uri_retries $id"
		get_output_arg='-O'
	fi

	if [ "$save_path" ]; then
		tmpf="$save_path"
	else
		tmpf=$(mktemp "$tmpdir/.tmpf_get.XXXXXX")
		chmod 600 "$tmpf"
		_grf_tmpfiles+=("$tmpf")
		get_file=$(echo "$get_uri" | tr '/' '\n' | tail -n1)
	fi

	$get_bin $get_opts "$get_uri" $get_output_arg "$tmpf" || true  # safe: download failure is non-fatal; file existence check below handles it

	if [ ! -f "$tmpf" ] || [ ! -s "$tmpf" ]; then
		eout "{$grf_svc} could not download $get_uri, please try again later." $verbose
		unset return_file
	else
		eout "{$grf_svc} downloaded $get_uri"
		return_file="$tmpf"
	fi

}

import_user_sigs() {
	if [ "$sig_import_md5_url" ]; then
		get_remote_file "$sig_import_md5_url" "importsigs" "1"
		if [ -f "$return_file" ]; then
			cp -f "$return_file" "$sig_user_md5_file"
			eout "{importsigs} imported custom signature data from $sig_import_md5_url"
		fi
	fi
	if [ "$sig_import_hex_url" ]; then
		get_remote_file "$sig_import_hex_url" "importsigs" "1"
		if [ -f "$return_file" ]; then
			cp -f "$return_file" "$sig_user_hex_file"
			eout "{importsigs} imported custom signature data from $sig_import_hex_url"
		fi
	fi
	if [ "$sig_import_yara_url" ]; then
		get_remote_file "$sig_import_yara_url" "importsigs" "1"
		if [ -f "$return_file" ]; then
			local yara_valid=1
			if [ -n "$yr" ] && [ -f "$yr" ]; then
				"$yr" check "$return_file" > /dev/null 2>&1 || yara_valid=0
			elif [ -n "$yara" ] && [ -f "$yara" ]; then
				"$yara" "$return_file" /dev/null > /dev/null 2>&1 || yara_valid=0
			fi
			if [ "$yara_valid" == "1" ]; then
				cp -f "$return_file" "$sig_user_yara_file"
				eout "{importsigs} imported custom YARA rules from $sig_import_yara_url"
			else
				eout "{importsigs} WARNING: downloaded YARA rules from $sig_import_yara_url failed syntax check, skipping import"
			fi
		fi
	fi
	if [ "$sig_import_sha256_url" ]; then
		get_remote_file "$sig_import_sha256_url" "importsigs" "1"
		if [ -f "$return_file" ]; then
			cp -f "$return_file" "$sig_user_sha256_file"
			eout "{importsigs} imported custom SHA-256 signature data from $sig_import_sha256_url"
		fi
	fi
	if [ "$sig_import_csig_url" ]; then
		get_remote_file "$sig_import_csig_url" "importsigs" "1"
		if [ -f "$return_file" ]; then
			cp -f "$return_file" "$sig_user_csig_file"
			eout "{importsigs} imported custom compound signature data from $sig_import_csig_url"
		fi
	fi
	_grf_cleanup
}

_safe_source_conf() {
	# Parse a remote config file safely, accepting only known conf.maldet
	# variable names. Uses a TRUE ALLOWLIST -- any variable not listed here
	# is rejected, preventing override of internal path vars (inspath,
	# sigdir, cldir, etc.) via compromised import_config_url.
	# MAINTENANCE: when adding new variables to conf.maldet, also add them
	# to _ssc_allowed_pat below.
	local _ssc_file="$1"
	local _ssc_line _ssc_var _ssc_val
	# Allowlist: every user-facing variable defined in conf.maldet.
	# Organized by section to ease maintenance.
	local _ssc_allowed_pat
	_ssc_allowed_pat='^(email_alert|email_addr|email_ignore_clean|email_subj'
	_ssc_allowed_pat="${_ssc_allowed_pat}|email_panel_user_alerts|email_panel_from|email_panel_replyto|email_panel_alert_subj"
	_ssc_allowed_pat="${_ssc_allowed_pat}|email_format|smtp_relay|smtp_from|smtp_user|smtp_pass"
	_ssc_allowed_pat="${_ssc_allowed_pat}|slack_alert|slack_subj|slack_token|slack_channels"
	_ssc_allowed_pat="${_ssc_allowed_pat}|telegram_alert|telegram_file_caption|telegram_bot_token|telegram_channel_id"
	_ssc_allowed_pat="${_ssc_allowed_pat}|discord_alert|discord_webhook_url"
	_ssc_allowed_pat="${_ssc_allowed_pat}|autoupdate_signatures|autoupdate_version|autoupdate_version_hashed|sigup_interval"
	_ssc_allowed_pat="${_ssc_allowed_pat}|cron_prune_days|cron_daily_scan|scan_days"
	_ssc_allowed_pat="${_ssc_allowed_pat}|import_config_url|import_config_expire"
	_ssc_allowed_pat="${_ssc_allowed_pat}|sig_import_md5_url|sig_import_hex_url|sig_import_yara_url|sig_import_sha256_url|sig_import_csig_url"
	_ssc_allowed_pat="${_ssc_allowed_pat}|scan_hashtype|scan_workers|scan_clamscan|scan_yara|scan_yara_timeout|scan_yara_scope|scan_csig"
	_ssc_allowed_pat="${_ssc_allowed_pat}|scan_user_access|scan_user_access_minuid|scan_max_depth"
	_ssc_allowed_pat="${_ssc_allowed_pat}|scan_min_filesize|scan_max_filesize|scan_hexdepth"
	_ssc_allowed_pat="${_ssc_allowed_pat}|scan_cpunice|scan_ionice|scan_cpulimit"
	_ssc_allowed_pat="${_ssc_allowed_pat}|scan_ignore_root|scan_ignore_user|scan_ignore_group"
	_ssc_allowed_pat="${_ssc_allowed_pat}|scan_find_timeout|scan_export_filelist|scan_tmpdir_paths"
	_ssc_allowed_pat="${_ssc_allowed_pat}|quarantine_hits|quarantine_clean|quarantine_on_error"
	_ssc_allowed_pat="${_ssc_allowed_pat}|quarantine_suspend_user|quarantine_suspend_user_minuid"
	_ssc_allowed_pat="${_ssc_allowed_pat}|default_monitor_mode|inotify_base_watches|inotify_sleep|inotify_reloadtime"
	_ssc_allowed_pat="${_ssc_allowed_pat}|inotify_minuid|inotify_docroot|inotify_cpunice|inotify_ionice"
	_ssc_allowed_pat="${_ssc_allowed_pat}|inotify_cpulimit|inotify_verbose"
	_ssc_allowed_pat="${_ssc_allowed_pat}|digest_interval|digest_escalate_hits|monitor_paths_extra"
	_ssc_allowed_pat="${_ssc_allowed_pat}|scan_clamd_remote|remote_clamd_config|remote_clamd_max_retry|remote_clamd_retry_sleep"
	_ssc_allowed_pat="${_ssc_allowed_pat}|enable_statistic|elk_host|elk_port|elk_index"
	_ssc_allowed_pat="${_ssc_allowed_pat}|string_length_scan|string_length"
	_ssc_allowed_pat="${_ssc_allowed_pat}|session_legacy_compat"
	_ssc_allowed_pat="${_ssc_allowed_pat})\$"
	while IFS= read -r _ssc_line || [ -n "$_ssc_line" ]; do
		# Skip blank lines and comments
		case "$_ssc_line" in
			''|\#*) continue ;;
		esac
		# Must match: VARNAME=value
		if [[ "$_ssc_line" =~ ^[a-zA-Z_][a-zA-Z0-9_]*= ]]; then
			_ssc_var="${_ssc_line%%=*}"
			_ssc_val="${_ssc_line#*=}"
			# Strip surrounding quotes
			case "$_ssc_val" in
				\"*\") _ssc_val="${_ssc_val#\"}"; _ssc_val="${_ssc_val%\"}" ;;
				\'*\') _ssc_val="${_ssc_val#\'}"; _ssc_val="${_ssc_val%\'}" ;;
			esac
			# Reject values containing shell metacharacters
			case "$_ssc_val" in
				*'$'*|*'`'*|*';'*|*'|'*|*'&'*|*'('*|*')'*)
					eout "{importconf} WARNING: rejected unsafe line in remote config: $_ssc_var"
					continue
					;;
			esac
			# Allowlist check: only accept known conf.maldet variables
			if ! [[ "$_ssc_var" =~ $_ssc_allowed_pat ]]; then
				eout "{importconf} WARNING: rejected unknown variable in remote config: $_ssc_var"
				continue
			fi
			printf -v "$_ssc_var" '%s' "$_ssc_val"
		else
			eout "{importconf} WARNING: skipped non-assignment line in remote config"
		fi
	done < "$_ssc_file"
}

import_conf() {
	current_utime=$(date +"%s")
	if [ -z "$import_config_expire" ]; then
		import_config_expire=43200
	fi
	if [ -f "$sessdir/.import_conf.utime" ]; then
		import_utime=$(cat "$sessdir/.import_conf.utime")
		if [ -z "$import_utime" ]; then
			import_utime="0"
		fi
		import_diff=$((current_utime-import_utime))
		if [ "$import_diff" -lt "$import_config_expire" ]; then
			import_config_skip="1"
			eout "{importconf} configuration expire value has not lapsed (${import_diff}/${import_config_expire}), using cache."
			import_conf_cached=1
		fi
	fi
	if [ "$import_config_url" ]; then
		if [ -z "$import_config_skip" ]; then
			get_remote_file "$import_config_url" "importconf" "1"
			if [ -f "$return_file" ]; then
				cp -f "$return_file" "$sessdir/.import_conf.cache"
				echo "$current_utime" > "$sessdir/.import_conf.utime"
			fi
		fi
		if [ -f "$sessdir/.import_conf.cache" ]; then
			if [ -z "$_lmd_cli_co_applied" ]; then # skip re-source when CLI -co overrides are active — re-sourcing would discard them
				source "$intcnf"
				source "$cnf"
			fi
			_safe_source_conf "$sessdir/.import_conf.cache"
			if [ "$import_conf_cached" ]; then
				eout "{importconf} imported configuration from $import_config_url (cached)"
			else
				eout "{importconf} imported configuration from $import_config_url"
			fi
			if [ -f "$compatcnf" ]; then
				source "$compatcnf"
			fi
			if [ -f "$syscnf" ]; then
				source "$syscnf"
			fi
		fi
	fi
	_grf_cleanup
}
