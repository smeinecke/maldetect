#!/usr/bin/env bash
#
##
# Linux Malware Detect v2.0.1
#             (C) 2002-2026, R-fx Networks <proj@rfxn.com>
#             (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#
PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
lmd_version="2.0.1"
inspath=/usr/local/maldetect
logf=$inspath/logs/event_log

# Source shared packaging library
PKG_BACKUP_SYMLINK="maldetect.last"
PKG_BACKUP_PRUNE_DAYS="30"
# shellcheck disable=SC1091
source files/internals/pkg_lib.sh

# --- ClamAV integration (LMD-specific) ---

clamav_linksigs() {
	local cpath="$1"
	if [ -d "$cpath" ]; then
		rm -f "$cpath"/rfxn.{hdb,ndb,yara,hsb} 2>/dev/null
		cp -f "$inspath/sigs/rfxn.ndb" "$inspath/sigs/rfxn.hdb" "$inspath/sigs/rfxn.yara" "$cpath/" 2>/dev/null
		[ -f "$inspath/sigs/rfxn.hsb" ] && [ -s "$inspath/sigs/rfxn.hsb" ] && \
			command cp -f "$inspath/sigs/rfxn.hsb" "$cpath"/ 2>/dev/null
		rm -f "$cpath"/lmd.user.* 2>/dev/null
		[ -s "$inspath/sigs/lmd.user.ndb" ] && command cp -f "$inspath/sigs/lmd.user.ndb" "$cpath"/ 2>/dev/null
		[ -s "$inspath/sigs/lmd.user.hdb" ] && command cp -f "$inspath/sigs/lmd.user.hdb" "$cpath"/ 2>/dev/null
		[ -s "$inspath/sigs/lmd.user.hsb" ] && command cp -f "$inspath/sigs/lmd.user.hsb" "$cpath"/ 2>/dev/null
	fi
}

clamav_paths="/usr/local/cpanel/3rdparty/share/clamav/ /var/lib/clamav/ /var/clamav/ /usr/share/clamav/ /usr/local/share/clamav"

# --- Core file installation (silent — no user output) ---

_install_core() {
	pkg_copy_tree "files" "$inspath"
	chmod 755 "$inspath"
	chmod 755 "$inspath/maldet"
	chmod 640 "$inspath/conf.maldet"
	test -f "$inspath/conf.maldet.hookscan" && chmod 640 "$inspath/conf.maldet.hookscan"
	pkg_create_dirs 750 "$inspath/clean" "$inspath/pub" "$inspath/quarantine" \
		"$inspath/sess" "$inspath/sigs" "$inspath/tmp"
	chmod 750 "$inspath/logs" "$inspath/internals/tlog" "$inspath/internals/alert" 2>/dev/null
	chmod 750 "$inspath/internals/tlog_lib.sh" "$inspath/internals/alert_lib.sh" \
		"$inspath/internals/elog_lib.sh" "$inspath/internals/pkg_lib.sh" 2>/dev/null
	# Sub-library permissions (decomposed from functions monolith)
	chmod 750 "$inspath/internals/lmd.lib.sh"
	# shellcheck disable=SC2086
	chmod 750 "$inspath/internals"/lmd_*.sh 2>/dev/null
	# shellcheck disable=SC2086
	chmod 640 "$inspath/internals/alert/"* 2>/dev/null
	# tlog: replace default BASERUN for cursor storage security
	sed -i "s|BASERUN=\"\${BASERUN:-/tmp}\"|BASERUN=\"\${BASERUN:-$inspath/tmp}\"|" "$inspath/internals/tlog"
	pkg_symlink "$inspath/maldet" /usr/local/sbin/maldet
	pkg_symlink "$inspath/maldet" /usr/local/sbin/lmd
	cp -f CHANGELOG COPYING.GPL README "$inspath/"
	# Man page: compress in-place at install path, then symlink to system dir
	mkdir -p /usr/local/share/man/man1/
	gzip -9 "$inspath/maldet.1"
	pkg_symlink "$inspath/maldet.1.gz" /usr/local/share/man/man1/maldet.1.gz
	# Create empty custom sig files if absent (upgrade path: prior versions lack them)
	[ -f "$inspath/sigs/custom.sha256.dat" ] || touch "$inspath/sigs/custom.sha256.dat"
	[ -f "$inspath/sigs/custom.csig.dat" ] || touch "$inspath/sigs/custom.csig.dat"
	for lp in $clamav_paths; do
		clamav_linksigs "$lp"
	done
	killall -SIGUSR2 clamd 2>/dev/null  # safe: signal ClamAV to reload sigs
}

_read_conf_value() {
	# Read a single variable value from conf.maldet.
	# Handles both quoted (var="val") and unquoted (var=val) formats.
	# Arg 1: variable name (e.g., sigup_interval)
	# Arg 2: default value if not found
	# Output: value on stdout
	local _var="$1" _default="${2:-}"
	local _val="$_default"
	if [ -f "$inspath/conf.maldet" ]; then
		_val=$(grep -m1 "^${_var}=" "$inspath/conf.maldet" \
			| command sed "s/^${_var}="'"\{0,1\}\([^"]*\)"\{0,1\}/\1/' 2>/dev/null)
		_val="${_val:-$_default}"
	fi
	echo "$_val"
}

# --- Cron & service installation ---

_install_cron_service() {
	pkg_cron_install cron.daily /etc/cron.daily/maldet
	pkg_cron_install cron.watchdog /etc/cron.weekly/maldet-watchdog
	pkg_cron_install cron.d.pub /etc/cron.d/maldet_pub

	# Independent sig update cron (sigup_interval, default 6h)
	# Source installed conf.maldet to read sigup_interval — conf is already
	# copied by _install_core() which runs before _install_cron_service().
	# On upgrade, user's custom value is not yet imported (that happens in
	# _import_config), so the default 6 is used. User changes to
	# sigup_interval take effect on next install.sh run.
	local _sigup_interval
	_sigup_interval=$(_read_conf_value "sigup_interval" "6")
	if [ "$_sigup_interval" != "0" ] && [ "$_sigup_interval" -gt 0 ] 2>/dev/null; then
		pkg_cron_install cron.d.sigup /etc/cron.d/maldet-sigup
		# Replace default interval with configured value
		if [ "$_sigup_interval" != "6" ]; then
			command sed -i "s|\\*/6|\\*/$_sigup_interval|g" /etc/cron.d/maldet-sigup
		fi
	else
		# sigup_interval=0: remove cron file if present (upgrade path)
		command rm -f /etc/cron.d/maldet-sigup 2>/dev/null
	fi

	if [ "$(uname -s)" != "FreeBSD" ]; then
		pkg_detect_os
		_init_system=$(cat /proc/1/comm 2>/dev/null)
		if test "$_init_system" == "systemd"; then
			pkg_service_install maldet ./files/service/maldet.service
			systemctl enable maldet.service 2>/dev/null  # safe: idempotent
		else
			pkg_service_install maldet ./files/service/maldet.sh
			if [ "$_PKG_OS_FAMILY" = "rhel" ] && command -v chkconfig >/dev/null 2>&1; then
				chkconfig --level 2345 maldet on
			fi
		fi
		# Read old default_monitor_mode for migration (applied after sysconfig install)
		_old_dmm=""
		if [ -n "${bkpath:-}" ] && [ -f "$bkpath/conf.maldet" ]; then
			_old_dmm=$(grep '^default_monitor_mode=' "$bkpath/conf.maldet" 2>/dev/null | tail -1 | sed 's/^default_monitor_mode=//' | tr -d '"')
		fi
		# Install sysconfig/default override file
		if [ "$_PKG_OS_FAMILY" = "rhel" ]; then
			if [ ! -f "/etc/sysconfig/maldet" ]; then
				cp -f ./files/service/maldet.sysconfig /etc/sysconfig/maldet
			fi
		elif [ "$_PKG_OS_FAMILY" = "debian" ]; then
			if [ ! -f "/etc/default/maldet" ]; then
				cp -f ./files/service/maldet.sysconfig /etc/default/maldet
			fi
			if [ "$_init_system" != "systemd" ]; then
				update-rc.d -f maldet remove
				update-rc.d maldet defaults 70 30
			fi
		elif [ "$_PKG_OS_FAMILY" = "gentoo" ]; then
			if [ "$_init_system" != "systemd" ]; then
				rc-update add maldet default
			fi
		elif [ "$_PKG_OS_FAMILY" = "slackware" ]; then
			if [ "$_init_system" != "systemd" ]; then
				# Slackware uses /etc/rc.d/rc.NAME; executable scripts are auto-started by rc.M
				ln -sf /etc/init.d/maldet /etc/rc.d/rc.maldet
				chmod +x /etc/rc.d/rc.maldet 2>/dev/null  # safe: symlink may point to newly installed init script
			fi
		else
			if [ ! -f "/etc/sysconfig/maldet" ]; then
				cp -f ./files/service/maldet.sysconfig /etc/sysconfig/maldet 2>/dev/null  # safe: dir may not exist
			fi
		fi
		# Apply default_monitor_mode migration now that sysconfig file is guaranteed to exist
		if [ -n "${_old_dmm:-}" ] && [ "$_old_dmm" != "users" ]; then
			for _scf in /etc/sysconfig/maldet /etc/default/maldet; do
				if [ -f "$_scf" ]; then
					if grep -q '^MONITOR_MODE=' "$_scf"; then
						sed -i "s|^MONITOR_MODE=.*|MONITOR_MODE=\"$_old_dmm\"|" "$_scf"
					else
						echo "MONITOR_MODE=\"$_old_dmm\"" >> "$_scf"
					fi
					break
				fi
			done
		fi
		unset _old_dmm
		unset _init_system
	fi

	# Log setup
	mkdir -p "$inspath/logs" && touch "$logf"
	pkg_symlink "$logf" "$inspath/event_log"
	"$inspath/maldet" --alert-daily 2>/dev/null  # safe: primes digest state; no-op if no monitor running
}

# --- Installation summary ---

_postinfo() {
	echo ""
	pkg_item "Install path" "$inspath"
	pkg_item "Config file" "$inspath/conf.maldet"
	pkg_item "Exec file" "$inspath/maldet"
	pkg_item "Exec link" "/usr/local/sbin/maldet"
	pkg_item "Exec link" "/usr/local/sbin/lmd"
	pkg_item "Cron.daily" "/etc/cron.daily/maldet"
}

# --- Config import on upgrade ---

# _compat_migrate old_conf merged_conf old_var new_var
# Migrate a renamed config variable from old backup into merged output.
# Only migrates if: old_var present and non-empty in old_conf,
# AND new_var NOT present (or empty) in old_conf (user hasn't already migrated).
# Mirrors compat.conf semantics: [ ! "$new_var" ] && [ "$old_var" ]
_compat_migrate() {
	local _old_conf="$1" _merged="$2" _old_var="$3" _new_var="$4"
	local _val
	# Skip if user's old config already has the new variable name with a non-empty value.
	# pkg_config_get returns 0 with empty output for VAR=""; treat empty as
	# "not set" to match compat.conf's [ ! "$new_var" ] semantics.
	_val=$(pkg_config_get "$_old_conf" "$_new_var") && [[ -n "$_val" ]] && return 0
	# Read old variable value; skip if absent from old config
	_val=$(pkg_config_get "$_old_conf" "$_old_var") || return 0
	# Guard: skip empty values to avoid overwriting real defaults
	[[ -n "$_val" ]] || return 0
	# Apply old value to new variable name in merged output
	pkg_config_set "$_merged" "$_new_var" "$_val"
}

_import_config() {
	local _old_conf="${bkpath:-}/conf.maldet"
	[ -f "$_old_conf" ] || return 0

	local _merge_tmp
	_merge_tmp=$(mktemp "${PKG_TMPDIR:-/tmp}/lmd-conf-merge.XXXXXX")
	trap 'rm -f "$_merge_tmp"' RETURN  # cleanup on any exit path

	# AWK merge: old user values into new template structure
	pkg_config_merge "$_old_conf" "files/conf.maldet" "$_merge_tmp" || {
		pkg_warn "config merge failed, using new defaults"
		return 0
	}

	# Standard compat migrations: renamed user-facing config variables.
	# Only variables present in conf.maldet need install-time migration.
	# Internal vars (sig paths, version URLs) handled at runtime by compat.conf.
	_compat_migrate "$_old_conf" "$_merge_tmp" suppress_cleanhit email_ignore_clean
	_compat_migrate "$_old_conf" "$_merge_tmp" quar_clean quarantine_clean
	_compat_migrate "$_old_conf" "$_merge_tmp" quar_hits quarantine_hits
	_compat_migrate "$_old_conf" "$_merge_tmp" quar_susp quarantine_suspend_user
	_compat_migrate "$_old_conf" "$_merge_tmp" quar_susp_minuid quarantine_suspend_user_minuid
	_compat_migrate "$_old_conf" "$_merge_tmp" maxdepth scan_max_depth
	_compat_migrate "$_old_conf" "$_merge_tmp" minfilesize scan_min_filesize
	_compat_migrate "$_old_conf" "$_merge_tmp" maxfilesize scan_max_filesize
	_compat_migrate "$_old_conf" "$_merge_tmp" hexdepth scan_hexdepth
	_compat_migrate "$_old_conf" "$_merge_tmp" clamav_scan scan_clamscan
	_compat_migrate "$_old_conf" "$_merge_tmp" tmpdir_paths scan_tmpdir_paths
	_compat_migrate "$_old_conf" "$_merge_tmp" public_scan scan_user_access
	_compat_migrate "$_old_conf" "$_merge_tmp" pubuser_minuid scan_user_access_minuid
	_compat_migrate "$_old_conf" "$_merge_tmp" scan_nice scan_cpunice
	_compat_migrate "$_old_conf" "$_merge_tmp" inotify_stime inotify_sleep
	_compat_migrate "$_old_conf" "$_merge_tmp" inotify_webdir inotify_docroot
	_compat_migrate "$_old_conf" "$_merge_tmp" inotify_nice inotify_cpunice
	_compat_migrate "$_old_conf" "$_merge_tmp" import_custsigs_md5_url sig_import_md5_url
	_compat_migrate "$_old_conf" "$_merge_tmp" import_custsigs_hex_url sig_import_hex_url
	_compat_migrate "$_old_conf" "$_merge_tmp" import_custsigs_yara_url sig_import_yara_url
	_compat_migrate "$_old_conf" "$_merge_tmp" import_custsigs_sha256_url sig_import_sha256_url
	_compat_migrate "$_old_conf" "$_merge_tmp" import_custsigs_csig_url sig_import_csig_url

	# Special case: scan_hexfifo consolidation (v2.0.1)
	# Old scan_hexfifo + scan_hexfifo_depth are consolidated into scan_hexdepth.
	# First migrate the pre-1.5 intermediate names if present:
	_compat_migrate "$_old_conf" "$_merge_tmp" hex_fifo_scan scan_hexfifo
	_compat_migrate "$_old_conf" "$_merge_tmp" hex_fifo_depth scan_hexfifo_depth
	# Then, if hexfifo was enabled, propagate its depth to scan_hexdepth:
	local _hexfifo_val _hexfifo_depth
	_hexfifo_val=$(pkg_config_get "$_old_conf" scan_hexfifo 2>/dev/null) || \
		_hexfifo_val=$(pkg_config_get "$_old_conf" hex_fifo_scan 2>/dev/null) || \
		_hexfifo_val=""  # safe: suppress "not found" when var absent from old config
	if [[ "${_hexfifo_val:-0}" = "1" ]]; then
		_hexfifo_depth=$(pkg_config_get "$_old_conf" scan_hexfifo_depth 2>/dev/null) || \
			_hexfifo_depth=$(pkg_config_get "$_old_conf" hex_fifo_depth 2>/dev/null) || \
			_hexfifo_depth=""  # safe: suppress "not found" when var absent from old config
		if [[ -n "$_hexfifo_depth" ]]; then
			pkg_config_set "$_merge_tmp" scan_hexdepth "$_hexfifo_depth"
		fi
	fi

	# Special case: scan_hex_workers -> scan_workers (unconditional, v2.0.1)
	# conf.maldet defaults scan_workers="0", so standard _compat_migrate would
	# see new_var in merged output and skip. This override is unconditional:
	# if old config had scan_hex_workers set, it always overrides scan_workers.
	local _hex_workers
	_hex_workers=$(pkg_config_get "$_old_conf" scan_hex_workers 2>/dev/null) || \
		_hex_workers=""  # safe: suppress "not found" when var absent from old config
	if [[ -n "$_hex_workers" ]]; then
		pkg_config_set "$_merge_tmp" scan_workers "$_hex_workers"
	fi

	# Install merged config
	command mv -f "$_merge_tmp" "$inspath/conf.maldet"
	chmod 640 "$inspath/conf.maldet"  # restore restrictive perms — conf contains credentials
	pkg_info "imported config options from ${_old_conf}"
}

# --- Restart monitor if it was running ---

_restart_monitor() {
	if [ "${monmode:-}" == "1" ]; then
		pkg_info "NOTE: monitor process uses legacy forking model; restart to use new supervisor mode"
		if pkg_is_systemd && systemctl is-enabled maldet.service >/dev/null 2>&1; then
			pkg_info "restarting monitor via systemctl"
			systemctl restart maldet.service >>/dev/null 2>&1 &
		else
			pkg_info "restarting monitor with '-b -m users'"
			"$inspath/maldet" -b -m users >>/dev/null 2>&1 &
		fi
	fi
}

# ══════════════════════════════════════════════════════════════════
# Main: fresh install vs upgrade
# ══════════════════════════════════════════════════════════════════

if [ -d "$inspath" ] && [ -d "files" ]; then
	# --- Upgrade path ---
	pkg_header "Linux Malware Detect" "$lmd_version" "upgrade"
	echo "            (C) 2002-2026, R-fx Networks <proj@rfxn.com>"
	echo "            (C) 2026, Ryan MacDonald <ryan@rfxn.com>"
	echo "This program may be freely redistributed under the terms of the GNU GPL v2"

	# Stop active monitor before backup
	if [ "$(ps -A --user root -o "command" 2>/dev/null | grep maldetect | grep inotifywait)" ]; then
		"$inspath/maldet" -k >>/dev/null 2>&1
		monmode=1
	fi

	pkg_section "Backing up existing installation"
	# One-time: prune old-format backups from pre-pkg_lib installations
	find "$(dirname "$inspath")" -maxdepth 1 -name "$(basename "$inspath").bk*" -type d -mtime +"$PKG_BACKUP_PRUNE_DAYS" -exec rm -rf {} + 2>/dev/null || true  # safe: old .bk* dirs may not exist
	# Prune new-format backups
	pkg_backup_prune "$inspath" "$PKG_BACKUP_PRUNE_DAYS"
	# Remove chattr locks before backup
	if command -v chattr >/dev/null 2>&1; then
		chattr -ia "$inspath/internals/internals.conf"
	fi
	# Create backup (move method — removes original)
	if ! pkg_backup "$inspath" "move"; then
		pkg_error "failed to backup $inspath, aborting install."
		exit 1
	fi
	# Resolve backup path for restore operations
	bkpath=$(pkg_backup_path "$inspath")

	pkg_section "Installing files"
	_install_core
	# Restore user data from backup
	# shellcheck disable=SC2086
	cp -f "$bkpath"/ignore_* "$inspath/" >>/dev/null 2>&1  # safe: glob may match nothing
	# shellcheck disable=SC2086
	cp -f "$bkpath"/sess/* "$inspath/sess/" >>/dev/null 2>&1  # safe: dir may be empty
	# shellcheck disable=SC2086
	cp -f "$bkpath"/tmp/* "$inspath/tmp/" >>/dev/null 2>&1  # safe: dir may be empty
	# shellcheck disable=SC2086
	cp -f "$bkpath"/quarantine/* "$inspath/quarantine/" >>/dev/null 2>&1  # safe: dir may be empty
	# shellcheck disable=SC2086
	cp -f "$bkpath"/cron/* "$inspath/cron/" >>/dev/null 2>&1  # safe: dir may be empty
	# shellcheck disable=SC2086
	cp -f "$bkpath"/logs/* "$inspath/logs/" >>/dev/null 2>&1  # safe: dir may be empty
	# shellcheck disable=SC2086
	cp -f "$bkpath"/sigs/custom.* "$inspath/sigs/" >>/dev/null 2>&1  # safe: glob may match nothing
	if [ -d "$bkpath/sigs/custom.yara.d" ]; then
		cp -rf "$bkpath/sigs/custom.yara.d" "$inspath/sigs/" >>/dev/null 2>&1  # safe: copy yara rules
	fi
	cp -f "$bkpath/monitor_paths" "$inspath/" >>/dev/null 2>&1  # safe: file may not exist
	cp -f "$bkpath/monitor_paths.extra" "$inspath/" >>/dev/null 2>&1  # safe: file may not exist
	# shellcheck disable=SC2086
	cp -pf "$bkpath"/clean/custom.* "$inspath/clean/" >>/dev/null 2>&1  # safe: glob may match nothing
	cp -pf "$bkpath/conf.maldet.hookscan" "$inspath/" >>/dev/null 2>&1  # safe: file may not exist
	if [ -d "$bkpath/pub" ]; then
		cp -af "$bkpath/pub" "$inspath/" >>/dev/null 2>&1  # safe: preserve pub data
	fi
	if [ -d "$bkpath/internals/alert/custom.d" ]; then
		cp -rf "$bkpath/internals/alert/custom.d" "$inspath/internals/alert/" >>/dev/null 2>&1  # safe: custom alert templates
	fi
	# Create empty monitor_paths.extra if not restored from backup
	if [ ! -f "$inspath/monitor_paths.extra" ]; then
		touch "$inspath/monitor_paths.extra"
		chmod 640 "$inspath/monitor_paths.extra"
	fi
	# tlog cursor migration: inotify switching from line-count to byte-offset
	rm -f "$inspath/tmp/inotify" 2>/dev/null  # safe: legacy cursor file
	# Remove stale Perl hex scripts and FIFO (replaced by native grep engine)
	rm -f "$inspath/internals/hexfifo.pl" "$inspath/internals/hexstring.pl" \
		"$inspath/internals/hexfifo" 2>/dev/null  # safe: legacy files
	_install_cron_service

	pkg_section "Importing configuration"
	_import_config

	# Re-evaluate sigup_interval after config import (user may have set to 0)
	_post_sigup_interval=$(_read_conf_value "sigup_interval" "6")
	if [ "$_post_sigup_interval" = "0" ] || ! [ "$_post_sigup_interval" -gt 0 ] 2>/dev/null; then
		command rm -f /etc/cron.d/maldet-sigup 2>/dev/null  # safe: user disabled sigup
	fi
	unset _post_sigup_interval

	pkg_section "Updating signatures"
	"$inspath/maldet" --update 1

	_restart_monitor
	_postinfo
	pkg_success "Linux Malware Detect ${lmd_version} upgrade complete"

elif [ -d "files" ]; then
	# --- Fresh install path ---
	pkg_header "Linux Malware Detect" "$lmd_version" "install"
	echo "            (C) 2002-2026, R-fx Networks <proj@rfxn.com>"
	echo "            (C) 2026, Ryan MacDonald <ryan@rfxn.com>"
	echo "This program may be freely redistributed under the terms of the GNU GPL v2"

	pkg_section "Installing files"
	_install_core
	# Create empty monitor_paths.extra if not restored from backup
	if [ ! -f "$inspath/monitor_paths.extra" ]; then
		touch "$inspath/monitor_paths.extra"
		chmod 640 "$inspath/monitor_paths.extra"
	fi
	_install_cron_service

	pkg_section "Updating signatures"
	"$inspath/maldet" --update 1

	_postinfo
	pkg_success "Linux Malware Detect ${lmd_version} installation complete"
fi
