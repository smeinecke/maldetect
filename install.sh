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
conftemp="$inspath/internals/importconf"

# Source shared packaging library
PKG_BACKUP_SYMLINK="maldetect.last"
PKG_BACKUP_PRUNE_DAYS="30"
# shellcheck disable=SC1091
source files/internals/pkg_lib.sh

# --- ClamAV integration (LMD-specific) ---

clamav_linksigs() {
	local cpath="$1"
	if [ -d "$cpath" ]; then
		rm -f "$cpath"/rfxn.* ; cp -f "$inspath/sigs/rfxn.ndb" "$inspath/sigs/rfxn.hdb" "$inspath/sigs/rfxn.yara" "$cpath/" 2>/dev/null
		rm -f "$cpath"/lmd.user.* 2>/dev/null
		[ -s "$inspath/sigs/lmd.user.ndb" ] && /usr/bin/cp -f "$inspath/sigs/lmd.user.ndb" "$cpath"/ 2>/dev/null
		[ -s "$inspath/sigs/lmd.user.hdb" ] && /usr/bin/cp -f "$inspath/sigs/lmd.user.hdb" "$cpath"/ 2>/dev/null
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
		"$inspath/internals/lmd_alert.sh" "$inspath/internals/elog_lib.sh" \
		"$inspath/internals/pkg_lib.sh" 2>/dev/null
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
	for lp in $clamav_paths; do
		clamav_linksigs "$lp"
	done
	killall -SIGUSR2 clamd 2>/dev/null  # safe: signal ClamAV to reload sigs
}

# --- Cron & service installation ---

_install_cron_service() {
	pkg_cron_install cron.daily /etc/cron.daily/maldet
	pkg_cron_install cron.watchdog /etc/cron.weekly/maldet-watchdog
	pkg_cron_install cron.d.pub /etc/cron.d/maldet_pub

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
	"$inspath/maldet" --alert-daily 2>/dev/null  # safe: configures daily alert cron
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

_import_config() {
	if [ -f "$conftemp" ] && [ -f "${inspath}.last/conf.maldet" ]; then
		# shellcheck disable=SC1091
		. files/conf.maldet
		# shellcheck disable=SC1090
		. "${inspath}.last/conf.maldet"
		if [ "$quarantine_hits" == "0" ] && [ "$quar_hits" == "1" ]; then
			quarantine_hits=1
		fi
		if [ "$quarantine_clean" == "0" ] && [ "$quar_clean" == "1" ]; then
			quarantine_clean="1"
		fi
		if [ -f "files/internals/compat.conf" ]; then
			# shellcheck disable=SC1091
			source files/internals/compat.conf
		fi
		# shellcheck disable=SC1090
		source "$conftemp"
		pkg_info "imported config options from ${inspath}.last/conf.maldet"
	fi
}

# --- Restart monitor if it was running ---

_restart_monitor() {
	if [ "${monmode:-}" == "1" ]; then
		if pkg_is_systemd && systemctl is-enabled maldet.service >/dev/null 2>&1; then
			pkg_info "detected active monitoring mode, restarting via systemctl"
			systemctl restart maldet.service >>/dev/null 2>&1 &
		else
			pkg_info "detected active monitoring mode, restarted inotify watch with '-m users'"
			"$inspath/maldet" -m users >>/dev/null 2>&1 &
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
	# shellcheck disable=SC2086
	cp -pf "$bkpath"/clean/custom.* "$inspath/clean/" >>/dev/null 2>&1  # safe: glob may match nothing
	cp -pf "$bkpath/conf.maldet.hookscan" "$inspath/" >>/dev/null 2>&1  # safe: file may not exist
	if [ -d "$bkpath/pub" ]; then
		cp -af "$bkpath/pub" "$inspath/" >>/dev/null 2>&1  # safe: preserve pub data
	fi
	if [ -d "$bkpath/internals/alert/custom.d" ]; then
		cp -rf "$bkpath/internals/alert/custom.d" "$inspath/internals/alert/" >>/dev/null 2>&1  # safe: custom alert templates
	fi
	# tlog cursor migration: inotify switching from line-count to byte-offset
	rm -f "$inspath/tmp/inotify" 2>/dev/null  # safe: legacy cursor file
	# Remove stale Perl hex scripts and FIFO (replaced by native grep engine)
	rm -f "$inspath/internals/hexfifo.pl" "$inspath/internals/hexstring.pl" \
		"$inspath/internals/hexfifo" 2>/dev/null  # safe: legacy files
	_install_cron_service

	pkg_section "Importing configuration"
	_import_config

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
	_install_cron_service

	pkg_section "Updating signatures"
	"$inspath/maldet" --update 1

	_postinfo
	pkg_success "Linux Malware Detect ${lmd_version} installation complete"
fi
