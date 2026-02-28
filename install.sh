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
ver=2.0.1
ver_major=2.0
inspath=/usr/local/maldetect
logf=$inspath/logs/event_log
conftemp="$inspath/internals/importconf"
find=$(command -v find 2>/dev/null)


clamav_linksigs() {
        cpath="$1"
        if [ -d "$cpath" ]; then
                rm -f "$cpath"/rfxn.* ; cp -f "$inspath/sigs/rfxn.ndb" "$inspath/sigs/rfxn.hdb" "$inspath/sigs/rfxn.yara" "$cpath/" 2> /dev/null
                rm -f "$cpath"/lmd.user.* ; cp -f "$inspath/sigs/lmd.user.ndb" "$inspath/sigs/lmd.user.hdb" "$cpath/" 2> /dev/null
        fi
}

if [ ! -d "$inspath" ] && [ -d "files" ]; then
	mkdir -p "$inspath"
	chmod 755 "$inspath"
	cp -pR files/* "$inspath"
	chmod 755 "$inspath/maldet"
	chmod 640 "$inspath/conf.maldet"
	test -f "$inspath/conf.maldet.hookscan" && chmod 640 "$inspath/conf.maldet.hookscan"
	mkdir -p "$inspath/clean" "$inspath/pub" "$inspath/quarantine" "$inspath/sess" "$inspath/sigs" "$inspath/tmp" 2> /dev/null
	chmod 750 "$inspath/quarantine" "$inspath/sess" "$inspath/tmp" "$inspath/internals/tlog" "$inspath/internals/tlog_lib.sh" 2> /dev/null
	# tlog: replace default BASERUN for cursor storage security
	sed -i "s|BASERUN=\"\${BASERUN:-/tmp}\"|BASERUN=\"\${BASERUN:-$inspath/tmp}\"|" "$inspath/internals/tlog"
	ln -fs "$inspath/maldet" /usr/local/sbin/maldet
	ln -fs "$inspath/maldet" /usr/local/sbin/lmd
	cp -f CHANGELOG COPYING.GPL README "$inspath/"
	mkdir -p /usr/local/share/man/man1/
	gzip -9 "$inspath/maldet.1"
	ln -fs "$inspath/maldet.1.gz" /usr/local/share/man/man1/maldet.1.gz
	clamav_paths="/usr/local/cpanel/3rdparty/share/clamav/ /var/lib/clamav/ /var/clamav/ /usr/share/clamav/ /usr/local/share/clamav"
	for lp in $clamav_paths; do
		clamav_linksigs "$lp"
	done
	killall -SIGUSR2 clamd 2> /dev/null
else
	if [ "$(ps -A --user root -o "command" 2> /dev/null | grep maldetect | grep inotifywait)" ]; then
		$inspath/maldet -k >> /dev/null 2>&1
		monmode=1
	fi
	$find "${inspath}."* -maxdepth 0 -type d -mtime +30 -exec rm -rf {} + 2> /dev/null
	chattr -ia "$inspath/internals/internals.conf"
	if ! mv "$inspath" "$inspath.bk$$"; then
		echo "ERROR: failed to backup $inspath to $inspath.bk$$, aborting install."
		exit 1
	fi
	ln -fs "$inspath.bk$$" "$inspath.last"
	mkdir -p "$inspath"
	chmod 755 "$inspath"
	cp -pR files/* "$inspath"
	chmod 755 "$inspath/maldet"
	chmod 640 "$inspath/conf.maldet"
	test -f "$inspath/conf.maldet.hookscan" && chmod 640 "$inspath/conf.maldet.hookscan"
	ln -fs "$inspath/maldet" /usr/local/sbin/maldet
	ln -fs "$inspath/maldet" /usr/local/sbin/lmd
	mkdir -p /usr/local/share/man/man1/
	gzip -9 "$inspath/maldet.1"
	ln -fs "$inspath/maldet.1.gz" /usr/local/share/man/man1/maldet.1.gz
	cp -f "$inspath.bk$$"/ignore_* "$inspath/"  >> /dev/null 2>&1
	cp -f "$inspath.bk$$"/sess/* "$inspath/sess/" >> /dev/null 2>&1
	cp -f "$inspath.bk$$"/tmp/* "$inspath/tmp/" >> /dev/null 2>&1
	cp -f "$inspath.bk$$"/quarantine/* "$inspath/quarantine/" >> /dev/null 2>&1
	cp -f "$inspath.bk$$"/cron/* "$inspath/cron/" >> /dev/null 2>&1
	cp -f "$inspath.bk$$"/logs/* "$inspath/logs/" >> /dev/null 2>&1
	cp -f "$inspath.bk$$"/sigs/custom.* "$inspath/sigs/" >> /dev/null 2>&1
	if [ -d "$inspath.bk$$"/sigs/custom.yara.d ]; then
		cp -rf "$inspath.bk$$"/sigs/custom.yara.d "$inspath/sigs/" >> /dev/null 2>&1
	fi
	cp -f "$inspath.bk$$"/monitor_paths "$inspath/" >> /dev/null 2>&1
	cp -pf "$inspath.bk$$"/clean/custom.* "$inspath/clean/" >> /dev/null 2>&1
	cp -f CHANGELOG COPYING.GPL README "$inspath/"
	mkdir -p "$inspath/clean" "$inspath/pub" "$inspath/quarantine" "$inspath/sess" "$inspath/sigs" "$inspath/tmp" 2> /dev/null
	chmod 750 "$inspath/quarantine" "$inspath/sess" "$inspath/tmp" "$inspath/internals/tlog" "$inspath/internals/tlog_lib.sh" 2> /dev/null
	# tlog: replace default BASERUN for cursor storage security
	sed -i "s|BASERUN=\"\${BASERUN:-/tmp}\"|BASERUN=\"\${BASERUN:-$inspath/tmp}\"|" "$inspath/internals/tlog"
	# tlog cursor migration: inotify switching from line-count to byte-offset
	rm -f "$inspath/tmp/inotify" 2>/dev/null
	clamav_paths="/usr/local/cpanel/3rdparty/share/clamav/ /var/lib/clamav/ /var/clamav/ /usr/share/clamav/ /usr/local/share/clamav"
	for lp in $clamav_paths; do
		clamav_linksigs "$lp"
	done
	killall -SIGUSR2 clamd 2> /dev/null
fi

if [ -d "/etc/cron.daily" ]; then
	cp -f cron.daily /etc/cron.daily/maldet
	chmod 755 /etc/cron.daily/maldet
fi

if [ -d "/etc/cron.weekly" ]; then
	cp -f cron.watchdog /etc/cron.weekly/maldet-watchdog
	chmod 755 /etc/cron.weekly/maldet-watchdog
fi

if [ -d "/etc/cron.d" ]; then
	cp -f cron.d.pub /etc/cron.d/maldet_pub
	chmod 644 /etc/cron.d/maldet_pub
fi

if [ "$(uname -s)" != "FreeBSD" ]; then
        if test "$(cat /proc/1/comm 2> /dev/null)" == "systemd"
        then
                mkdir -p /etc/systemd/system/
                mkdir -p /usr/lib/systemd/system/
                rm -f /usr/lib/systemd/system/maldet.service
                cp ./files/service/maldet.service /usr/lib/systemd/system/
                systemctl daemon-reload
                systemctl enable maldet.service
	else
                cp -af ./files/service/maldet.sh /etc/init.d/maldet
                chmod 755 /etc/init.d/maldet
		if command -v chkconfig >/dev/null 2>&1; then
			chkconfig --level 2345 maldet on
		fi
	fi
	# Migrate default_monitor_mode to MONITOR_MODE in sysconfig for systemd
	if [ -f "$inspath.bk$$/conf.maldet" ]; then
		_old_dmm=$(grep '^default_monitor_mode=' "$inspath.bk$$/conf.maldet" 2>/dev/null | tail -1 | sed 's/^default_monitor_mode=//' | tr -d '"')
		if [ -n "$_old_dmm" ] && [ "$_old_dmm" != "users" ]; then
			for _scf in /etc/sysconfig/maldet /etc/default/maldet; do
				if [ -f "$_scf" ]; then
					if grep -q '^MONITOR_MODE=' "$_scf"; then
						sed -i "s|^MONITOR_MODE=.*|MONITOR_MODE=\"$_old_dmm\"|" "$_scf"
					else
						echo "MONITOR_MODE=\"$_old_dmm\"" >> "$_scf"
					fi
				fi
			done
		fi
		unset _old_dmm
	fi
	if [ -f /etc/redhat-release ]; then
		if [ ! -f "/etc/sysconfig/maldet" ]; then
			cp -f ./files/service/maldet.sysconfig /etc/sysconfig/maldet
		fi
	elif [ -f /etc/debian_version ] || [ -f /etc/lsb-release ]; then
		if [ ! -f "/etc/default/maldet" ]; then
			cp -f ./files/service/maldet.sysconfig /etc/default/maldet
		fi
		update-rc.d -f maldet remove
		update-rc.d maldet defaults 70 30
	elif [ -f /etc/gentoo-release ]; then
		rc-update add maldet default
	elif [ -f /etc/slackware-version ]; then
		ln -sf /etc/init.d/maldet /etc/rc.d/rc3.d/S70maldet
		ln -sf /etc/init.d/maldet /etc/rc.d/rc4.d/S70maldet
		ln -sf /etc/init.d/maldet /etc/rc.d/rc5.d/S70maldet
	else
		if [ ! -f "/etc/sysconfig/maldet" ]; then
			cp -f ./files/service/maldet.sysconfig /etc/sysconfig/maldet 2> /dev/null
		fi
		if command -v chkconfig >/dev/null 2>&1; then
			chkconfig maldet on
		fi
	fi
fi

mkdir -p "$inspath/logs" && touch "$logf"
ln -fs "$logf" "$inspath/event_log"
$inspath/maldet --alert-daily 2> /dev/null

echo "Linux Malware Detect v$ver"
echo "            (C) 2002-2026, R-fx Networks <proj@rfxn.com>"
echo "            (C) 2026, Ryan MacDonald <ryan@rfxn.com>"
echo "This program may be freely redistributed under the terms of the GNU GPL v2"
echo ""
echo "installation completed to $inspath"
echo "config file: $inspath/conf.maldet"
echo "exec file: $inspath/maldet"
echo "exec link: /usr/local/sbin/maldet"
echo "exec link: /usr/local/sbin/lmd"
echo "cron.daily: /etc/cron.daily/maldet"
if [ -f "$conftemp" ] && [ -f "${inspath}.last/conf.maldet" ]; then
	. files/conf.maldet
	. "${inspath}.last/conf.maldet"
	if [ "$quarantine_hits" == "0" ] && [ "$quar_hits" == "1" ]; then
		quarantine_hits=1
	fi
	if [ "$quarantine_clean" == "0" ] && [ "$quar_clean" == "1" ]; then
		quarantine_clean="1"
	fi
	if [ -f "files/internals/compat.conf" ]; then
		source files/internals/compat.conf
	fi
	source "$conftemp"
	echo "imported config options from $inspath.last/conf.maldet"
fi
$inspath/maldet --update 1
if [ "$monmode" == "1" ]; then
	if test "$(cat /proc/1/comm 2> /dev/null)" == "systemd" && systemctl is-enabled maldet.service >/dev/null 2>&1; then
		echo "detected active monitoring mode, restarting via systemctl"
		systemctl restart maldet.service >> /dev/null 2>&1 &
	else
		echo "detected active monitoring mode, restarted inotify watch with '-m users'"
		$inspath/maldet -m users >> /dev/null 2>&1 &
	fi
fi
echo ""
