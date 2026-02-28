#!/usr/bin/env bash
#
##
# Linux Malware Detect v2.0.1
#             (C) 2002-2026, R-fx Networks <proj@rfxn.com>
#             (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#
export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:$PATH
echo "This will completely remove Linux Malware Detect from your server including all quarantine data!"
echo -n "Would you like to proceed? "
read -p "[y/n] " -n 1 Z
echo
if [ "$Z" == "y" ] || [ "$Z" == "Y" ]; then
	if [ "$(uname -s)" != "FreeBSD" ]; then
		if test "$(cat /proc/1/comm 2>/dev/null)" = "systemd"
		then
			systemctl disable maldet.service
			systemctl stop maldet.service
			rm -f /usr/lib/systemd/system/maldet.service
			systemctl daemon-reload
		else
			maldet -k
			if [ -f /etc/redhat-release ]; then
				if command -v chkconfig >/dev/null 2>&1; then
					chkconfig maldet off
					chkconfig maldet --del
				fi
			elif [ -f /etc/debian_version ] || [ -f /etc/lsb-release ]; then
				update-rc.d -f maldet remove
			elif [ -f /etc/gentoo-release ]; then
				rc-update del maldet default
			elif [ -f /etc/slackware-version ]; then
				rm -f /etc/rc.d/rc3.d/S70maldet
				rm -f /etc/rc.d/rc4.d/S70maldet
				rm -f /etc/rc.d/rc5.d/S70maldet
			else
				if command -v chkconfig >/dev/null 2>&1; then
					chkconfig maldet off
					chkconfig maldet --del
				fi
			fi
			rm -f /etc/init.d/maldet
		fi
	fi
	rm -rf /usr/local/maldetect* /etc/cron.d/maldet_pub /etc/cron.daily/maldet /etc/cron.weekly/maldet-watchdog /usr/local/sbin/maldet /usr/local/sbin/lmd /usr/local/share/man/man1/maldet.1.gz
	rm -f /etc/sysconfig/maldet /etc/default/maldet
	clamav_paths="/usr/local/cpanel/3rdparty/share/clamav/ /var/lib/clamav/ /var/clamav/ /usr/share/clamav/ /usr/local/share/clamav"
	for cpath in $clamav_paths; do
		rm -f $cpath/rfxn.* $cpath/lmd.user.*
	done
	echo "Linux Malware Detect has been uninstalled."
else
	echo "You selected No or provided an invalid confirmation, nothing has been done!"
fi
