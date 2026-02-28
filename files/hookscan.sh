#!/usr/bin/env bash
#
##
# Linux Malware Detect v2.0.1
#             (C) 2002-2026, R-fx Networks <proj@rfxn.com>
#             (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#
file="$1"

# Reject filenames with shell metacharacters, newlines, or null bytes
case "$file" in
	*[![:print:]]*)
		logger -t maldet-hookscan "rejected filename with non-printable characters"
		exit 1
		;;
esac
metachar_pat='[;|&$(){}`]'
if [[ "$file" =~ $metachar_pat ]]; then
	logger -t maldet-hookscan "rejected filename with shell metacharacters"
	exit 1
fi
if [ ! -f "$file" ]; then
	exit 1
fi

inspath='/usr/local/maldetect'
intcnf="$inspath/internals/internals.conf"
if [ -f "$intcnf" ]; then
	source "$intcnf"
fi

## these values can be overridden in conf.maldet.hookscan
quarantine_hits=1
quarantine_clean=0
scan_tmpdir_paths=''
scan_yara=0
hscan=1

if [ -n "$pidof" ]; then
	isclamd=$($pidof clamd 2> /dev/null)
fi
if [ "$isclamd" ] && [ -f "$clamdscan" ]; then
	clamd_scan=1
else
	clamd_scan=0
fi

hookcnf="$inspath/conf.maldet.hookscan"
if [ -f "$hookcnf" ]; then
        source "$hookcnf"
fi

cd /tmp ; $inspath/maldet --hook-scan --config-option quarantine_hits=$quarantine_hits,quarantine_clean=$quarantine_clean,tmpdir=/var/tmp,scan_tmpdir_paths=$scan_tmpdir_paths,scan_clamscan=$clamd_scan,scan_yara=$scan_yara -a "$file"
