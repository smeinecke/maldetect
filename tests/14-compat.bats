#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'

LMD_INSTALL="/usr/local/maldetect"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
}

# Helper: source compat.conf safely (it expects conf.maldet vars to exist)
_source_compat() {
    set +u
    source "$LMD_INSTALL/internals/compat.conf"
    set -u
}

@test "deprecated maxdepth maps to scan_max_depth" {
    unset scan_max_depth
    maxdepth=5
    _source_compat
    [ "$scan_max_depth" = "5" ]
}

@test "deprecated quar_clean maps to quarantine_clean" {
    unset quarantine_clean
    quar_clean=1
    _source_compat
    [ "$quarantine_clean" = "1" ]
}

@test "deprecated quar_susp maps to quarantine_suspend_user" {
    unset quarantine_suspend_user
    quar_susp=1
    _source_compat
    [ "$quarantine_suspend_user" = "1" ]
}

@test "deprecated scan_nice maps to scan_cpunice" {
    unset scan_cpunice
    scan_nice=15
    _source_compat
    [ "$scan_cpunice" = "15" ]
}

@test "deprecated inotify_stime maps to inotify_sleep" {
    unset inotify_sleep
    inotify_stime=30
    _source_compat
    [ "$inotify_sleep" = "30" ]
}

@test "deprecated inotify_webdir maps to inotify_docroot" {
    unset inotify_docroot
    inotify_webdir="public_html"
    _source_compat
    [ "$inotify_docroot" = "public_html" ]
}

@test "deprecated hex_fifo_scan maps to scan_hexfifo" {
    unset scan_hexfifo
    hex_fifo_scan=0
    _source_compat
    [ "$scan_hexfifo" = "0" ]
}

@test "deprecated clamav_scan maps to scan_clamscan" {
    unset scan_clamscan
    clamav_scan=1
    _source_compat
    [ "$scan_clamscan" = "1" ]
}

@test "deprecated suppress_cleanhit maps to email_ignore_clean" {
    unset email_ignore_clean
    suppress_cleanhit=1
    _source_compat
    [ "$email_ignore_clean" = "1" ]
}

@test "new variable takes priority over deprecated" {
    scan_max_depth=10
    maxdepth=5
    _source_compat
    [ "$scan_max_depth" = "10" ]
}

@test "multiple deprecated vars work together" {
    unset quarantine_clean scan_cpunice scan_hexfifo
    quar_clean=1
    scan_nice=15
    hex_fifo_scan=0
    _source_compat
    [ "$quarantine_clean" = "1" ]
    [ "$scan_cpunice" = "15" ]
    [ "$scan_hexfifo" = "0" ]
}

@test "deprecated minfilesize maps to scan_min_filesize" {
    unset scan_min_filesize
    minfilesize=1024
    _source_compat
    [ "$scan_min_filesize" = "1024" ]
}

@test "deprecated maxfilesize maps to scan_max_filesize" {
    unset scan_max_filesize
    maxfilesize=2048000
    _source_compat
    [ "$scan_max_filesize" = "2048000" ]
}

@test "deprecated hexdepth maps to scan_hexdepth" {
    unset scan_hexdepth
    hexdepth=65536
    _source_compat
    [ "$scan_hexdepth" = "65536" ]
}

@test "deprecated tmpdir_paths maps to scan_tmpdir_paths" {
    unset scan_tmpdir_paths
    tmpdir_paths="/tmp /var/tmp"
    _source_compat
    [ "$scan_tmpdir_paths" = "/tmp /var/tmp" ]
}

@test "compat.conf sourced after conf.maldet in maldet entry point" {
    run grep -n 'source.*compatcnf' "$LMD_INSTALL/maldet"
    assert_success
    local compat_line
    compat_line=$(echo "$output" | head -1 | cut -d: -f1)
    run grep -n 'source.*cnf' "$LMD_INSTALL/maldet"
    assert_success
    local cnf_line
    cnf_line=$(echo "$output" | head -1 | cut -d: -f1)
    [ "$compat_line" -gt "$cnf_line" ]
}
