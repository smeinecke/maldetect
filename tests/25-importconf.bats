#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    # Back up original conf.maldet
    cp -p "$LMD_INSTALL/conf.maldet" "$LMD_INSTALL/conf.maldet.bak"
}

teardown() {
    # Restore original conf.maldet
    if [ -f "$LMD_INSTALL/conf.maldet.bak" ]; then
        mv -f "$LMD_INSTALL/conf.maldet.bak" "$LMD_INSTALL/conf.maldet"
    fi
}

# Helper: source config stack, apply variable overrides, run importconf
_run_importconf() {
    set +eu
    source "$LMD_INSTALL/conf.maldet"
    # Caller sets variable overrides before calling this function
    source "$LMD_INSTALL/internals/importconf"
}

@test "importconf preserves email_alert setting" {
    email_alert="1"
    _run_importconf
    run grep '^email_alert=' "$LMD_INSTALL/conf.maldet"
    assert_output 'email_alert="1"'
}

@test "importconf preserves email_ignore_clean=0 (not hardcoded to 1)" {
    email_ignore_clean="0"
    _run_importconf
    run grep '^email_ignore_clean=' "$LMD_INSTALL/conf.maldet"
    assert_output 'email_ignore_clean="0"'
}

@test "importconf preserves scan_max_filesize (not hardcoded)" {
    scan_max_filesize="4096k"
    _run_importconf
    run grep '^scan_max_filesize=' "$LMD_INSTALL/conf.maldet"
    assert_output 'scan_max_filesize="4096k"'
}

@test "importconf preserves inotify_sleep (not hardcoded to 30)" {
    inotify_sleep="15"
    _run_importconf
    run grep '^inotify_sleep=' "$LMD_INSTALL/conf.maldet"
    assert_output 'inotify_sleep="15"'
}

@test "importconf preserves autoupdate_signatures=0 (not hardcoded to 1)" {
    autoupdate_signatures="0"
    _run_importconf
    run grep '^autoupdate_signatures=' "$LMD_INSTALL/conf.maldet"
    assert_output 'autoupdate_signatures="0"'
}

@test "importconf includes email_subj variable" {
    email_subj="custom subject"
    _run_importconf
    run grep '^email_subj=' "$LMD_INSTALL/conf.maldet"
    assert_output 'email_subj="custom subject"'
}

@test "importconf includes scan_yara variable" {
    scan_yara="1"
    _run_importconf
    run grep '^scan_yara=' "$LMD_INSTALL/conf.maldet"
    assert_output 'scan_yara="1"'
}

@test "importconf includes scan_yara_timeout variable" {
    scan_yara_timeout="600"
    _run_importconf
    run grep '^scan_yara_timeout=' "$LMD_INSTALL/conf.maldet"
    assert_output 'scan_yara_timeout="600"'
}

@test "importconf includes scan_yara_scope variable" {
    scan_yara_scope="all"
    _run_importconf
    run grep '^scan_yara_scope=' "$LMD_INSTALL/conf.maldet"
    assert_output 'scan_yara_scope="all"'
}

@test "importconf includes import_custsigs_yara_url variable" {
    import_custsigs_yara_url="http://example.com/rules.yar"
    _run_importconf
    run grep '^import_custsigs_yara_url=' "$LMD_INSTALL/conf.maldet"
    assert_output 'import_custsigs_yara_url="http://example.com/rules.yar"'
}

@test "importconf preserves scan_tmpdir_paths (not hardcoded)" {
    scan_tmpdir_paths="/tmp /var/tmp /dev/shm /var/fcgi_ipc"
    _run_importconf
    run grep '^scan_tmpdir_paths=' "$LMD_INSTALL/conf.maldet"
    assert_output 'scan_tmpdir_paths="/tmp /var/tmp /dev/shm /var/fcgi_ipc"'
}

@test "importconf preserves string_length_scan (not hardcoded)" {
    string_length_scan="1"
    _run_importconf
    run grep '^string_length_scan=' "$LMD_INSTALL/conf.maldet"
    assert_output --partial 'string_length_scan="1"'
}
