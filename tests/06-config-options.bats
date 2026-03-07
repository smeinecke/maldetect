#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-config"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

@test "-co overrides single variable" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -co scan_max_filesize=1 -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "empty file list"
}

@test "compat.conf exists" {
    [ -f "$LMD_INSTALL/internals/compat.conf" ]
}

@test "system override file location is detected" {
    # On Debian-based systems, /etc/default/maldet should exist
    # On RHEL-based, /etc/sysconfig/maldet
    if [ -f /etc/debian_version ]; then
        [ -f /etc/default/maldet ] || [ ! -f /etc/debian_version ]
    elif [ -f /etc/redhat-release ]; then
        [ -f /etc/sysconfig/maldet ] || [ ! -f /etc/redhat-release ]
    fi
}

@test "conf.maldet has all critical variables" {
    run grep -c '^quarantine_hits=' "$LMD_INSTALL/conf.maldet"
    assert_output "1"
    run grep -c '^email_alert=' "$LMD_INSTALL/conf.maldet"
    assert_output "1"
    run grep -c '^scan_clamscan=' "$LMD_INSTALL/conf.maldet"
    assert_output "1"
}

@test "scan_user_access_minuid has default value 100" {
    run grep '^scan_user_access_minuid="100"' "$LMD_INSTALL/conf.maldet"
    assert_success
}

@test "scan_ignore_user with non-existent user does not break scan" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -co scan_ignore_user=nonexistent_user_xyz -a "$TEST_SCAN_DIR"
    assert_output --partial "does not exist, skipping"
    assert_output --partial "malware hits 1"
}

@test "scan_ignore_group with non-existent group does not break scan" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -co scan_ignore_group=nonexistent_group_xyz -a "$TEST_SCAN_DIR"
    assert_output --partial "does not exist, skipping"
    assert_output --partial "malware hits 1"
}
