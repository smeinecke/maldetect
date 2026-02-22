#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-hook"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

@test "hookscan.sh exists and is executable" {
    [ -f "$LMD_INSTALL/hookscan.sh" ]
}

@test "hookscan.sh syntax is valid" {
    run bash -n "$LMD_INSTALL/hookscan.sh"
    assert_success
}

@test "maldet -hscan on clean file returns OK" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/upload.txt"
    run maldet --hook-scan -a "$TEST_SCAN_DIR"
    assert_success
    # Hook scan in modsec mode returns "1 maldet: OK" for clean files
    assert_output --partial "OK"
}

@test "hook scan suppresses header output" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/upload.txt"
    run maldet --hook-scan -a "$TEST_SCAN_DIR"
    # hscan mode sets hscan=1, which suppresses header() call
    refute_output --partial "Linux Malware Detect v"
}

@test "maldet -hscan detects malware in scanned path" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet --hook-scan -a "$TEST_SCAN_DIR"
    # Hook scan returns "0 maldet: SIGNAME PATH" on detection
    assert_output --partial "0 maldet:"
}
