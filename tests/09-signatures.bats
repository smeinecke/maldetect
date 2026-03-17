#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-sigs"

setup() {
    RESET_FULL=1
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

@test "empty custom signature files do not cause errors" {
    > "$LMD_INSTALL/sigs/custom.md5.dat"
    > "$LMD_INSTALL/sigs/custom.hex.dat"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
}

@test "missing custom signature files do not cause errors" {
    rm -f "$LMD_INSTALL/sigs/custom.md5.dat" "$LMD_INSTALL/sigs/custom.hex.dat"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
}

@test "signature version file is not modified by scan" {
    echo "20250101" > "$LMD_INSTALL/sigs/maldet.sigs.ver"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR"
    run cat "$LMD_INSTALL/sigs/maldet.sigs.ver"
    assert_output "20250101"
}

@test "scan output reports signature counts" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "signatures ready"
}

@test "signature files exist and are non-empty" {
    [ -s "$LMD_INSTALL/sigs/md5v2.dat" ]
    [ -s "$LMD_INSTALL/sigs/hex.dat" ]
    [ -f "$LMD_INSTALL/sigs/maldet.sigs.ver" ]
}

@test "sha256v2.dat absence is non-fatal (upgrade path)" {
    rm -f "$LMD_INSTALL/sigs/sha256v2.dat"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
}
