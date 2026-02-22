#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-quar"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

@test "quarantine moves file out of original location" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet -q "$scanid"
    assert_success
    [ ! -f "$TEST_SCAN_DIR/eicar.com" ]
}

@test "quarantined file exists in quarantine directory" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    maldet -q "$scanid"
    local qcount
    qcount=$(find "$LMD_INSTALL/quarantine" -type f ! -name '*.info' | wc -l)
    [ "$qcount" -ge 1 ]
}

@test "quarantined file has permissions 000" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    maldet -q "$scanid"
    local qfile
    qfile=$(find "$LMD_INSTALL/quarantine" -type f ! -name '*.info' | head -1)
    [ -n "$qfile" ]
    local perms
    perms=$(stat -c '%a' "$qfile")
    [ "$perms" = "0" ]
}

@test "quarantine metadata recorded in quarantine.hist" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    maldet -q "$scanid"
    [ -f "$LMD_INSTALL/sess/quarantine.hist" ]
    [ -s "$LMD_INSTALL/sess/quarantine.hist" ]
}

@test "quarantine hist contains original file path" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    maldet -q "$scanid"
    run grep "$TEST_SCAN_DIR/eicar.com" "$LMD_INSTALL/sess/quarantine.hist"
    assert_success
}

@test "quarantine hist contains signature name" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    maldet -q "$scanid"
    run grep "EICAR" "$LMD_INSTALL/sess/quarantine.hist"
    assert_success
}

@test "restore returns file to original location" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    maldet -q "$scanid"
    [ ! -f "$TEST_SCAN_DIR/eicar.com" ]
    run maldet -s "$scanid"
    assert_success
    [ -f "$TEST_SCAN_DIR/eicar.com" ]
}

@test "restored file has correct content" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    local orig_md5
    orig_md5=$(md5sum "$TEST_SCAN_DIR/eicar.com" | awk '{print $1}')
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    maldet -q "$scanid"
    maldet -s "$scanid"
    local restored_md5
    restored_md5=$(md5sum "$TEST_SCAN_DIR/eicar.com" | awk '{print $1}')
    [ "$orig_md5" = "$restored_md5" ]
}

@test "batch quarantine via -q SCANID handles multiple files" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/eicar1.com"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/eicar2.com"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet -q "$scanid"
    assert_success
    [ ! -f "$TEST_SCAN_DIR/eicar1.com" ]
    [ ! -f "$TEST_SCAN_DIR/eicar2.com" ]
}

@test "batch restore via -s SCANID restores multiple files" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/eicar1.com"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/eicar2.com"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    maldet -q "$scanid"
    run maldet -s "$scanid"
    assert_success
    [ -f "$TEST_SCAN_DIR/eicar1.com" ]
    [ -f "$TEST_SCAN_DIR/eicar2.com" ]
}

@test "clean file is not quarantined" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR"
    local scanid
    scanid=$(get_last_scanid)
    run maldet -q "$scanid"
    [ -f "$TEST_SCAN_DIR/clean-file.txt" ]
}

@test "quarantine_hits=1 auto-quarantines on scan" {
    lmd_set_config quarantine_hits 1
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    [ ! -f "$TEST_SCAN_DIR/eicar.com" ]
}

@test "quarantine_hits=0 does not auto-quarantine" {
    lmd_set_config quarantine_hits 0
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    [ -f "$TEST_SCAN_DIR/eicar.com" ]
}
