#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-report"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

@test "--dump-report SCANID displays report" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet -E "$scanid"
    assert_success
    # TSV header starts with #LMD:v1; legacy text contains "SCAN ID"
    [[ "$output" == *"SCAN ID"* ]] || [[ "$output" == *"#LMD:v1"* ]]
}

@test "--dump-report outputs report to stdout" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet -E "$scanid"
    assert_success
    [ -n "$output" ]
}

@test "report contains hit information" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet -E "$scanid"
    assert_success
    # Sig name case varies by hash engine (EICAR for MD5, eicar for SHA-256/HEX)
    assert_output --regexp '[Ee][Ii][Cc][Aa][Rr]'
}

@test "report contains file path" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet -E "$scanid"
    assert_success
    assert_output --partial "$TEST_SCAN_DIR"
}

@test "report for clean scan shows zero hits" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR"
    local scanid
    scanid=$(get_last_scanid)
    run maldet -E "$scanid"
    assert_success
    assert_output --partial "0"
}

@test "session files created for each scan" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR"
    local scanid report
    scanid=$(get_last_scanid)
    report=$(get_session_report_file "$scanid")
    [ -n "$report" ] && [ -f "$report" ]
}

@test "no persistent HTML session file after scan" {
    lmd_set_config email_format "html"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid report
    scanid=$(get_last_scanid)
    # Session file (TSV or plaintext) always created; HTML rendered on-demand, not stored
    report=$(get_session_report_file "$scanid")
    [ -n "$report" ] && [ -f "$report" ]
    [ ! -f "$LMD_INSTALL/sess/session.${scanid}.html" ]
}
