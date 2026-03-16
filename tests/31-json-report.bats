#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    TEST_DIR=$(mktemp -d)
}

teardown() {
    rm -rf "$TEST_DIR"
}

# --- Test 1: --json-report outputs valid JSON structure ---
@test "--json-report outputs valid JSON with version 1.0" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -a "$TEST_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet --json-report "$scanid"
    assert_success
    # Check for JSON opening and closing braces
    [[ "$output" == "{"* ]]
    [[ "$output" == *"}" ]]
    assert_output --partial '"version": "1.0"'
}

# --- Test 2: JSON contains type field set to scan ---
@test "--json-report contains type scan" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -a "$TEST_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet --json-report "$scanid"
    assert_success
    assert_output --partial '"type": "scan"'
}

# --- Test 3: JSON hits array has correct count ---
@test "--json-report hits array matches scan hit count" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -a "$TEST_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet --json-report "$scanid"
    assert_success
    # Count index entries in the hits array — each hit has an "index" key
    local hit_count
    hit_count=$(echo "$output" | grep -c '"index":')
    [ "$hit_count" -eq 1 ]
}

# --- Test 4: JSON summary has by_type object ---
@test "--json-report summary contains by_type object" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -a "$TEST_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet --json-report "$scanid"
    assert_success
    assert_output --partial '"by_type":'
}

# --- Test 5: --json-report list outputs report_list type ---
@test "--json-report list outputs report_list type" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -a "$TEST_DIR" || true
    run maldet --json-report list
    assert_success
    assert_output --partial '"type": "report_list"'
}

# --- Test 6: --json-report with invalid SCANID exits non-zero ---
@test "--json-report with invalid SCANID exits non-zero" {
    run maldet --json-report "999999.99999"
    assert_failure
}

# --- Test 7: JSON quarantine_enabled is boolean ---
@test "--json-report quarantine_enabled is boolean true or false" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -a "$TEST_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet --json-report "$scanid"
    assert_success
    # quarantine_enabled must be true or false (JSON boolean), not 1 or 0
    local qval
    qval=$(echo "$output" | grep '"quarantine_enabled"' | head -1)
    [[ "$qval" == *"true"* ]] || [[ "$qval" == *"false"* ]]
    # Must NOT contain quoted "1" or "0" for this field
    [[ "$qval" != *'"1"'* ]]
    [[ "$qval" != *'"0"'* ]]
}

# --- Test 8: JSON contains scanner version ---
@test "--json-report contains scanner version" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -a "$TEST_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet --json-report "$scanid"
    assert_success
    assert_output --partial '"name": "Linux Malware Detect"'
}

# --- Test 9: JSON hit entry contains signature and file path ---
@test "--json-report hit entries contain signature and file fields" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -co scan_hashtype=md5 -a "$TEST_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet --json-report "$scanid"
    assert_success
    assert_output --partial '"signature":'
    assert_output --partial '"file":'
    assert_output --partial "eicar"
}

# --- Test 10: Clean scan JSON has empty hits array ---
@test "--json-report for clean scan has zero hits" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_DIR/"
    maldet -a "$TEST_DIR"
    local scanid
    scanid=$(get_last_scanid)
    run maldet --json-report "$scanid"
    assert_success
    assert_output --partial '"total_hits": 0'
}

# --- Test 11: JSON report newest defaults to most recent scan ---
@test "--json-report with no SCANID defaults to newest scan" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -a "$TEST_DIR" || true
    run maldet --json-report
    assert_success
    assert_output --partial '"version": "1.0"'
    assert_output --partial '"type": "scan"'
}

# --- Test 12: JSON list version field present ---
@test "--json-report list contains version 1.0" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -a "$TEST_DIR" || true
    run maldet --json-report list
    assert_success
    assert_output --partial '"version": "1.0"'
}
