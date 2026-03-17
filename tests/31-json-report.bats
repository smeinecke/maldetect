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

# --- Test 13: Legacy JSON support ---
@test "--json-report renders legacy plaintext session as JSON" {
    local sessdir="$LMD_INSTALL/sess"
    local sid="991231-2359.99999"
    # Create synthetic legacy session file
    cat > "$sessdir/session.$sid" <<'LEGACY'
HOST:      testhost.example.com
SCAN ID:   991231-2359.99999
STARTED:   Dec 31 2099 23:59:59 +0000
COMPLETED: Jan 01 2100 00:00:05 +0000
ELAPSED:   6s [find: 1s]
PATH:      /home/testuser/public_html
TOTAL FILES: 42
TOTAL HITS:  1
TOTAL CLEANED: 0

FILE HIT LIST:
{HEX}php.cmdshell.unclassed.365 : /home/testuser/public_html/evil.php
LEGACY
    cat > "$sessdir/session.hits.$sid" <<'HITS'
{HEX}php.cmdshell.unclassed.365 : /home/testuser/public_html/evil.php
HITS
    run maldet --json-report "$sid"
    rm -f "$sessdir/session.$sid" "$sessdir/session.hits.$sid"
    assert_success
    assert_output --partial '"version": "1.0"'
    assert_output --partial '"source": "legacy"'
    assert_output --partial '"type": "scan"'
    assert_output --partial '"id": "991231-2359.99999"'
    assert_output --partial '"hostname": "testhost.example.com"'
    assert_output --partial '"signature": "{HEX}php.cmdshell.unclassed.365"'
}

# --- Test 14: Legacy JSON has null for enriched fields ---
@test "--json-report legacy session has null for enriched fields" {
    local sessdir="$LMD_INSTALL/sess"
    local sid="991231-2359.99998"
    cat > "$sessdir/session.$sid" <<'LEGACY'
HOST:      testhost.example.com
SCAN ID:   991231-2359.99998
STARTED:   Dec 31 2099 23:59:59 +0000
COMPLETED: Jan 01 2100 00:00:05 +0000
ELAPSED:   6s [find: 1s]
PATH:      /home/testuser
TOTAL FILES: 10
TOTAL HITS:  1
TOTAL CLEANED: 0

FILE HIT LIST:
{MD5}md5.test.sig.1 : /home/testuser/bad.php
LEGACY
    cat > "$sessdir/session.hits.$sid" <<'HITS'
{MD5}md5.test.sig.1 : /home/testuser/bad.php
HITS
    run maldet --json-report "$sid"
    rm -f "$sessdir/session.$sid" "$sessdir/session.hits.$sid"
    assert_success
    # Enriched fields unavailable in legacy format → null
    assert_output --partial '"hash": null'
    assert_output --partial '"size": null'
    assert_output --partial '"owner": null'
    assert_output --partial '"host_id": null'
}

# --- Test 15: Legacy JSON with zero hits has empty hits array ---
@test "--json-report legacy session with zero hits has empty hits array" {
    local sessdir="$LMD_INSTALL/sess"
    local sid="991231-2359.99997"
    cat > "$sessdir/session.$sid" <<'LEGACY'
HOST:      testhost.example.com
SCAN ID:   991231-2359.99997
STARTED:   Dec 31 2099 23:59:59 +0000
COMPLETED: Jan 01 2100 00:00:01 +0000
ELAPSED:   1s [find: 0s]
PATH:      /home/cleanuser
TOTAL FILES: 100
TOTAL HITS:  0
TOTAL CLEANED: 0
LEGACY
    run maldet --json-report "$sid"
    rm -f "$sessdir/session.$sid"
    assert_success
    # Empty hits array renders as "hits": [\n    ] (awk always emits newline before close bracket)
    assert_output --partial '"hits": ['
    assert_output --partial '"total_hits": 0'
    # Verify no hit entries exist (no "index" keys)
    local hit_count
    hit_count=$(echo "$output" | grep -c '"index":' || true)
    [ "$hit_count" -eq 0 ]
}

# --- Test 16: Legacy JSON list includes legacy sessions ---
@test "--json-report list includes legacy sessions" {
    local sessdir="$LMD_INSTALL/sess"
    local sid="991231-2359.99996"
    cat > "$sessdir/session.$sid" <<'LEGACY'
HOST:      testhost.example.com
SCAN ID:   991231-2359.99996
STARTED:   Dec 31 2099 23:59:59 +0000
COMPLETED: Jan 01 2100 00:00:05 +0000
ELAPSED:   6s [find: 1s]
PATH:      /home/testuser
TOTAL FILES: 42
TOTAL HITS:  1
TOTAL CLEANED: 0

FILE HIT LIST:
{HEX}php.cmdshell.unclassed.365 : /home/testuser/evil.php
LEGACY
    run maldet --json-report list
    rm -f "$sessdir/session.$sid"
    assert_success
    assert_output --partial '"991231-2359.99996"'
    assert_output --partial '"source": "legacy"'
}

# --- Test 17: Legacy JSON with hits-only file (no session header) ---
@test "--json-report works with hits-only file (no session header)" {
    local sessdir="$LMD_INSTALL/sess"
    local sid="991231-2359.99995"
    # Only session.hits file, no session file
    cat > "$sessdir/session.hits.$sid" <<'HITS'
{HEX}php.cmdshell.unclassed.365 : /home/testuser/evil.php
HITS
    run maldet --json-report "$sid"
    rm -f "$sessdir/session.hits.$sid"
    assert_success
    assert_output --partial '"version": "1.0"'
    assert_output --partial '"source": "legacy"'
    assert_output --partial '"signature": "{HEX}php.cmdshell.unclassed.365"'
}

# --- Test 18: Legacy JSON sanitizes bash 4.x {YARA\} artifact ---
@test "--json-report legacy session sanitizes bash 4.x YARA backslash artifact" {
    local sessdir="$LMD_INSTALL/sess"
    local sid="991231-2359.99994"
    # Simulate pre-4d914a3 session data: bash 4.x ${var/pat/repl} produced {YARA\}
    cat > "$sessdir/session.$sid" <<'LEGACY'
HOST:      testhost.example.com
SCAN ID:   991231-2359.99994
STARTED:   Dec 31 2099 23:59:59 +0000
COMPLETED: Jan 01 2100 00:00:05 +0000
ELAPSED:   6s [find: 1s]
PATH:      /home/testuser/public_html
TOTAL FILES: 100
TOTAL HITS:  2
TOTAL CLEANED: 0

FILE HIT LIST:
LEGACY
    # Write hits with literal backslash before } — the bash 4.x artifact
    printf '{YARA\\}Safe0ver_Shell__Safe_Mod_Bypass_By_Evilc0der_php : /home/testuser/public_html/shell.php\n' \
        > "$sessdir/session.hits.$sid"
    printf '{HEX}php.cmdshell.r57.339 : /home/testuser/public_html/r57.php\n' \
        >> "$sessdir/session.hits.$sid"
    run maldet --json-report "$sid"
    rm -f "$sessdir/session.$sid" "$sessdir/session.hits.$sid"
    assert_success
    # Signature must have clean {YARA} prefix — no backslash
    assert_output --partial '"signature": "{YARA}Safe0ver_Shell__Safe_Mod_Bypass_By_Evilc0der_php"'
    # hit_type must be extracted correctly (was empty before fix)
    assert_output --partial '"hit_type": "YARA"'
    assert_output --partial '"hit_type_label": "YARA Rule"'
    # HEX hit in same scan must still work correctly
    assert_output --partial '"hit_type": "HEX"'
}

# --- Test 19: --format json with -e produces JSON ---
@test "--format json with -e produces JSON output" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -a "$TEST_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet --format json -e "$scanid"
    assert_success
    assert_output --partial '"version": "1.0"'
    assert_output --partial '"type": "scan"'
}

# --- Test 20: --format json with -e list produces JSON list ---
@test "--format json with -e list produces JSON list" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -a "$TEST_DIR" || true
    run maldet --format json -e list
    assert_success
    assert_output --partial '"type": "report_list"'
}

# --- Test 21: --format html with -e produces HTML ---
@test "--format html with -e produces HTML output" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -a "$TEST_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet --format html -e "$scanid"
    assert_success
    # HTML output should not contain copyright banner
    refute_output --partial 'This program may be freely redistributed'
}

# --- Test 22: --format with invalid value exits error ---
@test "--format with invalid value exits with error" {
    run maldet --format xml -e list
    assert_failure
    assert_output --partial 'ERROR: --format requires text, json, or html'
}

# --- Test 23: --format json position-independent (after -e) ---
@test "--format json works after -e flag" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -a "$TEST_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet -e "$scanid" --format json
    assert_success
    assert_output --partial '"version": "1.0"'
}
