#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-csig"

# Hex constants for test patterns
# CSIG_PATTERN_ALPHA
HEX_ALPHA="435349475f5041545445524e5f414c504841"
# CSIG_PATTERN_BRAVO
HEX_BRAVO="435349475f5041545445524e5f425241564f"
# CSIG_UNIQUE_MARKER_SINGLE
HEX_SINGLE="435349475f554e495155455f4d41524b45525f53494e474c45"
# CSIG_PATTERN_CHARLIE (not in any test file — for miss testing)
HEX_CHARLIE="435349475f5041545445524e5f434841524c4945"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

# --- Test 1: Single-pattern csig detection ---
@test "csig: single-pattern detection" {
    echo "${HEX_SINGLE}:{CSIG}test.csig.single.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 2: AND detection (all subsigs match) ---
@test "csig: AND detection - all subsigs match" {
    echo "${HEX_ALPHA}||${HEX_BRAVO}:{CSIG}test.csig.and.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-and.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 3: AND partial miss (not all match → no detection) ---
@test "csig: AND partial miss - no detection" {
    echo "${HEX_ALPHA}||${HEX_CHARLIE}:{CSIG}test.csig.and.2" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-partial.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 0"
}

# --- Test 4: OR/threshold detection (>=N match) ---
@test "csig: OR threshold detection - meets threshold" {
    # 3 subsigs, threshold 2 — file has ALPHA and BRAVO (2 of 3)
    echo "${HEX_ALPHA}||${HEX_BRAVO}||${HEX_CHARLIE}:{CSIG}test.csig.or.1;2" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-or.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 5: OR/threshold miss (<N match → no detection) ---
@test "csig: OR threshold miss - below threshold" {
    # 3 subsigs, threshold 3 — file has only 2 of 3
    echo "${HEX_ALPHA}||${HEX_BRAVO}||${HEX_CHARLIE}:{CSIG}test.csig.or.2;3" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-or.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 0"
}

# --- Test 6: First-match-wins across stages (MD5 hit → csig skipped) ---
@test "csig: MD5 hit takes priority over csig" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    # Add a csig that would also match eicar
    local eicar_hex
    eicar_hex=$(od -An -tx1 "$SAMPLES_DIR/eicar.com" | tr -d ' \n' | head -c 40)
    echo "${eicar_hex}:{CSIG}test.csig.eicar.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    # Force MD5 hashtype so MD5 pass runs and takes priority
    run maldet -co scan_hashtype=md5 -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
    # Verify hit is from MD5 (in session file), not CSIG
    local scanid
    scanid=$(get_last_scanid)
    local hitsfile; hitsfile=$(get_session_hits_file "$scanid")
    run grep "{MD5}" "$hitsfile"
    assert_success
}

# --- Test 7: First-match-wins within csig.dat (file order) ---
@test "csig: first-match-wins within csig rules" {
    # Two rules that both match — first should win
    printf '%s\n' \
        "${HEX_SINGLE}:{CSIG}test.csig.first.1" \
        "${HEX_SINGLE}:{CSIG}test.csig.second.1" \
        > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
    # Check session hits file for first rule, not second
    local scanid
    scanid=$(get_last_scanid)
    local hitsfile; hitsfile=$(get_session_hits_file "$scanid")
    run grep "test.csig.first" "$hitsfile"
    assert_success
    run grep "test.csig.second" "$hitsfile"
    assert_failure
}

# --- Test 8: scan_csig=0 disables pass ---
@test "csig: scan_csig=0 disables csig scanning" {
    echo "${HEX_SINGLE}:{CSIG}test.csig.single.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    run maldet -co scan_csig=0 -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 0"
}

# --- Test 9: Missing csig.dat → scan completes normally ---
@test "csig: missing csig.dat does not break scan" {
    rm -f "$LMD_INSTALL/sigs/csig.dat" "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 10: Empty csig.dat → scan completes normally ---
@test "csig: empty csig.dat does not break scan" {
    > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 11: Case-insensitive (i:) matching ---
@test "csig: case-insensitive (i:) matching" {
    # Csig_Mixed_Case_Marker in hex (mixed case)
    # Use the uppercase version with i: prefix
    local upper_hex
    upper_hex=$(echo -n "CSIG_MIXED_CASE_MARKER" | od -An -tx1 | tr -d ' \n')
    echo "i:${upper_hex}:{CSIG}test.csig.icase.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-icase.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 12: Wide (w:) matching ---
@test "csig: wide (w:) UTF-16LE matching" {
    # test-csig-wide.txt contains "WIDEMARKER" in UTF-16LE encoding
    # Raw hex for "WIDEMARKER" = 574944454d41524b4552
    # w: prefix causes null-byte interleaving to match UTF-16LE
    echo "w:574944454d41524b4552:{CSIG}test.csig.wide.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-wide.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 13: Bounded gap ({N-M}) matching ---
@test "csig: bounded gap {N-M} wildcard matching" {
    # test-csig-and.php has CSIG_PATTERN_ALPHA (13 bytes between CSIG_ and ALPHA)
    # Match "CSIG_" then {3-20} byte gap then "ALPHA"
    echo "435349475f{3-20}414c504841:{CSIG}test.csig.gap.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-and.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 14: csig hit quarantined ---
@test "csig: detected file is quarantined" {
    echo "${HEX_SINGLE}:{CSIG}test.csig.single.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    lmd_set_config quarantine_hits 1
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_quarantined "$TEST_SCAN_DIR/test-csig-single.php"
}

# --- Test 15: csig hit in scan report with {CSIG} prefix ---
@test "csig: scan report shows {CSIG} prefix" {
    echo "${HEX_SINGLE}:{CSIG}test.csig.single.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
    # Verify {CSIG} prefix in session hits file
    local scanid
    scanid=$(get_last_scanid)
    local hitsfile; hitsfile=$(get_session_hits_file "$scanid")
    run grep "{CSIG}test.csig.single" "$hitsfile"
    assert_success
}

# --- Test 16: Signature count includes csig ---
@test "csig: signature count includes csig sigs" {
    echo "${HEX_SINGLE}:{CSIG}test.csig.single.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "1 USER"
}

# --- Test 17: ignore_sigs filters csig rules ---
@test "csig: ignore_sigs filters csig rules" {
    echo "${HEX_SINGLE}:{CSIG}test.csig.single.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    echo "test.csig.single" > "$LMD_INSTALL/ignore_sigs"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 0"
}

# --- Test 18: Malformed line skipped with warning ---
@test "csig: malformed line skipped with warning" {
    printf '%s\n' \
        "malformed_no_colon_separator" \
        "${HEX_SINGLE}:{CSIG}test.csig.single.1" \
        > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    # Valid rule still detects
    assert_output --partial "malware hits 1"
}

# --- Test 19: Single-worker mode works ---
@test "csig: single-worker mode (scan_workers=1)" {
    echo "${HEX_SINGLE}:{CSIG}test.csig.single.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    run maldet -co scan_workers=1 -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 20: Clean operation strips {CSIG} prefix correctly (CH-001) ---
@test "csig: clean() strips {CSIG} prefix from sig name" {
    echo "${HEX_SINGLE}:{CSIG}test.csig.single.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    lmd_set_config quarantine_hits 1
    lmd_set_config quarantine_clean 1
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    # Should not show error about {CSIG} prefix in clean rule path
    refute_output --partial '{CSIG}test.csig.single'
}

# --- Test 21: OR subsig with ClamAV alternation (a|b) parsed correctly (CH-003) ---
@test "csig: alternation group in subsig does not split incorrectly" {
    # Use an alternation (4d5a|5a4d) inside a subsig to test || parsing
    # The file has CSIG_PATTERN_ALPHA
    echo "(435349475f|deadbeef)||${HEX_ALPHA}:{CSIG}test.csig.altgrp.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-and.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 22: Grouped OR-in-AND detection ---
@test "csig: grouped OR-in-AND detection" {
    # Group: (ALPHA or CHARLIE, need 1) AND BRAVO
    # File has both ALPHA and BRAVO → group match (ALPHA), AND match (BRAVO) → hit
    echo "(${HEX_ALPHA}||${HEX_CHARLIE});1||${HEX_BRAVO}:{CSIG}test.csig.group.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-and.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 23: Group threshold=0 rejected with warning ---
# Validates the threshold=0 guard in _csig_compile_rules() (CH-002/CH-003).
# A rule with threshold=0 would always match every file — the compiler must
# log a WARNING and skip the rule entirely.
@test "csig: group threshold=0 rejected with warning" {
    # Rule with threshold=0: should be skipped
    echo "${HEX_ALPHA}||${HEX_BRAVO}:{CSIG}test.csig.zero.1;0" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-and.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    # threshold=0 rule must NOT produce a hit
    assert_output --partial "malware hits 0"
    # Verify WARNING was logged
    run grep "WARNING: threshold=0 produces always-matching rule" "$LMD_INSTALL/logs/event_log"
    assert_success
}

# --- Test 24: Comments in csig.dat are ignored ---
@test "csig: comment lines in csig.dat are ignored" {
    printf '%s\n' \
        "# This is a comment" \
        "${HEX_SINGLE}:{CSIG}test.csig.single.1" \
        > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}
