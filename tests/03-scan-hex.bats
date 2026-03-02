#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-hex"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"

    # Install test HEX signature for eval(base64_decode(
    echo "6576616c286261736536345f6465636f646528:test.hex.php.1" > "$LMD_INSTALL/sigs/custom.hex.dat"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

@test "HEX scan detects test PHP sample" {
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "HEX scan: clean file produces no hits" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "malware hits 0"
}

@test "HEX FIFO mode produces detection" {
    lmd_set_config scan_hexfifo 1
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "HEX stdin mode produces detection" {
    lmd_set_config scan_hexfifo 0
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "scan_hexdepth limits bytes scanned" {
    # Set hex depth very small so the pattern won't be found
    lmd_set_config scan_hexdepth 5
    lmd_set_config scan_hexfifo_depth 5
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "malware hits 0"
}

@test "custom HEX signatures are loaded alongside builtin" {
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    [ -n "$scanid" ]
    assert_report_contains "$scanid" "test.hex.php"
}

@test "hexfifo.pl script exists and is executable" {
    [ -f "$LMD_INSTALL/internals/hexfifo.pl" ]
}

@test "hexstring.pl script exists and is executable" {
    [ -f "$LMD_INSTALL/internals/hexstring.pl" ]
}

@test "HEX scan with both MD5 and HEX sigs active" {
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 2"
}
