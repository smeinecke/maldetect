#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-clamav"
MOCK_CLAMAV_DIR="/tmp/mock-clamav"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"
    rm -rf "$MOCK_CLAMAV_DIR"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR" "$MOCK_CLAMAV_DIR"
    # Restore clamav_paths in internals.conf if modified
    if [ -f "$LMD_INSTALL/internals/internals.conf.bak" ]; then
        mv "$LMD_INSTALL/internals/internals.conf.bak" "$LMD_INSTALL/internals/internals.conf"
    fi
}

@test "gensigs creates NDB symlink in sigdir after scan" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR"
    [ -L "$LMD_INSTALL/sigs/lmd.user.ndb" ]
}

@test "gensigs creates HDB symlink in sigdir after scan" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR"
    [ -L "$LMD_INSTALL/sigs/lmd.user.hdb" ]
}

@test "gensigs merges custom hex signatures into scan" {
    # Add custom hex sig and verify it produces a detection
    echo "6576616c286261736536345f6465636f646528:custom.gensigs.test.1" \
        > "$LMD_INSTALL/sigs/custom.hex.dat"
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    assert_report_contains "$scanid" "custom.gensigs.test"
}

@test "clamav_linksigs copies signatures to mock ClamAV directory" {
    mkdir -p "$MOCK_CLAMAV_DIR"
    # Create a mock main.cvd so clamav_linksigs recognizes this as a ClamAV dir
    touch "$MOCK_CLAMAV_DIR/main.cvd"
    # Add mock dir to clamav_paths
    cp "$LMD_INSTALL/internals/internals.conf" "$LMD_INSTALL/internals/internals.conf.bak"
    sed -i "s|^clamav_paths=.*|clamav_paths=\"$MOCK_CLAMAV_DIR\"|" "$LMD_INSTALL/internals/internals.conf"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR"
    # rfxn.hdb and rfxn.ndb should be copied to the mock dir
    [ -f "$MOCK_CLAMAV_DIR/rfxn.hdb" ] || [ -f "$MOCK_CLAMAV_DIR/rfxn.ndb" ]
}

@test "clamav_linksigs skips non-existent directories" {
    cp "$LMD_INSTALL/internals/internals.conf" "$LMD_INSTALL/internals/internals.conf.bak"
    sed -i 's|^clamav_paths=.*|clamav_paths="/nonexistent/clamav/path"|' "$LMD_INSTALL/internals/internals.conf"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    # Should complete without error
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
}

@test "scan completes with native engine when scan_clamscan=0" {
    lmd_set_config scan_clamscan 0
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "scan_clamscan=1 without ClamAV binaries falls back gracefully" {
    lmd_set_config scan_clamscan 1
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    # No ClamAV installed in test container — clamselector sets scan_clamscan=0
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# Helper: source LMD config stack for unit-level function tests.
# Disables errexit and nounset because internals.conf has command -v
# calls that return non-zero for missing binaries.
_source_lmd_stack_clamav() {
    set +eu
    source "$LMD_INSTALL/internals/internals.conf"
    source "$LMD_INSTALL/conf.maldet"
    source "$LMD_INSTALL/internals/functions"
}

# S-003: F-006 unit test — _process_clamav_hits() colon-path parsing
# ClamAV output uses ": " (colon-space) as the filepath/signame separator.
# Filepaths containing colons must not be truncated at the first colon.
# The greedy sed in _process_clamav_hits() ensures the full filepath
# (including colons) is captured.
@test "_process_clamav_hits parses filepath containing colons" {
    _source_lmd_stack_clamav

    # Create a file with a colon in its path for the [ -f ] check
    local colon_dir="$TEST_SCAN_DIR/path:with:colons"
    mkdir -p "$colon_dir"
    echo "malicious content for testing" > "$colon_dir/evil.php"

    # Set up minimal infrastructure for _process_clamav_hits
    local scan_session_file
    scan_session_file=$(mktemp "$tmpdir/.scan_session.XXXXXX")
    scan_session="$scan_session_file"
    hits_history=$(mktemp "$tmpdir/.hits_hist.XXXXXX")
    progress_hits=0
    quarantine_hits=0
    _in_scan_context=""

    # Create mock ClamAV results in the format clamscan produces:
    #   /path/to/file: Sig.Name FOUND
    local mock_results
    mock_results=$(mktemp "$tmpdir/.mock_clam_results.XXXXXX")
    echo "$colon_dir/evil.php: Php.Malware.TestSig-1 FOUND" > "$mock_results"

    # Call the function under test
    _process_clamav_hits "$mock_results" ""

    # Verify the full colon-containing filepath appears in scan_session
    run grep -F "$colon_dir/evil.php" "$scan_session_file"
    assert_success

    # Verify the signature was recorded with {CAV} prefix
    run grep -F "{CAV}Php.Malware.TestSig-1" "$scan_session_file"
    assert_success

    # Cleanup
    rm -f "$mock_results" "$scan_session_file" "$hits_history"
    rm -rf "$colon_dir"
}
