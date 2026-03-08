#!/usr/bin/env bats
# 12-signature-management.bats -- LMD Signature Management UAT
# Verifies: custom signatures, signature listing, gensigs merge behavior

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-lmd'
load '../infra/lib/uat-helpers'

TEST_DIR="/tmp/uat-lmd-test/sig-mgmt"

setup_file() {
    uat_setup
    uat_lmd_install
    uat_lmd_reset
    mkdir -p "$TEST_DIR"
}

teardown_file() {
    rm -rf "$TEST_DIR"
    uat_lmd_reset
}

# bats test_tags=uat,uat:signatures
@test "UAT: custom HEX signature injection produces detection" {
    # Inject hex sig for eval(base64_decode(
    echo "6576616c286261736536345f6465636f646528:uat.sig.hex.test.1" \
        > "$LMD_INSTALL/sigs/custom.hex.dat"

    printf '<?php eval(base64_decode("test")); ?>' > "$TEST_DIR/hex-test.php"

    uat_capture "sig-mgmt" maldet -a "$TEST_DIR"
    [ "$status" -eq 2 ]
    assert_output --partial "malware hits 1"
}

# bats test_tags=uat,uat:signatures
@test "UAT: custom MD5 signature injection produces detection" {
    rm -f "$TEST_DIR"/*
    : > "$LMD_INSTALL/sigs/custom.hex.dat"

    # Create a test file with known content
    echo "uat-md5-sig-test-content-12345" > "$TEST_DIR/md5-test.txt"

    # Compute its MD5 and size, inject as custom sig
    local file_md5 file_size
    file_md5="$(md5sum "$TEST_DIR/md5-test.txt" | cut -d' ' -f1)"
    file_size="$(stat -c '%s' "$TEST_DIR/md5-test.txt")"
    echo "${file_md5}:${file_size}:{MD5}uat.sig.md5.test.1" \
        > "$LMD_INSTALL/sigs/custom.md5.dat"

    uat_capture "sig-mgmt" maldet -a "$TEST_DIR"
    [ "$status" -eq 2 ]
    assert_output --partial "malware hits 1"
}

# bats test_tags=uat,uat:signatures
@test "UAT: scan output shows signature counts" {
    rm -f "$TEST_DIR"/*
    : > "$LMD_INSTALL/sigs/custom.md5.dat"
    : > "$LMD_INSTALL/sigs/custom.hex.dat"

    uat_lmd_create_eicar "$TEST_DIR"

    uat_capture "sig-mgmt" maldet -a "$TEST_DIR"
    [ "$status" -eq 2 ]
    assert_output --partial "signatures loaded"
}

# bats test_tags=uat,uat:signatures
@test "UAT: default signature files exist and are non-empty" {
    [ -s "$LMD_INSTALL/sigs/md5v2.dat" ]
    [ -s "$LMD_INSTALL/sigs/hex.dat" ]
    [ -f "$LMD_INSTALL/sigs/maldet.sigs.ver" ]
}

# bats test_tags=uat,uat:signatures
@test "UAT: gensigs merges custom signatures into scan results" {
    rm -f "$TEST_DIR"/*
    rm -rf "$LMD_INSTALL/sess/"*
    : > "$LMD_INSTALL/sigs/custom.md5.dat"

    # Inject a custom HEX sig and scan a matching file
    echo "6576616c286261736536345f6465636f646528:uat.merge.test.1" \
        > "$LMD_INSTALL/sigs/custom.hex.dat"

    # Suppress builtin sigs that match the same pattern so the custom one shows
    echo "php.base64.inject" > "$LMD_INSTALL/ignore_sigs"

    printf '<?php eval(base64_decode("test")); ?>' > "$TEST_DIR/merge-test.php"

    run maldet -a "$TEST_DIR"
    [ "$status" -eq 2 ]

    local scanid
    scanid="$(uat_lmd_last_scanid)"
    [ -n "$scanid" ]

    # Report should reference the custom signature name
    uat_capture "sig-mgmt" maldet -e "$scanid"
    assert_success
    assert_output --partial "uat.merge.test"

    # Clean up ignore override
    : > "$LMD_INSTALL/ignore_sigs"
}
