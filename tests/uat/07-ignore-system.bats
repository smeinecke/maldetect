#!/usr/bin/env bats
# 07-ignore-system.bats — LMD Ignore System UAT
# Verifies: ignore by path, ignore by extension, ignore by signature

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-lmd'
load '../infra/lib/uat-helpers'

TEST_DIR="/tmp/uat-lmd-test/ignore"

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

# --- Ignore by path ---

# bats test_tags=uat,uat:ignore-system
@test "UAT: add path to ignore_paths" {
    echo "$TEST_DIR/ignored/" >> "$LMD_INSTALL/ignore_paths"
    run grep -c "$TEST_DIR/ignored/" "$LMD_INSTALL/ignore_paths"
    assert_success
}

# bats test_tags=uat,uat:ignore-system
@test "UAT: EICAR in ignored path is not detected" {
    mkdir -p "$TEST_DIR/ignored"
    uat_lmd_create_eicar "$TEST_DIR/ignored"

    uat_capture "ignore-path" maldet -a "$TEST_DIR/ignored/"
    # Should be clean (exit 0) because path is ignored
    assert_success
}

# bats test_tags=uat,uat:ignore-system
@test "UAT: EICAR outside ignored path is still detected" {
    mkdir -p "$TEST_DIR/scanned"
    uat_lmd_create_eicar "$TEST_DIR/scanned"

    uat_capture "ignore-path" maldet -a "$TEST_DIR/scanned/"
    [ "$status" -eq 2 ]
}

# --- Ignore by extension ---

# bats test_tags=uat,uat:ignore-system
@test "UAT: add extension to ignore_file_ext" {
    # Reset ignore_paths so it does not interfere
    : > "$LMD_INSTALL/ignore_paths"
    echo ".skipme" >> "$LMD_INSTALL/ignore_file_ext"
    run grep -c ".skipme" "$LMD_INSTALL/ignore_file_ext"
    assert_success
}

# bats test_tags=uat,uat:ignore-system
@test "UAT: EICAR with ignored extension is not detected" {
    mkdir -p "$TEST_DIR/ext-test"
    uat_lmd_create_eicar "$TEST_DIR/ext-test" "malware.skipme"

    uat_capture "ignore-ext" maldet -a "$TEST_DIR/ext-test/"
    # Should be clean because extension is ignored
    assert_success
}

# bats test_tags=uat,uat:ignore-system
@test "UAT: EICAR with non-ignored extension is detected" {
    mkdir -p "$TEST_DIR/ext-test2"
    uat_lmd_create_eicar "$TEST_DIR/ext-test2" "malware.txt"

    uat_capture "ignore-ext" maldet -a "$TEST_DIR/ext-test2/"
    [ "$status" -eq 2 ]
}

# --- Ignore by signature ---

# bats test_tags=uat,uat:ignore-system
@test "UAT: add signature to ignore_sigs" {
    : > "$LMD_INSTALL/ignore_file_ext"
    # Signature names use format like EICAR.TEST — match the base name
    echo "EICAR.TEST" >> "$LMD_INSTALL/ignore_sigs"
    run grep -c "EICAR.TEST" "$LMD_INSTALL/ignore_sigs"
    assert_success
}

# bats test_tags=uat,uat:ignore-system
@test "UAT: EICAR ignored by signature name" {
    mkdir -p "$TEST_DIR/sig-test"
    uat_lmd_create_eicar "$TEST_DIR/sig-test"

    uat_capture "ignore-sig" maldet -a "$TEST_DIR/sig-test/"
    # Should be clean because EICAR.TEST signature is ignored
    assert_success
}
