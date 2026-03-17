#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    export LMD_TEST_MODE=1
}

# Helper: source LMD config stack for unit-level function tests.
# Disables errexit and nounset because internals.conf has command -v
# calls that return non-zero for missing binaries.
_source_lmd_stack() {
    set +eu
    source "$LMD_INSTALL/internals/internals.conf"
    source "$LMD_INSTALL/conf.maldet"
    source "$LMD_INSTALL/internals/functions"
}

# --- Test 1: --cron-sigup handler exists and exits cleanly ---
@test "--cron-sigup exits 0 when signatures are current" {
    run maldet --cron-sigup
    assert_success
    # Verify sigup() was actually invoked (not skipped by flock)
    run grep -q '{sigup}' "$LMD_INSTALL/logs/event_log"
    assert_success
}

# --- Test 2: sigup_interval in _safe_source_conf allowlist ---
@test "_safe_source_conf accepts sigup_interval" {
    _source_lmd_stack
    local tmpconf
    tmpconf=$(mktemp)
    echo 'sigup_interval="12"' > "$tmpconf"
    sigup_interval=""
    _safe_source_conf "$tmpconf"
    rm -f "$tmpconf"
    [ "$sigup_interval" = "12" ]
}

# --- Test 3: _safe_source_conf rejects unknown variable ---
@test "_safe_source_conf rejects sigup_bogus" {
    _source_lmd_stack
    local tmpconf
    tmpconf=$(mktemp)
    echo 'sigup_bogus="evil"' > "$tmpconf"
    sigup_bogus=""
    _safe_source_conf "$tmpconf"
    rm -f "$tmpconf"
    [ -z "$sigup_bogus" ]
}

# --- Test 4: conf.maldet contains sigup_interval default ---
@test "conf.maldet defines sigup_interval with default 6" {
    run grep '^sigup_interval=' "$LMD_INSTALL/conf.maldet"
    assert_success
    assert_output --partial '"6"'
}
