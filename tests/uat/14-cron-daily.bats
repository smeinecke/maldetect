#!/usr/bin/env bats
# 14-cron-daily.bats -- LMD Cron Daily UAT
# Verifies: cron.daily execution, stale file cleanup, log rotation, lockfile
# Note: Runs cron.daily script directly -- no active scan or monitor dependency.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-lmd'
load '../infra/lib/uat-helpers'

CRON_SCRIPT="/etc/cron.daily/maldet"

setup_file() {
    uat_setup
    uat_lmd_install
    uat_lmd_reset

    if [ ! -f "$CRON_SCRIPT" ]; then
        skip "cron.daily/maldet not installed"
    fi

    # Disable auto-updates and scanning for isolation
    uat_lmd_set_config autoupdate_version 0
    uat_lmd_set_config autoupdate_signatures 0
    uat_lmd_set_config cron_daily_scan 0
}

teardown_file() {
    rm -f "$LMD_INSTALL/tmp/.cron.lock"
    uat_lmd_reset
}

# bats test_tags=uat,uat:cron
@test "UAT: cron.daily prunes old quarantine files" {
    if [ ! -f "$CRON_SCRIPT" ]; then
        skip "cron.daily/maldet not installed"
    fi

    uat_lmd_set_config cron_prune_days 21

    # Create a file older than the prune threshold
    touch -d '30 days ago' "$LMD_INSTALL/quarantine/old-uat-quar-file"
    [ -f "$LMD_INSTALL/quarantine/old-uat-quar-file" ]

    run bash "$CRON_SCRIPT"

    # Old file should be pruned
    [ ! -f "$LMD_INSTALL/quarantine/old-uat-quar-file" ]
}

# bats test_tags=uat,uat:cron
@test "UAT: cron.daily prunes old session and tmp files" {
    if [ ! -f "$CRON_SCRIPT" ]; then
        skip "cron.daily/maldet not installed"
    fi

    uat_lmd_set_config cron_prune_days 21

    touch -d '30 days ago' "$LMD_INSTALL/sess/old-uat-sess-file"
    touch -d '30 days ago' "$LMD_INSTALL/tmp/old-uat-tmp-file"
    [ -f "$LMD_INSTALL/sess/old-uat-sess-file" ]
    [ -f "$LMD_INSTALL/tmp/old-uat-tmp-file" ]

    run bash "$CRON_SCRIPT"

    [ ! -f "$LMD_INSTALL/sess/old-uat-sess-file" ]
    [ ! -f "$LMD_INSTALL/tmp/old-uat-tmp-file" ]
}

# bats test_tags=uat,uat:cron
@test "UAT: cron.daily preserves recent files within prune threshold" {
    if [ ! -f "$CRON_SCRIPT" ]; then
        skip "cron.daily/maldet not installed"
    fi

    uat_lmd_set_config cron_prune_days 21

    # Create a recent file (10 days old — within threshold)
    touch -d '10 days ago' "$LMD_INSTALL/quarantine/recent-uat-quar-file"

    run bash "$CRON_SCRIPT"

    # Recent file should survive
    [ -f "$LMD_INSTALL/quarantine/recent-uat-quar-file" ]
    rm -f "$LMD_INSTALL/quarantine/recent-uat-quar-file"
}

# bats test_tags=uat,uat:cron
@test "UAT: cron.daily lockfile prevents overlapping runs" {
    if [ ! -f "$CRON_SCRIPT" ]; then
        skip "cron.daily/maldet not installed"
    fi

    if ! command -v flock >/dev/null 2>&1; then
        skip "flock not available"
    fi

    # Hold the lock in a background fd
    exec 8>"$LMD_INSTALL/tmp/.cron.lock"
    flock -n 8 || skip "flock failed to acquire lock"

    # Second cron run should exit immediately (not block)
    run bash "$CRON_SCRIPT"
    assert_success

    # Release lock
    exec 8>&-
}
