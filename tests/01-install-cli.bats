#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'

LMD_INSTALL="/usr/local/maldetect"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
}

@test "LMD is installed to /usr/local/maldetect" {
    [ -d "$LMD_INSTALL" ]
}

@test "maldet executable exists and is executable" {
    [ -x "$LMD_INSTALL/maldet" ]
}

@test "symlink /usr/local/sbin/maldet exists" {
    [ -L "/usr/local/sbin/maldet" ]
    [ -x "/usr/local/sbin/maldet" ]
}

@test "symlink /usr/local/sbin/lmd exists" {
    [ -L "/usr/local/sbin/lmd" ]
    [ -x "/usr/local/sbin/lmd" ]
}

@test "maldet --help exits 0" {
    run maldet --help
    assert_success
}

@test "maldet --help displays usage information" {
    run maldet --help
    assert_success
    assert_output --partial "maldet"
}

@test "maldet -l shows event log" {
    run maldet -l
    assert_success
}

@test "internals.conf exists" {
    [ -f "$LMD_INSTALL/internals/internals.conf" ]
}

@test "conf.maldet exists" {
    [ -f "$LMD_INSTALL/conf.maldet" ]
}

@test "functions library exists" {
    [ -f "$LMD_INSTALL/internals/functions" ]
}

@test "signature directory exists" {
    [ -d "$LMD_INSTALL/sigs" ]
}

@test "quarantine directory exists with correct permissions" {
    [ -d "$LMD_INSTALL/quarantine" ]
    local perms
    perms=$(stat -c '%a' "$LMD_INSTALL/quarantine")
    [ "$perms" = "750" ]
}

@test "session directory exists" {
    [ -d "$LMD_INSTALL/sess" ]
}

@test "tmp directory exists" {
    [ -d "$LMD_INSTALL/tmp" ]
}

@test "version output is correct" {
    run maldet --help
    assert_success
    assert_output --partial "Linux Malware Detect v"
}

@test "-co config option override works" {
    run maldet -co scan_max_filesize=1024 --help
    assert_success
}

@test "invalid argument returns exit code 1" {
    run maldet --invalid-option
    assert_failure
    assert_output --partial "unrecognized option"
}
