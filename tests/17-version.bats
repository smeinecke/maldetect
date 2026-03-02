#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'

LMD_INSTALL="/usr/local/maldetect"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
}

@test "VERSION file exists" {
    [ -f "$LMD_INSTALL/VERSION" ]
}

@test "VERSION file contains current version" {
    run cat "$LMD_INSTALL/VERSION"
    assert_output --partial "2.0.1"
}

@test "maldet reports correct version" {
    run maldet --help
    assert_success
    assert_output --partial "v2.0.1"
}

@test "internals.conf references lmd_version_file" {
    run grep 'lmd_version_file=' "$LMD_INSTALL/internals/internals.conf"
    assert_success
}

@test "maldet ver variable is set to 2.0.1" {
    run grep '^ver=2.0.1' "$LMD_INSTALL/maldet"
    assert_success
}
