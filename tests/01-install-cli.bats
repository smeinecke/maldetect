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

# F-031: PIDFile references monitor.pid
@test "maldet.service PIDFile references monitor.pid" {
    grep -q 'PIDFile=.*monitor\.pid' "$LMD_INSTALL/service/maldet.service"
}

# F-032: EnvironmentFile does not reference conf.maldet
@test "maldet.service EnvironmentFile does not reference conf.maldet" {
    ! grep -q 'EnvironmentFile.*conf\.maldet' "$LMD_INSTALL/service/maldet.service"
}

@test "maldet.service ExecStart uses MONITOR_MODE variable" {
    grep -q 'MONITOR_MODE' "$LMD_INSTALL/service/maldet.service"
}

# F-018: uninstall removes watchdog cron
@test "uninstall.sh removes cron.weekly watchdog" {
    grep -q 'cron.weekly/maldet-watchdog' "$LMD_INSTALL/uninstall.sh"
}

# F-023: install.sh backup mv error check
@test "install.sh checks backup mv exit code" {
    grep -q 'failed to backup' /opt/lmd-src/install.sh
}

# F-019: FreeBSD detection
@test "internals.conf sets os_freebsd variable" {
    grep -q 'os_freebsd=' "$LMD_INSTALL/internals/internals.conf"
}

@test "no OSTYPE FreeBSD checks remain in source files" {
    ! grep -rq 'OSTYPE.*FreeBSD' "$LMD_INSTALL/internals/" "$LMD_INSTALL/maldet"
}

@test "uninstall.sh uses uname for FreeBSD detection" {
    grep -q 'uname -s' "$LMD_INSTALL/uninstall.sh"
}

# Man page tests
@test "maldet.1.gz compressed man page exists at install path" {
    [ -f "$LMD_INSTALL/maldet.1.gz" ]
}

@test "man page symlink exists in system man directory" {
    [ -L /usr/local/share/man/man1/maldet.1.gz ]
}

@test "man page contains expected sections" {
    run zcat "$LMD_INSTALL/maldet.1.gz"
    assert_success
    assert_output --partial "NAME"
    assert_output --partial "SYNOPSIS"
    assert_output --partial "OPTIONS"
    assert_output --partial "EXIT STATUS"
    assert_output --partial "FILES"
}

@test "uninstall.sh removes man page symlink" {
    grep -q 'maldet.1.gz' "$LMD_INSTALL/uninstall.sh"
}

# F-073: Empty SCANID validation
@test "-q without SCANID prints error and exits 1" {
    run maldet -q
    assert_failure
    assert_output --partial "requires a SCANID"
}

@test "-n without SCANID prints error and exits 1" {
    run maldet -n
    assert_failure
    assert_output --partial "requires a SCANID"
}

@test "-s without argument prints error and exits 1" {
    run maldet -s
    assert_failure
    assert_output --partial "requires a SCANID"
}
