#!/usr/bin/env bats
# 30-monitor-utils.bats — Unit tests for monitor mode utility functions

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'

LMD_INSTALL="/usr/local/maldetect"

# --- Helper: source LMD functions into test scope ---
_source_lmd_stack() {
    set +eu
    trap - ERR  # bash 5.1: BATS ERR trap leaks into sourced files even with set +e
    export inspath="$LMD_INSTALL"
    # shellcheck disable=SC1090,SC1091
    source "$LMD_INSTALL/internals/internals.conf"
    # shellcheck disable=SC1090,SC1091
    source "$LMD_INSTALL/conf.maldet"
    # shellcheck disable=SC1090,SC1091
    source "$LMD_INSTALL/internals/tlog_lib.sh"
    # shellcheck disable=SC1090,SC1091
    source "$LMD_INSTALL/internals/elog_lib.sh"
    # shellcheck disable=SC1090,SC1091
    source "$LMD_INSTALL/internals/alert_lib.sh"
    # shellcheck disable=SC1090,SC1091
    source "$LMD_INSTALL/internals/lmd_alert.sh"
    # shellcheck disable=SC1090,SC1091
    source "$LMD_INSTALL/internals/lmd.lib.sh"
    set -eu
}

# --- _monitor_parse_interval ---

# bats test_tags=monitor,unit
@test "monitor: _monitor_parse_interval parses hours" {
    _source_lmd_stack
    run _monitor_parse_interval "24h"
    [ "$status" -eq 0 ]
    [ "$output" = "86400" ]
}

# bats test_tags=monitor,unit
@test "monitor: _monitor_parse_interval parses minutes" {
    _source_lmd_stack
    run _monitor_parse_interval "30m"
    [ "$status" -eq 0 ]
    [ "$output" = "1800" ]
}

# bats test_tags=monitor,unit
@test "monitor: _monitor_parse_interval parses days" {
    _source_lmd_stack
    run _monitor_parse_interval "7d"
    [ "$status" -eq 0 ]
    [ "$output" = "604800" ]
}

# bats test_tags=monitor,unit
@test "monitor: _monitor_parse_interval returns 0 for disabled" {
    _source_lmd_stack
    run _monitor_parse_interval "0"
    [ "$status" -eq 0 ]
    [ "$output" = "0" ]
}

# bats test_tags=monitor,unit
@test "monitor: _monitor_parse_interval rejects invalid inputs" {
    _source_lmd_stack
    # Invalid suffix
    run _monitor_parse_interval "10x"
    [ "$status" -eq 1 ]
    # Empty string
    run _monitor_parse_interval ""
    [ "$status" -eq 1 ]
    # Non-numeric
    run _monitor_parse_interval "abc"
    [ "$status" -eq 1 ]
}

# bats test_tags=monitor,unit
@test "monitor: _monitor_parse_interval handles 1h" {
    _source_lmd_stack
    run _monitor_parse_interval "1h"
    [ "$status" -eq 0 ]
    [ "$output" = "3600" ]
}

# --- _monitor_escape_ere ---

# bats test_tags=monitor,unit
@test "monitor: _monitor_escape_ere escapes dot" {
    _source_lmd_stack
    run _monitor_escape_ere "/home/user/.cache"
    [ "$status" -eq 0 ]
    [ "$output" = '/home/user/\.cache' ]
}

# bats test_tags=monitor,unit
@test "monitor: _monitor_escape_ere escapes multiple metacharacters" {
    _source_lmd_stack
    run _monitor_escape_ere "/path/with+special(chars)*"
    [ "$status" -eq 0 ]
    [ "$output" = '/path/with\+special\(chars\)\*' ]
}

# bats test_tags=monitor,unit
@test "monitor: _monitor_escape_ere escapes all POSIX ERE metacharacters" {
    _source_lmd_stack
    run _monitor_escape_ere '.+*?()[]{}|\\^$'
    [ "$status" -eq 0 ]
    # Verify each metachar category is escaped (avoids BATS bash 5.1
    # compilation bug with dense backslash sequences in [ = ] assertions)
    [[ "$output" == *'\.'* ]]
    [[ "$output" == *'\+'* ]]
    [[ "$output" == *'\*'* ]]
    [[ "$output" == *'\?'* ]]
    [[ "$output" == *'\('* ]]
    [[ "$output" == *'\)'* ]]
    [[ "$output" == *'\['* ]]
    [[ "$output" == *'\]'* ]]
    [[ "$output" == *'\{'* ]]
    [[ "$output" == *'\}'* ]]
    [[ "$output" == *'\|'* ]]
    [[ "$output" == *'\^'* ]]
    [[ "$output" == *'\$'* ]]
}

# bats test_tags=monitor,unit
@test "monitor: _monitor_escape_ere passes through plain paths" {
    _source_lmd_stack
    run _monitor_escape_ere "/home/user/public_html"
    [ "$status" -eq 0 ]
    [ "$output" = "/home/user/public_html" ]
}

# bats test_tags=monitor,unit
@test "monitor: _monitor_escape_ere handles empty string" {
    _source_lmd_stack
    run _monitor_escape_ere ""
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

# --- _monitor_filter_events ---

# bats test_tags=monitor,unit
@test "monitor: _monitor_filter_events extracts CREATE events" {
    _source_lmd_stack
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "/home/user/public_html/shell.php CREATE 18 Mar 10:30:01" > "$tmpdir/events"
    printf '' > "$tmpdir/ignore"
    run _monitor_filter_events "$tmpdir/ignore" < "$tmpdir/events"
    [ "$status" -eq 0 ]
    [ "$output" = "/home/user/public_html/shell.php" ]
    rm -rf "$tmpdir"
}

# bats test_tags=monitor,unit
@test "monitor: _monitor_filter_events deduplicates paths" {
    _source_lmd_stack
    local tmpdir
    tmpdir=$(mktemp -d)
    cat > "$tmpdir/events" <<'EVENTS'
/home/user/file.php CREATE 18 Mar 10:30:01
/home/user/file.php MODIFY 18 Mar 10:30:02
/home/user/file.php CREATE 18 Mar 10:30:03
EVENTS
    printf '' > "$tmpdir/ignore"
    run _monitor_filter_events "$tmpdir/ignore" < "$tmpdir/events"
    [ "$status" -eq 0 ]
    [ "$(echo "$output" | wc -l)" -eq 1 ]
    [ "$output" = "/home/user/file.php" ]
    rm -rf "$tmpdir"
}

# bats test_tags=monitor,unit
@test "monitor: _monitor_filter_events applies ignore_paths substring match" {
    _source_lmd_stack
    local tmpdir
    tmpdir=$(mktemp -d)
    cat > "$tmpdir/events" <<'EVENTS'
/home/user/public_html/good.php CREATE 18 Mar 10:30:01
/home/user/.cache/bad.tmp CREATE 18 Mar 10:30:02
/home/user/public_html/ok.js MODIFY 18 Mar 10:30:03
EVENTS
    echo "/home/user/.cache" > "$tmpdir/ignore"
    run _monitor_filter_events "$tmpdir/ignore" < "$tmpdir/events"
    [ "$status" -eq 0 ]
    [ "$(echo "$output" | wc -l)" -eq 2 ]
    echo "$output" | grep -q "good.php"
    echo "$output" | grep -q "ok.js"
    ! echo "$output" | grep -q "bad.tmp"
    rm -rf "$tmpdir"
}

# bats test_tags=monitor,unit
@test "monitor: _monitor_filter_events ignores non-target events" {
    _source_lmd_stack
    local tmpdir
    tmpdir=$(mktemp -d)
    cat > "$tmpdir/events" <<'EVENTS'
/home/user/file.php DELETE 18 Mar 10:30:01
/home/user/dir ACCESS 18 Mar 10:30:02
/home/user/new.php CREATE 18 Mar 10:30:03
EVENTS
    printf '' > "$tmpdir/ignore"
    run _monitor_filter_events "$tmpdir/ignore" < "$tmpdir/events"
    [ "$status" -eq 0 ]
    [ "$output" = "/home/user/new.php" ]
    rm -rf "$tmpdir"
}

# bats test_tags=monitor,unit
@test "monitor: _monitor_filter_events handles MOVED_TO events" {
    _source_lmd_stack
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "/home/user/uploaded.php MOVED_TO 18 Mar 10:30:01" > "$tmpdir/events"
    printf '' > "$tmpdir/ignore"
    run _monitor_filter_events "$tmpdir/ignore" < "$tmpdir/events"
    [ "$status" -eq 0 ]
    [ "$output" = "/home/user/uploaded.php" ]
    rm -rf "$tmpdir"
}

# bats test_tags=monitor,unit
@test "monitor: _monitor_filter_events produces no output for empty input" {
    _source_lmd_stack
    local tmpdir
    tmpdir=$(mktemp -d)
    printf '' > "$tmpdir/events"
    printf '' > "$tmpdir/ignore"
    run _monitor_filter_events "$tmpdir/ignore" < "$tmpdir/events"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
    rm -rf "$tmpdir"
}

# --- _monitor_append_extra_paths ---

# bats test_tags=monitor,unit
@test "monitor: _monitor_append_extra_paths adds valid directories" {
    _source_lmd_stack
    local tmpdir
    tmpdir=$(mktemp -d)
    local extradir1 extradir2
    extradir1=$(mktemp -d "$tmpdir/extra1.XXXXXX")
    extradir2=$(mktemp -d "$tmpdir/extra2.XXXXXX")
    echo "$extradir1" > "$tmpdir/paths_extra"
    echo "$extradir2" >> "$tmpdir/paths_extra"
    printf '' > "$tmpdir/fpaths"
    _monitor_append_extra_paths "$tmpdir/paths_extra" "$tmpdir/fpaths"
    [ "$(wc -l < "$tmpdir/fpaths")" -eq 2 ]
    grep -q "$extradir1" "$tmpdir/fpaths"
    grep -q "$extradir2" "$tmpdir/fpaths"
    rm -rf "$tmpdir"
}

# bats test_tags=monitor,unit
@test "monitor: _monitor_append_extra_paths skips non-existent paths" {
    _source_lmd_stack
    local tmpdir
    tmpdir=$(mktemp -d)
    local extradir
    extradir=$(mktemp -d "$tmpdir/exists.XXXXXX")
    echo "/nonexistent/path/abc" > "$tmpdir/paths_extra"
    echo "$extradir" >> "$tmpdir/paths_extra"
    printf '' > "$tmpdir/fpaths"
    _monitor_append_extra_paths "$tmpdir/paths_extra" "$tmpdir/fpaths"
    [ "$(wc -l < "$tmpdir/fpaths")" -eq 1 ]
    grep -q "$extradir" "$tmpdir/fpaths"
    rm -rf "$tmpdir"
}

# bats test_tags=monitor,unit
@test "monitor: _monitor_append_extra_paths no-ops on missing file" {
    _source_lmd_stack
    local tmpdir
    tmpdir=$(mktemp -d)
    printf '' > "$tmpdir/fpaths"
    _monitor_append_extra_paths "$tmpdir/nonexistent" "$tmpdir/fpaths"
    [ "$(wc -l < "$tmpdir/fpaths")" -eq 0 ]
    rm -rf "$tmpdir"
}

# bats test_tags=monitor,unit
@test "monitor: _monitor_append_extra_paths skips blank lines and comments" {
    _source_lmd_stack
    local tmpdir
    tmpdir=$(mktemp -d)
    local extradir
    extradir=$(mktemp -d "$tmpdir/real.XXXXXX")
    cat > "$tmpdir/paths_extra" <<PATHS

# This is a comment
$extradir

PATHS
    printf '' > "$tmpdir/fpaths"
    _monitor_append_extra_paths "$tmpdir/paths_extra" "$tmpdir/fpaths"
    [ "$(wc -l < "$tmpdir/fpaths")" -eq 1 ]
    grep -q "$extradir" "$tmpdir/fpaths"
    rm -rf "$tmpdir"
}
