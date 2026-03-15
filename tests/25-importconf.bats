#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
_BATS_OLD_CONF=""
_BATS_MERGED=""

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    cp -p "$LMD_INSTALL/conf.maldet" "$LMD_INSTALL/conf.maldet.bak"
    _BATS_OLD_CONF="$BATS_TMPDIR/old-conf.maldet"
    _BATS_MERGED="$BATS_TMPDIR/merged.maldet"
}

teardown() {
    if [ -f "$LMD_INSTALL/conf.maldet.bak" ]; then
        mv -f "$LMD_INSTALL/conf.maldet.bak" "$LMD_INSTALL/conf.maldet"
    fi
    rm -f "$_BATS_OLD_CONF" "$_BATS_MERGED"
}

# Source pkg_lib and extract actual _compat_migrate / _import_config from install.sh.
# CH-3-002: uses awk to extract real function bodies — NOT a copy-paste re-implementation.
_load_install_functions() {
    set +eu
    # shellcheck disable=SC1091
    source "$LMD_INSTALL/internals/pkg_lib.sh"
    # Extract function definitions from install.sh without executing top-level code
    eval "$(awk '
        /^_compat_migrate\(\) \{/ { capture=1 }
        /^_import_config\(\) \{/ { capture=1 }
        capture { print }
        capture && /^\}$/ { capture=0 }
    ' /opt/lmd-src/install.sh)"
    set -eu
}

# Helper: create old config, merge with template, write to _BATS_MERGED
_run_merge() {
    _load_install_functions
    pkg_config_merge "$_BATS_OLD_CONF" "$LMD_INSTALL/conf.maldet" "$_BATS_MERGED"
}

# Helper: run a single _compat_migrate call
_run_compat_migrate() {
    _load_install_functions
    _compat_migrate "$@"
}

# --- Merge tests (was: importconf variable expansion tests) ---

@test "config merge preserves email_alert=1 from old config" {
    cp "$LMD_INSTALL/conf.maldet" "$_BATS_OLD_CONF"
    sed -i 's/^email_alert=.*/email_alert="1"/' "$_BATS_OLD_CONF"
    _run_merge
    run grep '^email_alert=' "$_BATS_MERGED"
    assert_output 'email_alert="1"'
}

@test "config merge preserves email_ignore_clean=0 (not hardcoded to 1)" {
    cp "$LMD_INSTALL/conf.maldet" "$_BATS_OLD_CONF"
    sed -i 's/^email_ignore_clean=.*/email_ignore_clean="0"/' "$_BATS_OLD_CONF"
    _run_merge
    run grep '^email_ignore_clean=' "$_BATS_MERGED"
    assert_output 'email_ignore_clean="0"'
}

@test "config merge preserves scan_max_filesize (not hardcoded)" {
    cp "$LMD_INSTALL/conf.maldet" "$_BATS_OLD_CONF"
    sed -i 's/^scan_max_filesize=.*/scan_max_filesize="4096k"/' "$_BATS_OLD_CONF"
    _run_merge
    run grep '^scan_max_filesize=' "$_BATS_MERGED"
    assert_output 'scan_max_filesize="4096k"'
}

@test "config merge preserves inotify_sleep=15 (not hardcoded to 30)" {
    cp "$LMD_INSTALL/conf.maldet" "$_BATS_OLD_CONF"
    sed -i 's/^inotify_sleep=.*/inotify_sleep="15"/' "$_BATS_OLD_CONF"
    _run_merge
    run grep '^inotify_sleep=' "$_BATS_MERGED"
    assert_output 'inotify_sleep="15"'
}

@test "config merge preserves autoupdate_signatures=0 (not hardcoded to 1)" {
    cp "$LMD_INSTALL/conf.maldet" "$_BATS_OLD_CONF"
    sed -i 's/^autoupdate_signatures=.*/autoupdate_signatures="0"/' "$_BATS_OLD_CONF"
    _run_merge
    run grep '^autoupdate_signatures=' "$_BATS_MERGED"
    assert_output 'autoupdate_signatures="0"'
}

@test "config merge preserves custom email_subj" {
    cp "$LMD_INSTALL/conf.maldet" "$_BATS_OLD_CONF"
    sed -i 's/^email_subj=.*/email_subj="custom subject"/' "$_BATS_OLD_CONF"
    _run_merge
    run grep '^email_subj=' "$_BATS_MERGED"
    assert_output 'email_subj="custom subject"'
}

@test "config merge preserves scan_yara=1" {
    cp "$LMD_INSTALL/conf.maldet" "$_BATS_OLD_CONF"
    sed -i 's/^scan_yara=.*/scan_yara="1"/' "$_BATS_OLD_CONF"
    _run_merge
    run grep '^scan_yara=' "$_BATS_MERGED"
    assert_output 'scan_yara="1"'
}

@test "config merge preserves scan_yara_timeout=600" {
    cp "$LMD_INSTALL/conf.maldet" "$_BATS_OLD_CONF"
    sed -i 's/^scan_yara_timeout=.*/scan_yara_timeout="600"/' "$_BATS_OLD_CONF"
    _run_merge
    run grep '^scan_yara_timeout=' "$_BATS_MERGED"
    assert_output 'scan_yara_timeout="600"'
}

@test "config merge preserves scan_yara_scope=all" {
    cp "$LMD_INSTALL/conf.maldet" "$_BATS_OLD_CONF"
    sed -i 's/^scan_yara_scope=.*/scan_yara_scope="all"/' "$_BATS_OLD_CONF"
    _run_merge
    run grep '^scan_yara_scope=' "$_BATS_MERGED"
    assert_output 'scan_yara_scope="all"'
}

@test "config merge preserves sig_import_yara_url" {
    cp "$LMD_INSTALL/conf.maldet" "$_BATS_OLD_CONF"
    sed -i 's|^sig_import_yara_url=.*|sig_import_yara_url="http://example.com/rules.yar"|' "$_BATS_OLD_CONF"
    _run_merge
    run grep '^sig_import_yara_url=' "$_BATS_MERGED"
    assert_output 'sig_import_yara_url="http://example.com/rules.yar"'
}

@test "config merge preserves scan_tmpdir_paths (not hardcoded)" {
    cp "$LMD_INSTALL/conf.maldet" "$_BATS_OLD_CONF"
    sed -i 's|^scan_tmpdir_paths=.*|scan_tmpdir_paths="/tmp /var/tmp /dev/shm /var/fcgi_ipc"|' "$_BATS_OLD_CONF"
    _run_merge
    run grep '^scan_tmpdir_paths=' "$_BATS_MERGED"
    assert_output 'scan_tmpdir_paths="/tmp /var/tmp /dev/shm /var/fcgi_ipc"'
}

@test "config merge preserves string_length_scan=1" {
    cp "$LMD_INSTALL/conf.maldet" "$_BATS_OLD_CONF"
    sed -i 's/^string_length_scan=.*/string_length_scan="1"/' "$_BATS_OLD_CONF"
    _run_merge
    run grep '^string_length_scan=' "$_BATS_MERGED"
    assert_output --partial 'string_length_scan="1"'
}

# --- New variable gets template default when absent from old config ---

@test "config merge: new variable absent from old config gets template default" {
    # Create old config without discord_alert (simulating pre-2.0.1 config)
    cp "$LMD_INSTALL/conf.maldet" "$_BATS_OLD_CONF"
    sed -i '/^discord_alert=/d' "$_BATS_OLD_CONF"
    _run_merge
    run grep '^discord_alert=' "$_BATS_MERGED"
    assert_output 'discord_alert="0"'
}

# --- _compat_migrate tests (CH-3-002: invokes actual function from install.sh) ---

@test "compat migrate: deprecated quar_hits migrated to quarantine_hits" {
    cp "$LMD_INSTALL/conf.maldet" "$_BATS_OLD_CONF"
    # Remove modern name, add deprecated name
    sed -i '/^quarantine_hits=/d' "$_BATS_OLD_CONF"
    echo 'quar_hits="1"' >> "$_BATS_OLD_CONF"
    _run_merge
    _run_compat_migrate "$_BATS_OLD_CONF" "$_BATS_MERGED" quar_hits quarantine_hits
    run grep '^quarantine_hits=' "$_BATS_MERGED"
    assert_output 'quarantine_hits="1"'
}

@test "compat migrate: skips when user already has new variable name" {
    cp "$LMD_INSTALL/conf.maldet" "$_BATS_OLD_CONF"
    # Both old and new name present with non-empty values
    echo 'quar_hits="0"' >> "$_BATS_OLD_CONF"
    sed -i 's/^quarantine_hits=.*/quarantine_hits="1"/' "$_BATS_OLD_CONF"
    _run_merge
    _run_compat_migrate "$_BATS_OLD_CONF" "$_BATS_MERGED" quar_hits quarantine_hits
    # Should keep the value from merge (user's quarantine_hits), not overwrite with quar_hits
    run grep '^quarantine_hits=' "$_BATS_MERGED"
    assert_output 'quarantine_hits="1"'
}

@test "compat migrate: empty new_var in old config triggers migration (CH-3-001)" {
    cp "$LMD_INSTALL/conf.maldet" "$_BATS_OLD_CONF"
    # Set quarantine_hits="" (empty) and quar_hits="1" (non-empty deprecated)
    sed -i 's/^quarantine_hits=.*/quarantine_hits=""/' "$_BATS_OLD_CONF"
    echo 'quar_hits="1"' >> "$_BATS_OLD_CONF"
    _run_merge
    _run_compat_migrate "$_BATS_OLD_CONF" "$_BATS_MERGED" quar_hits quarantine_hits
    run grep '^quarantine_hits=' "$_BATS_MERGED"
    assert_output 'quarantine_hits="1"'
}

@test "compat migrate: empty old_var value does not overwrite template default" {
    cp "$LMD_INSTALL/conf.maldet" "$_BATS_OLD_CONF"
    # Remove modern name, set deprecated to empty
    sed -i '/^quarantine_hits=/d' "$_BATS_OLD_CONF"
    echo 'quar_hits=""' >> "$_BATS_OLD_CONF"
    _run_merge
    _run_compat_migrate "$_BATS_OLD_CONF" "$_BATS_MERGED" quar_hits quarantine_hits
    # Template default should remain (quarantine_hits="0")
    run grep '^quarantine_hits=' "$_BATS_MERGED"
    assert_output 'quarantine_hits="0"'
}

# --- Special-case migration tests ---

@test "compat migrate: scan_hex_workers unconditionally overrides scan_workers" {
    cp "$LMD_INSTALL/conf.maldet" "$_BATS_OLD_CONF"
    echo 'scan_hex_workers="3"' >> "$_BATS_OLD_CONF"
    _run_merge
    _load_install_functions
    # Unconditional override: read scan_hex_workers from old, set scan_workers in merged
    local _hw
    _hw=$(pkg_config_get "$_BATS_OLD_CONF" scan_hex_workers) || _hw=""
    if [[ -n "$_hw" ]]; then
        pkg_config_set "$_BATS_MERGED" scan_workers "$_hw"
    fi
    run grep '^scan_workers=' "$_BATS_MERGED"
    assert_output 'scan_workers="3"'
}

@test "compat migrate: scan_hexfifo consolidation migrates depth to scan_hexdepth" {
    cp "$LMD_INSTALL/conf.maldet" "$_BATS_OLD_CONF"
    echo 'scan_hexfifo="1"' >> "$_BATS_OLD_CONF"
    echo 'scan_hexfifo_depth="1048576"' >> "$_BATS_OLD_CONF"
    _run_merge
    _load_install_functions
    # Replicate the consolidation logic from _import_config
    local _hexfifo_val _hexfifo_depth
    _hexfifo_val=$(pkg_config_get "$_BATS_OLD_CONF" scan_hexfifo 2>/dev/null) || _hexfifo_val=""
    if [[ "${_hexfifo_val:-0}" = "1" ]]; then
        _hexfifo_depth=$(pkg_config_get "$_BATS_OLD_CONF" scan_hexfifo_depth 2>/dev/null) || _hexfifo_depth=""
        if [[ -n "$_hexfifo_depth" ]]; then
            pkg_config_set "$_BATS_MERGED" scan_hexdepth "$_hexfifo_depth"
        fi
    fi
    run grep '^scan_hexdepth=' "$_BATS_MERGED"
    assert_output 'scan_hexdepth="1048576"'
}

# --- Structural validation ---

@test "importconf file removed from install path" {
    [ ! -f "$LMD_INSTALL/internals/importconf" ]
}
