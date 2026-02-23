#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-security"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
    rm -f /tmp/pwned
}

# F-037: hex FIFO permissions
@test "hex FIFO created with mode 600 not 666" {
    rm -f "$LMD_INSTALL/internals/hexfifo"
    lmd_set_config scan_hexfifo 1
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    if [ -p "$LMD_INSTALL/internals/hexfifo" ]; then
        local perms
        perms=$(stat -c '%a' "$LMD_INSTALL/internals/hexfifo")
        [ "$perms" = "600" ]
    fi
}

# F-022: conf.maldet permissions
@test "conf.maldet is not world-readable" {
    local perms
    perms=$(stat -c '%a' "$LMD_INSTALL/conf.maldet")
    [ "$perms" = "640" ]
}

# F-004: hookscan filename validation
@test "hookscan rejects filenames with shell metacharacters" {
    # The validation is at the top of hookscan.sh before any sourcing
    # Test by running just the validation portion
    local hookscan="$LMD_INSTALL/hookscan.sh"
    # A filename with $() should be rejected
    run bash -c 'file="/tmp/test\$(whoami).php"; eval "$(head -17 "'"$hookscan"'")"'
    [ "$status" -eq 1 ]
}

@test "hookscan rejects filenames with backticks" {
    local hookscan="$LMD_INSTALL/hookscan.sh"
    run bash -c 'file="/tmp/test\`id\`.php"; eval "$(head -17 "'"$hookscan"'")"'
    [ "$status" -eq 1 ]
}

@test "hookscan rejects non-existent files" {
    local hookscan="$LMD_INSTALL/hookscan.sh"
    run bash -c 'file="/tmp/nonexistent_file_xyz.php"; eval "$(head -17 "'"$hookscan"'")"'
    [ "$status" -eq 1 ]
}

# F-002: -co config option injection
@test "-co rejects command substitution in values" {
    run maldet -co 'scan_max_filesize=$(id)' -a /tmp
    assert_output --partial "rejected unsafe -co value"
}

@test "-co rejects backtick injection" {
    run maldet -co 'scan_max_filesize=`id`' -a /tmp
    assert_output --partial "rejected unsafe -co value"
}

@test "-co accepts legitimate variable assignment" {
    mkdir -p /tmp/lmd-co-test
    echo "clean" > /tmp/lmd-co-test/file.txt
    run maldet -co scan_max_filesize=1 -a /tmp/lmd-co-test
    assert_success
    rm -rf /tmp/lmd-co-test
}

# F-001: import_conf safe config sourcing
# Helper: source LMD config stack (internals.conf has command -v calls
# that return non-zero for missing binaries, and functions uses unset
# variables, so disable errexit and nounset for the caller's scope)
_source_lmd_stack() {
    set +eu
    source "$LMD_INSTALL/internals/internals.conf"
    source "$LMD_INSTALL/conf.maldet"
    source "$LMD_INSTALL/internals/functions"
}

@test "import_conf rejects command substitution in remote config" {
    local sessdir="$LMD_INSTALL/sess"
    echo 'email_alert=$(id>/tmp/pwned)' > "$sessdir/.import_conf.cache"
    echo "999999999" > "$sessdir/.import_conf.utime"
    lmd_set_config import_config_url "http://127.0.0.1/fake"
    _source_lmd_stack
    import_conf
    # The command substitution should NOT have executed
    [ ! -f /tmp/pwned ]
    # The variable should NOT have been set to the malicious value
    [ "$email_alert" != '$(id>/tmp/pwned)' ]
}

@test "import_conf accepts safe variable assignments" {
    local sessdir="$LMD_INSTALL/sess"
    echo 'email_alert=1' > "$sessdir/.import_conf.cache"
    echo 'scan_max_filesize=768k' >> "$sessdir/.import_conf.cache"
    echo "999999999" > "$sessdir/.import_conf.utime"
    lmd_set_config import_config_url "http://127.0.0.1/fake"
    _source_lmd_stack
    import_conf
    [ "$email_alert" = "1" ]
    [ "$scan_max_filesize" = "768k" ]
}

@test "_safe_source_conf skips comments and blank lines" {
    local tmpfile
    tmpfile=$(mktemp)
    printf '# comment\n\nemail_alert=1\n' > "$tmpfile"
    _source_lmd_stack
    _safe_source_conf "$tmpfile"
    [ "$email_alert" = "1" ]
    rm -f "$tmpfile"
}
