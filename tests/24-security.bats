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
    rm -f /tmp/hookscan-val.*
}

# F-037: hex FIFO permissions
@test "hex FIFO created with mode 600 not 666" {
    rm -f "$LMD_INSTALL/internals/hexfifo"
    lmd_set_config scan_hexfifo 1
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    # FIFO must exist after a hex scan — fail explicitly if missing
    [ -p "$LMD_INSTALL/internals/hexfifo" ]
    local perms
    perms=$(stat -c '%a' "$LMD_INSTALL/internals/hexfifo")
    [ "$perms" = "600" ]
}

# F-022: conf.maldet permissions
@test "conf.maldet is not world-readable" {
    local perms
    perms=$(stat -c '%a' "$LMD_INSTALL/conf.maldet")
    [ "$perms" = "640" ]
}

# F-004: hookscan filename validation
# Extract the validation block from hookscan.sh by pattern (not line count)
# so the test survives preamble changes. Spans from 'file="$1"' to the line
# before 'inspath=' — covers case, metachar_pat, [[ =~ ]], and -f checks.
_hookscan_validation_script() {
    local tmpscript
    tmpscript=$(mktemp /tmp/hookscan-val.XXXXXX)
    printf '#!/usr/bin/env bash\n' > "$tmpscript"
    sed -n '/^file="\$1"/,/^inspath=/{/^inspath=/d;/^file="\$1"/d;p}' \
        "$LMD_INSTALL/hookscan.sh" >> "$tmpscript"
    chmod 755 "$tmpscript"
    echo "$tmpscript"
}

@test "hookscan rejects filenames with shell metacharacters" {
    local script
    script=$(_hookscan_validation_script)
    [ -s "$script" ]
    # A filename with $() should be rejected
    run bash -c 'file="/tmp/test\$(whoami).php"; source "'"$script"'"'
    rm -f "$script"
    [ "$status" -eq 1 ]
}

@test "hookscan rejects filenames with backticks" {
    local script
    script=$(_hookscan_validation_script)
    run bash -c 'file="/tmp/test\`id\`.php"; source "'"$script"'"'
    rm -f "$script"
    [ "$status" -eq 1 ]
}

@test "hookscan rejects non-existent files" {
    local script
    script=$(_hookscan_validation_script)
    run bash -c 'file="/tmp/nonexistent_file_xyz.php"; source "'"$script"'"'
    rm -f "$script"
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

# F-033: restore path traversal validation
@test "restore rejects path with .. traversal in .info" {
    lmd_set_config quarantine_hits 1
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    local scanid
    scanid=$(get_last_scanid)
    # Find the .info file and inject a traversal path
    local info_file
    info_file=$(ls "$LMD_INSTALL/quarantine/"*.info 2>/dev/null | head -1)
    [ -n "$info_file" ]
    # Replace the path (field 9) with a traversal path
    local original
    original=$(grep -E -v '^\#' "$info_file")
    local prefix
    prefix=$(echo "$original" | cut -d: -f1-8)
    echo "# owner:group:mode:size(b):md5:atime(epoch):mtime(epoch):ctime(epoch):file(path)" > "$info_file"
    echo "${prefix}:/tmp/../tmp/lmd-traversal-test" >> "$info_file"
    local qfile
    qfile=$(basename "${info_file%.info}")
    run maldet -s "$qfile"
    # The traversal path should NOT have been created
    [ ! -f "/tmp/lmd-traversal-test" ]
}

# F-052: chown uses POSIX ':' separator (not deprecated '.')
@test "functions uses POSIX chown user:group separator not deprecated dot" {
    local func_file="$LMD_INSTALL/internals/functions"
    # grep for chown with '.' separator — should find zero matches
    # Pattern: chown followed by word.word (not :)
    # Exclude lines with $quardir/$file_name.$rnd (that dot is filename, not separator)
    run bash -c "grep -n 'chown.*[a-z}]\.[a-z}]' \"$func_file\" | grep -v 'file_name\.\$rnd' | grep -v '^\s*#'"
    # No matches means the deprecated separator is gone
    assert_failure
}

# F-046: sed uses -E not -r
@test "functions uses sed -E not deprecated sed -r" {
    local func_file="$LMD_INSTALL/internals/functions"
    run grep -n 'sed -r' "$func_file"
    assert_failure
}

@test "restore succeeds with valid .info path" {
    lmd_set_config quarantine_hits 1
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/test-restore-valid.txt"
    run maldet -a "$TEST_SCAN_DIR"
    local qfile
    qfile=$(ls "$LMD_INSTALL/quarantine/" 2>/dev/null | grep -v '\.info$' | head -1)
    [ -n "$qfile" ]
    run maldet -s "$qfile"
    # File should be restored (normal behavior still works)
    assert_output --partial "restored"
}
