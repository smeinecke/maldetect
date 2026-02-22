#!/usr/bin/env bash
# Custom BATS assertions for LMD scan results

LMD_INSTALL="${LMD_INSTALL:-/usr/local/maldetect}"

# Assert scan completed (exit 0=no hits, 2=hits found, both are valid)
# Usage: run maldet -a PATH; assert_scan_completed
assert_scan_completed() {
    if [ "$status" -ne 0 ] && [ "$status" -ne 2 ]; then
        echo "# maldet scan failed with unexpected status $status" >&2
        echo "# output: $output" >&2
        return 1
    fi
}

# Assert that a scan detected a specific signature
# Usage: assert_scan_detected SCANID SIGNATURE
assert_scan_detected() {
    local scanid="$1"
    local signature="$2"
    local hitfile="$LMD_INSTALL/sess/session.hits.${scanid}"
    if [ ! -f "$hitfile" ]; then
        echo "# Hit file not found: $hitfile" >&2
        return 1
    fi
    if ! grep -q "$signature" "$hitfile"; then
        echo "# Signature '$signature' not found in scan $scanid" >&2
        echo "# Contents: $(cat "$hitfile")" >&2
        return 1
    fi
}

# Assert that a scan produced no hits
# Usage: assert_scan_clean SCANID
assert_scan_clean() {
    local scanid="$1"
    local hitfile="$LMD_INSTALL/sess/session.hits.${scanid}"
    if [ -f "$hitfile" ] && [ -s "$hitfile" ]; then
        echo "# Expected clean scan but found hits:" >&2
        echo "# $(cat "$hitfile")" >&2
        return 1
    fi
}

# Assert that a file has been quarantined
# Usage: assert_quarantined FILE
assert_quarantined() {
    local file="$1"
    if [ -f "$file" ]; then
        echo "# File still exists (not quarantined): $file" >&2
        return 1
    fi
    if ! grep -q "$file" "$LMD_INSTALL/sess/quarantine.hist" 2>/dev/null; then
        echo "# File not found in quarantine history: $file" >&2
        return 1
    fi
}

# Assert that a file has NOT been quarantined
# Usage: assert_not_quarantined FILE
assert_not_quarantined() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "# File does not exist: $file" >&2
        return 1
    fi
}

# Assert that a file has been restored from quarantine
# Usage: assert_file_restored FILE
assert_file_restored() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "# File not restored: $file" >&2
        return 1
    fi
}

# Assert that a scan report contains a pattern
# Usage: assert_report_contains SCANID PATTERN
assert_report_contains() {
    local scanid="$1"
    local pattern="$2"
    local report="$LMD_INSTALL/sess/session.${scanid}"
    if [ ! -f "$report" ]; then
        echo "# Report not found: $report" >&2
        return 1
    fi
    if ! grep -q "$pattern" "$report"; then
        echo "# Pattern '$pattern' not found in report $scanid" >&2
        return 1
    fi
}

# Get the most recent scan ID
# Usage: scanid=$(get_last_scanid)
get_last_scanid() {
    if [ -f "$LMD_INSTALL/sess/session.last" ]; then
        cat "$LMD_INSTALL/sess/session.last"
    else
        echo ""
    fi
}
