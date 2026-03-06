#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-alert"
MOCK_BIN_DIR="/tmp/lmd-mock-bins"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR" "$MOCK_BIN_DIR"
    rm -f /tmp/mock-mail.log /tmp/mock-mail.body
    rm -f /tmp/mock-sendmail.log /tmp/mock-sendmail.body
    rm -f /tmp/mock-curl.log
    # Remove any pre-existing mocks
    rm -f "$MOCK_BIN_DIR/mail" "$MOCK_BIN_DIR/sendmail" "$MOCK_BIN_DIR/curl"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR" "$MOCK_BIN_DIR"
    rm -f /tmp/mock-mail.log /tmp/mock-mail.body
    rm -f /tmp/mock-sendmail.log /tmp/mock-sendmail.body
    rm -f /tmp/mock-curl.log
}

# Helper: create mock mail binary
create_mock_mail() {
    cat > "$MOCK_BIN_DIR/mail" <<'EOF'
#!/usr/bin/env bash
echo "ARGS: $@" >> /tmp/mock-mail.log
cat >> /tmp/mock-mail.body
EOF
    chmod 755 "$MOCK_BIN_DIR/mail"
}

# Helper: create mock sendmail binary
create_mock_sendmail() {
    cat > "$MOCK_BIN_DIR/sendmail" <<'EOF'
#!/usr/bin/env bash
echo "ARGS: $@" >> /tmp/mock-sendmail.log
cat >> /tmp/mock-sendmail.body
EOF
    chmod 755 "$MOCK_BIN_DIR/sendmail"
}

# Helper: create mock curl binary for Slack/Telegram/Discord tests
# Handles shared alert_lib curl patterns (same Slack/Telegram APIs,
# plus Discord webhook support).
create_mock_curl() {
    local real_curl
    real_curl=$(command -v curl)
    cat > "$MOCK_BIN_DIR/curl" <<CURLEOF
#!/usr/bin/env bash
echo "CURL_CALL: \$@" >> /tmp/mock-curl.log
# Log -K config contents for test verification
_prev=""
for _arg in "\$@"; do
    if [ "\$_prev" = "-K" ] && [ -f "\$_arg" ]; then
        echo "CURL_CONFIG: \$(cat "\$_arg")" >> /tmp/mock-curl.log
    fi
    _prev="\$_arg"
done
if [[ "\$*" == *"getUploadURLExternal"* ]]; then
    echo '{"ok":true,"upload_url":"http://mock-upload","file_id":"F12345"}'
elif [[ "\$*" == *"completeUploadExternal"* ]]; then
    echo '{"ok":true}'
elif [[ "\$*" == *"chat.postMessage"* ]]; then
    echo '{"ok":true,"channel":"C12345","ts":"1234567890.123456"}'
elif [[ "\$*" == *"discord"*"webhook"* ]] || [[ "\$*" == *"discordapp"*"webhook"* ]]; then
    echo '{"id":"msg123"}'
elif [[ "\$*" == *"-K"* ]]; then
    # Telegram uses -K config file; check config content for sendDocument
    _cfg=""
    _p=""
    for _a in "\$@"; do
        if [ "\$_p" = "-K" ] && [ -f "\$_a" ]; then
            _cfg=\$(cat "\$_a")
        fi
        _p="\$_a"
    done
    if [[ "\$_cfg" == *"sendDocument"* ]] || [[ "\$_cfg" == *"sendMessage"* ]]; then
        echo '{"ok":true,"result":{}}'
    else
        $real_curl "\$@"
    fi
elif [[ "\$*" == *"mock-upload"* ]]; then
    echo 'ok'
else
    $real_curl "\$@"
fi
CURLEOF
    chmod 755 "$MOCK_BIN_DIR/curl"
}

# Helper: create mock curl that returns API errors
create_mock_curl_error() {
    cat > "$MOCK_BIN_DIR/curl" <<'CURLEOF'
#!/usr/bin/env bash
echo "CURL_CALL: $@" >> /tmp/mock-curl.log
# Log -K config contents for test verification
_prev=""
for _arg in "$@"; do
    if [ "$_prev" = "-K" ] && [ -f "$_arg" ]; then
        echo "CURL_CONFIG: $(cat "$_arg")" >> /tmp/mock-curl.log
    fi
    _prev="$_arg"
done
if [[ "$*" == *"getUploadURLExternal"* ]]; then
    echo '{"ok":false,"error":"invalid_auth"}'
elif [[ "$*" == *"completeUploadExternal"* ]]; then
    echo '{"ok":false,"error":"channel_not_found"}'
elif [[ "$*" == *"chat.postMessage"* ]]; then
    echo '{"ok":false,"error":"invalid_auth"}'
elif [[ "$*" == *"discord"*"webhook"* ]] || [[ "$*" == *"discordapp"*"webhook"* ]]; then
    echo '{"code":50035,"message":"Invalid Form Body"}'
    exit 0
elif [[ "$*" == *"-K"* ]]; then
    # Telegram uses -K config file; check config content for sendDocument
    _cfg=""
    _p=""
    for _a in "$@"; do
        if [ "$_p" = "-K" ] && [ -f "$_a" ]; then
            _cfg=$(cat "$_a")
        fi
        _p="$_a"
    done
    if [[ "$_cfg" == *"sendDocument"* ]] || [[ "$_cfg" == *"sendMessage"* ]]; then
        echo '{"ok":false,"error_code":401,"description":"Unauthorized"}'
    else
        echo '{"ok":false,"error":"unknown"}'
    fi
elif [[ "$*" == *"mock-upload"* ]]; then
    echo 'ok'
else
    echo '{"ok":false,"error":"unknown"}'
fi
CURLEOF
    chmod 755 "$MOCK_BIN_DIR/curl"
}

# Helper: create mock curl that simulates network failure
create_mock_curl_fail() {
    cat > "$MOCK_BIN_DIR/curl" <<'CURLEOF'
#!/usr/bin/env bash
echo "CURL_CALL: $@" >> /tmp/mock-curl.log
exit 7
CURLEOF
    chmod 755 "$MOCK_BIN_DIR/curl"
}

# Helper: run maldet with mock bins in PATH
run_maldet_with_mocks() {
    PATH="$MOCK_BIN_DIR:$PATH" run maldet "$@"
}

# ---------------------------------------------------------------------------
# Email alerts (via shared alert_lib _alert_deliver_email)
# ---------------------------------------------------------------------------

@test "email alert sent via mail binary when email_alert=1" {
    create_mock_mail
    lmd_set_config email_alert 1
    lmd_set_config email_addr "test@example.com"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run_maldet_with_mocks -a "$TEST_SCAN_DIR"
    assert_scan_completed
    [ -f /tmp/mock-mail.log ]
}

@test "email alert sent via sendmail when mail not available" {
    # Only create sendmail mock, no mail mock
    create_mock_sendmail
    lmd_set_config email_alert 1
    lmd_set_config email_addr "test@example.com"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run_maldet_with_mocks -a "$TEST_SCAN_DIR"
    assert_scan_completed
    [ -f /tmp/mock-sendmail.log ]
    # Shared lib uses sendmail -t -oi (recipient in To: header via stdin)
    run grep "test@example.com" /tmp/mock-sendmail.body
    assert_success
}

@test "email uses configured email_subj" {
    create_mock_mail
    lmd_set_config email_alert 1
    lmd_set_config email_addr "test@example.com"
    lmd_set_config email_subj "CUSTOM ALERT SUBJECT"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run_maldet_with_mocks -a "$TEST_SCAN_DIR"
    assert_scan_completed
    run grep "CUSTOM ALERT SUBJECT" /tmp/mock-mail.log
    assert_success
}

@test "email sent to configured email_addr" {
    create_mock_mail
    lmd_set_config email_alert 1
    lmd_set_config email_addr "admin@myhost.com"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run_maldet_with_mocks -a "$TEST_SCAN_DIR"
    assert_scan_completed
    run grep "admin@myhost.com" /tmp/mock-mail.log
    assert_success
}

@test "no email sent when email_alert=0" {
    create_mock_mail
    create_mock_sendmail
    lmd_set_config email_alert 0
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run_maldet_with_mocks -a "$TEST_SCAN_DIR"
    assert_scan_completed
    [ ! -f /tmp/mock-mail.log ]
    [ ! -f /tmp/mock-sendmail.log ]
}

# ---------------------------------------------------------------------------
# Slack alerts (via shared alert_lib _alert_slack_upload)
# ---------------------------------------------------------------------------

@test "slack alert calls getUploadURLExternal API" {
    create_mock_curl
    lmd_set_config email_alert 0
    lmd_set_config slack_alert 1
    lmd_set_config slack_token "xoxb-test-token-123"
    lmd_set_config slack_channels "C12345"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run_maldet_with_mocks -a "$TEST_SCAN_DIR"
    assert_scan_completed
    [ -f /tmp/mock-curl.log ]
    run grep "getUploadURLExternal" /tmp/mock-curl.log
    assert_success
}

@test "slack alert sends Bearer token in authorization header" {
    create_mock_curl
    lmd_set_config email_alert 0
    lmd_set_config slack_alert 1
    lmd_set_config slack_token "xoxb-test-token-123"
    lmd_set_config slack_channels "C12345"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run_maldet_with_mocks -a "$TEST_SCAN_DIR"
    assert_scan_completed
    run grep "Bearer xoxb-test-token-123" /tmp/mock-curl.log
    assert_success
}

# ---------------------------------------------------------------------------
# Telegram alerts (via shared alert_lib _alert_telegram_document)
# ---------------------------------------------------------------------------

@test "telegram alert calls sendDocument API" {
    create_mock_curl
    lmd_set_config email_alert 0
    lmd_set_config telegram_alert 1
    lmd_set_config telegram_bot_token "bot123456:ABC-DEF"
    lmd_set_config telegram_channel_id "-100123456"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run_maldet_with_mocks -a "$TEST_SCAN_DIR"
    assert_scan_completed
    [ -f /tmp/mock-curl.log ]
    run grep "sendDocument" /tmp/mock-curl.log
    assert_success
}

@test "slack alert disabled when slack_alert=0" {
    create_mock_curl
    lmd_set_config email_alert 0
    lmd_set_config slack_alert 0
    lmd_set_config telegram_alert 0
    lmd_set_config discord_alert 0
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run_maldet_with_mocks -a "$TEST_SCAN_DIR"
    assert_scan_completed
    if [ -f /tmp/mock-curl.log ]; then
        run grep "getUploadURLExternal" /tmp/mock-curl.log
        assert_failure
    fi
}

@test "telegram alert uses configured bot token and channel" {
    create_mock_curl
    lmd_set_config email_alert 0
    lmd_set_config telegram_alert 1
    lmd_set_config telegram_bot_token "bot999:XYZ"
    lmd_set_config telegram_channel_id "-999"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run_maldet_with_mocks -a "$TEST_SCAN_DIR"
    assert_scan_completed
    [ -f /tmp/mock-curl.log ]
    run grep -F "bot999:XYZ" /tmp/mock-curl.log
    assert_success
}

@test "slack API error logs error field from response" {
    create_mock_curl_error
    lmd_set_config email_alert 0
    lmd_set_config slack_alert 1
    lmd_set_config slack_token "xoxb-test-token-123"
    lmd_set_config slack_channels "C12345"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run_maldet_with_mocks -a "$TEST_SCAN_DIR"
    assert_scan_completed
    # Shared lib writes errors to stderr; LMD wraps with eout
    run grep -E "invalid_auth|messaging channels failed" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "slack curl failure logs exit code" {
    create_mock_curl_fail
    lmd_set_config email_alert 0
    lmd_set_config slack_alert 1
    lmd_set_config slack_token "xoxb-test-token-123"
    lmd_set_config slack_channels "C12345"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run_maldet_with_mocks -a "$TEST_SCAN_DIR"
    assert_scan_completed
    # Shared lib writes "curl exit N" to stderr; LMD wraps with eout
    run grep -E "curl exit 7|curl failed|messaging channels failed" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "telegram API error logs description from response" {
    create_mock_curl_error
    lmd_set_config email_alert 0
    lmd_set_config telegram_alert 1
    lmd_set_config telegram_bot_token "bot123456:ABC-DEF"
    lmd_set_config telegram_channel_id "-100123456"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run_maldet_with_mocks -a "$TEST_SCAN_DIR"
    assert_scan_completed
    # Shared lib writes "Unauthorized" to stderr; LMD wraps with eout
    run grep -E "Unauthorized|messaging channels failed" "$LMD_INSTALL/logs/event_log"
    assert_success
}

# ---------------------------------------------------------------------------
# Discord alerts (via shared alert_lib _alert_discord_webhook)
# ---------------------------------------------------------------------------

@test "discord alert calls webhook URL when discord_alert=1" {
    create_mock_curl
    lmd_set_config email_alert 0
    lmd_set_config discord_alert 1
    lmd_set_config discord_webhook_url "https://discord.com/api/webhooks/123/abc"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run_maldet_with_mocks -a "$TEST_SCAN_DIR"
    assert_scan_completed
    [ -f /tmp/mock-curl.log ]
    run grep "discord.com/api/webhooks" /tmp/mock-curl.log
    assert_success
}

@test "discord alert disabled when discord_alert=0" {
    create_mock_curl
    lmd_set_config email_alert 0
    lmd_set_config discord_alert 0
    lmd_set_config discord_webhook_url "https://discord.com/api/webhooks/123/abc"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run_maldet_with_mocks -a "$TEST_SCAN_DIR"
    assert_scan_completed
    if [ -f /tmp/mock-curl.log ]; then
        run grep "discord" /tmp/mock-curl.log
        assert_failure
    fi
}

@test "discord alert not sent when webhook URL empty" {
    create_mock_curl
    lmd_set_config email_alert 0
    lmd_set_config discord_alert 1
    lmd_set_config discord_webhook_url ""
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run_maldet_with_mocks -a "$TEST_SCAN_DIR"
    assert_scan_completed
    if [ -f /tmp/mock-curl.log ]; then
        run grep "discord" /tmp/mock-curl.log
        assert_failure
    fi
}
