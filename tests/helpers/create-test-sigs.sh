#!/usr/bin/env bash
# Generate minimal test signatures for deterministic testing
set -euo pipefail

LMD_INSTALL="${LMD_INSTALL:-/usr/local/maldetect}"
SAMPLES_DIR="${SAMPLES_DIR:-/opt/tests/samples}"

# Generate HEX signature for the test PHP sample
# The hex pattern matches the string "eval(base64_decode(" which is in test-hex-match.php
echo "6576616c286261736536345f6465636f646528:test.hex.php.1" >> "$LMD_INSTALL/sigs/custom.hex.dat"

# Note: EICAR test file is detected by builtin MD5 signatures (md5v2.dat)
# so no custom MD5 signature is needed for standard detection tests.
