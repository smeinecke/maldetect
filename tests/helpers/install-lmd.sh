#!/usr/bin/env bash
# Install LMD from source tree with test-safe configuration
set -euo pipefail

LMD_SRC="${LMD_SRC:-/opt/lmd-src}"
LMD_INSTALL="${LMD_INSTALL:-/usr/local/maldetect}"

cd "$LMD_SRC"
./install.sh

# Disable network-dependent features for deterministic tests
sed -i 's/^autoupdate_signatures=.*/autoupdate_signatures="0"/' "$LMD_INSTALL/conf.maldet"
sed -i 's/^autoupdate_version=.*/autoupdate_version="0"/' "$LMD_INSTALL/conf.maldet"
sed -i 's/^autoupdate_version_hashed=.*/autoupdate_version_hashed="0"/' "$LMD_INSTALL/conf.maldet"
sed -i 's/^email_alert=.*/email_alert="0"/' "$LMD_INSTALL/conf.maldet"
sed -i 's/^scan_clamscan=.*/scan_clamscan="0"/' "$LMD_INSTALL/conf.maldet"
sed -i 's/^import_config_url=.*/import_config_url=""/' "$LMD_INSTALL/conf.maldet"

# Save clean state for reset between tests
cp "$LMD_INSTALL/conf.maldet" "$LMD_INSTALL/conf.maldet.clean"
