#!/usr/bin/env bash
# Reset LMD to clean state between test files
set -euo pipefail

LMD_INSTALL="${LMD_INSTALL:-/usr/local/maldetect}"

# Restore clean config
cp "$LMD_INSTALL/conf.maldet.clean" "$LMD_INSTALL/conf.maldet"

# Restore clean signature files (sigignore modifies sigs in place)
if [ -d "$LMD_INSTALL/sigs.clean" ]; then
    rm -rf "$LMD_INSTALL/sigs"
    cp -a "$LMD_INSTALL/sigs.clean" "$LMD_INSTALL/sigs"
fi

# Clear session, quarantine, and temp data
rm -rf "$LMD_INSTALL/sess/"*
rm -rf "$LMD_INSTALL/quarantine/"*
rm -rf "$LMD_INSTALL/tmp/"*

# Reset custom signatures
> "$LMD_INSTALL/sigs/custom.md5.dat"
> "$LMD_INSTALL/sigs/custom.hex.dat"

# Clear ignore files
> "$LMD_INSTALL/ignore_paths"
> "$LMD_INSTALL/ignore_sigs"
> "$LMD_INSTALL/ignore_file_ext"
