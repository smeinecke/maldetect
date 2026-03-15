ARG BASE_IMAGE=lmd-base-debian12
FROM ${BASE_IMAGE}

RUN apt-get update && apt-get install -y --no-install-recommends \
    perl file inotify-tools ed yara \
    python3 bsdmainutils \
    && rm -rf /var/lib/apt/lists/*

COPY . /opt/lmd-src
COPY tests/ /opt/tests/

# Ensure cron directories exist for install.sh (cron.daily) and watchdog (cron.weekly)
RUN mkdir -p /etc/cron.daily /etc/cron.weekly

# Pre-install LMD with test config
RUN cd /opt/lmd-src && ./install.sh && \
    sed -i 's/^autoupdate_signatures=.*/autoupdate_signatures="0"/' /usr/local/maldetect/conf.maldet && \
    sed -i 's/^autoupdate_version=.*/autoupdate_version="0"/' /usr/local/maldetect/conf.maldet && \
    sed -i 's/^autoupdate_version_hashed=.*/autoupdate_version_hashed="0"/' /usr/local/maldetect/conf.maldet && \
    sed -i 's/^email_alert=.*/email_alert="0"/' /usr/local/maldetect/conf.maldet && \
    sed -i 's/^scan_clamscan=.*/scan_clamscan="0"/' /usr/local/maldetect/conf.maldet && \
    sed -i 's/^import_config_url=.*/import_config_url=""/' /usr/local/maldetect/conf.maldet && \
    sed -i 's/^scan_ignore_root=.*/scan_ignore_root="0"/' /usr/local/maldetect/conf.maldet && \
    sed -i 's/^scan_tmpdir_paths=.*/scan_tmpdir_paths=""/' /usr/local/maldetect/conf.maldet

# Restore source tree sigs for deterministic test behavior.
# install.sh downloads fresh sigs from cdn.rfxn.com which may have different
# signature names/counts than the local files/sigs/ used to write tests.
# Remove downloaded-only files (e.g., sha256v2.dat) and overwrite the rest.
RUN cd /usr/local/maldetect/sigs && \
    for f in *.dat *.hdb *.ndb *.yara; do \
        [ -f "$f" ] || continue; \
        case "$f" in custom.*|lmd.user.*|compiled.*) continue;; esac; \
        [ -f "/opt/lmd-src/files/sigs/$f" ] || rm -f "$f"; \
    done && \
    cp -f /opt/lmd-src/files/sigs/*.dat /opt/lmd-src/files/sigs/*.hdb \
          /opt/lmd-src/files/sigs/*.ndb /opt/lmd-src/files/sigs/*.yara \
          /usr/local/maldetect/sigs/ 2>/dev/null; true

# Save clean state for test resets
RUN cp /usr/local/maldetect/conf.maldet /usr/local/maldetect/conf.maldet.clean && \
    cp -a /usr/local/maldetect/sigs /usr/local/maldetect/sigs.clean

WORKDIR /opt/tests
CMD ["bats", "--formatter", "tap", "/opt/tests/"]
