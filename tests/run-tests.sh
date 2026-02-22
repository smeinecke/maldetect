#!/usr/bin/env bash
#
# LMD Test Runner — builds Docker image and runs BATS tests
#
# Usage examples:
#   ./tests/run-tests.sh                                  # Run all on Debian 12
#   ./tests/run-tests.sh --os rocky9                      # Run on Rocky 9
#   ./tests/run-tests.sh --filter "quarantine"            # Filter by test name
#   ./tests/run-tests.sh /opt/tests/02-scan-md5.bats      # Specific test file
#   ./tests/run-tests.sh --os centos7 --filter "MD5"      # OS + filter
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

ALL_TARGETS="centos6 centos7 rocky8 rocky9 ubuntu2004 ubuntu2404 debian12"

usage() {
    echo "Usage: $0 [--os OS] [--filter PATTERN] [BATS_ARGS...]"
    echo ""
    echo "Options:"
    echo "  --os OS           Target OS (default: debian12)"
    echo "  --filter PATTERN  Filter tests by name (passed to bats --filter)"
    echo "  --help            Show this help"
    echo ""
    echo "Any remaining arguments are passed directly to bats."
    echo ""
    echo "Supported targets:"
    echo "  $ALL_TARGETS"
    exit "${1:-0}"
}

OS="debian12"
BATS_ARGS=()

while [ $# -gt 0 ]; do
    case "$1" in
        --os)
            shift
            OS="$1"
            ;;
        --filter)
            shift
            BATS_ARGS+=("--filter" "$1")
            ;;
        --help|-h)
            usage 0
            ;;
        *)
            BATS_ARGS+=("$1")
            ;;
    esac
    shift
done

case "$OS" in
    debian12)
        DOCKERFILE="$SCRIPT_DIR/Dockerfile"
        ;;
    centos6|centos7|rocky8|rocky9|ubuntu2004|ubuntu2404)
        DOCKERFILE="$SCRIPT_DIR/Dockerfile.${OS}"
        ;;
    *)
        echo "Unsupported OS: $OS"
        echo "Supported: $ALL_TARGETS"
        exit 1
        ;;
esac

IMAGE_TAG="lmd-test-${OS}"

echo "=== Building test image: ${IMAGE_TAG} ==="
docker build -t "$IMAGE_TAG" -f "$DOCKERFILE" "$PROJECT_DIR"

echo "=== Running tests: ${OS} ==="
if [ ${#BATS_ARGS[@]} -gt 0 ]; then
    docker run --rm "$IMAGE_TAG" bats --formatter tap "${BATS_ARGS[@]}"
else
    docker run --rm "$IMAGE_TAG"
fi
