#!/usr/bin/env bash
#
# LMD Test Runner — builds Docker image and runs BATS tests
#
# Usage: ./tests/run-tests.sh [--os OS] [--parallel [N]] [--filter PATTERN] [bats args...]
#
# Examples:
#   ./tests/run-tests.sh                                  # Run all on Debian 12 (sequential)
#   ./tests/run-tests.sh --os rocky9                      # Run on Rocky 9
#   ./tests/run-tests.sh --parallel                       # Parallel (nproc*2 containers)
#   ./tests/run-tests.sh --parallel 4                     # Parallel with 4 containers
#   ./tests/run-tests.sh --os rocky9 --parallel            # Rocky 9, parallel
#   ./tests/run-tests.sh --parallel --filter "quarantine"  # Parallel + filter
#   ./tests/run-tests.sh --filter "quarantine"            # Filter by test name
#   ./tests/run-tests.sh /opt/tests/02-scan-md5.bats      # Specific test file
#   ./tests/run-tests.sh --os centos7 --filter "MD5"      # OS + filter
#
# Supported targets (CI matrix marked with *):
#   debian12   * Debian 12 slim (default)
#   centos6    * CentOS 6 (EOL, vault repos)
#   centos7    * CentOS 7 (EOL)
#   rocky8     * Rocky Linux 8
#   rocky9     * Rocky Linux 9
#   rocky10      Rocky Linux 10 (pending stable)
#   ubuntu2004 * Ubuntu 20.04 LTS
#   ubuntu2404 * Ubuntu 24.04 LTS
#   yara-x     * YARA-X (yr) on Debian 12
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

ALL_TARGETS="centos6 centos7 rocky8 rocky9 rocky10 ubuntu2004 ubuntu2404 debian12 yara-x"

usage() {
    echo "Usage: $0 [--os OS] [--parallel [N]] [--filter PATTERN] [BATS_ARGS...]"
    echo ""
    echo "Options:"
    echo "  --os OS           Target OS (default: debian12)"
    echo "  --parallel [N]    Run test files in N parallel containers (default: nproc*2)"
    echo "  --filter PATTERN  Filter tests by name (passed to bats --filter)"
    echo "  --help            Show this help"
    echo ""
    echo "Any remaining arguments are passed directly to bats."
    echo "Specific test file paths bypass parallel mode."
    echo ""
    echo "Supported targets:"
    echo "  $ALL_TARGETS"
    exit "${1:-0}"
}

OS="debian12"
PARALLEL=0
PARALLEL_N=0
BATS_ARGS=()
EXPLICIT_FILES=0

while [ $# -gt 0 ]; do
    case "$1" in
        --os)
            shift
            OS="$1"
            ;;
        --parallel)
            PARALLEL=1
            # Check if next arg is a number (optional N)
            if [ $# -ge 2 ] && [[ "$2" =~ ^[0-9]+$ ]]; then
                PARALLEL_N="$2"
                shift
            fi
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
            EXPLICIT_FILES=1
            ;;
    esac
    shift
done

# Map OS to Dockerfile
case "$OS" in
    debian12)
        DOCKERFILE="$SCRIPT_DIR/Dockerfile"
        ;;
    centos6|centos7|rocky8|rocky9|rocky10|ubuntu2004|ubuntu2404|yara-x)
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

# Direct mode: explicit file paths bypass parallel
if [ "$EXPLICIT_FILES" -eq 1 ]; then
    echo "=== Running tests: ${OS} ==="
    docker run --rm "$IMAGE_TAG" bats --formatter tap "${BATS_ARGS[@]}"
    exit $?
fi

# Sequential mode (no --parallel)
if [ "$PARALLEL" -eq 0 ]; then
    echo "=== Running tests: ${OS} ==="
    if [ ${#BATS_ARGS[@]} -gt 0 ]; then
        docker run --rm "$IMAGE_TAG" bats --formatter tap "${BATS_ARGS[@]}"
    else
        docker run --rm "$IMAGE_TAG"
    fi
    exit $?
fi

# --- Parallel mode ---

# Determine number of parallel groups
if [ "$PARALLEL_N" -gt 0 ]; then
    NUM_GROUPS="$PARALLEL_N"
else
    NUM_GROUPS=$(( $(nproc) * 2 ))
    [ "$NUM_GROUPS" -lt 1 ] && NUM_GROUPS=1
fi

# Discover test files (sorted by name)
TEST_FILES=()
while IFS= read -r f; do
    TEST_FILES+=("$f")
done < <(ls "$SCRIPT_DIR"/[0-9]*.bats 2>/dev/null | sort)

NUM_FILES=${#TEST_FILES[@]}
if [ "$NUM_FILES" -eq 0 ]; then
    echo "No test files found"
    exit 1
fi

# Cap groups at number of files
[ "$NUM_GROUPS" -gt "$NUM_FILES" ] && NUM_GROUPS="$NUM_FILES"

# Round-robin distribute files into groups
declare -a GROUP_FILES
for i in $(seq 0 $(( NUM_GROUPS - 1 ))); do
    GROUP_FILES[$i]=""
done

for i in $(seq 0 $(( NUM_FILES - 1 ))); do
    group=$(( i % NUM_GROUPS ))
    fname="$(basename "${TEST_FILES[$i]}")"
    container_path="/opt/tests/$fname"
    if [ -z "${GROUP_FILES[$group]}" ]; then
        GROUP_FILES[$group]="$container_path"
    else
        GROUP_FILES[$group]="${GROUP_FILES[$group]} $container_path"
    fi
done

# Build extra bats args (e.g., --filter) to pass to each group
EXTRA_ARGS=""
if [ ${#BATS_ARGS[@]} -gt 0 ]; then
    for arg in "${BATS_ARGS[@]}"; do
        EXTRA_ARGS="$EXTRA_ARGS $arg"
    done
fi

# Create temp dir for output
TMPDIR_PAR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_PAR"' EXIT

echo "=== Running tests: ${OS} (parallel: ${NUM_GROUPS} groups, ${NUM_FILES} files) ==="
START_TIME=$SECONDS

# Launch containers in parallel
PIDS=()
for i in $(seq 0 $(( NUM_GROUPS - 1 ))); do
    # shellcheck disable=SC2086
    docker run --rm "$IMAGE_TAG" \
        bats --formatter tap $EXTRA_ARGS ${GROUP_FILES[$i]} \
        > "$TMPDIR_PAR/group-$i.tap" 2>&1 &
    PIDS+=($!)
done

# Wait for all containers, collect exit codes
FAILED_GROUPS=0
EXIT_CODES=()
for i in $(seq 0 $(( NUM_GROUPS - 1 ))); do
    if wait "${PIDS[$i]}"; then
        EXIT_CODES[$i]=0
    else
        EXIT_CODES[$i]=1
        FAILED_GROUPS=$(( FAILED_GROUPS + 1 ))
    fi
done

ELAPSED=$(( SECONDS - START_TIME ))

# Display output with group headers
TOTAL_TESTS=0
TOTAL_PASS=0
TOTAL_FAIL=0
for i in $(seq 0 $(( NUM_GROUPS - 1 ))); do
    # Build short file list for header
    short_names=""
    # shellcheck disable=SC2086
    for f in ${GROUP_FILES[$i]}; do
        name="$(basename "$f" .bats)"
        if [ -z "$short_names" ]; then
            short_names="$name"
        else
            short_names="$short_names $name"
        fi
    done

    status="PASS"
    [ "${EXIT_CODES[$i]}" -ne 0 ] && status="FAIL"

    echo ""
    echo "=== Group $((i+1))/$NUM_GROUPS [$status]: $short_names ==="
    cat "$TMPDIR_PAR/group-$i.tap"

    # Count tests from TAP output
    while IFS= read -r line; do
        case "$line" in
            ok\ *)
                TOTAL_TESTS=$(( TOTAL_TESTS + 1 ))
                TOTAL_PASS=$(( TOTAL_PASS + 1 ))
                ;;
            not\ ok\ *)
                TOTAL_TESTS=$(( TOTAL_TESTS + 1 ))
                TOTAL_FAIL=$(( TOTAL_FAIL + 1 ))
                ;;
        esac
    done < "$TMPDIR_PAR/group-$i.tap"
done

echo ""
PASSED_GROUPS=$(( NUM_GROUPS - FAILED_GROUPS ))
echo "=== Results: $PASSED_GROUPS/$NUM_GROUPS groups passed ($TOTAL_TESTS tests, $TOTAL_FAIL failed) in ${ELAPSED}s ==="

[ "$FAILED_GROUPS" -gt 0 ] && exit 1
exit 0
