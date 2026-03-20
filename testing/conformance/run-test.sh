#!/bin/bash
# LLVM lit-like test runner for Weave
# Usage: run-test.sh <test-binary> <source-file> <suite-name>
#
# Extracts CHECK directives from source files and verifies test output.
# If no CHECK directives are present, only verifies exit code is 0.

BINARY="$1"
SOURCE="$2"
SUITE="$3"
WEAVE="../../../target/debug/weave"

# Extract CHECK lines from source (supports // and # comments)
EXPECTED=$(grep -E '^[[:space:]]*(//|#)[[:space:]]*CHECK:' "$SOURCE" 2>/dev/null | \
           sed -E 's/^[[:space:]]*(\/\/|#)[[:space:]]*CHECK:[[:space:]]?//')
EXPECTED_EXIT=$(grep -E '^[[:space:]]*(//|#)[[:space:]]*EXIT:' "$SOURCE" 2>/dev/null | \
                sed -E 's/^[[:space:]]*(\/\/|#)[[:space:]]*EXIT:[[:space:]]?//' | tail -n 1)

# Run test
OUTPUT=$($WEAVE -- "./$BINARY" 2>&1)
STATUS=$?

# Default to exit status 0 unless the source requests another status.
if [ -z "$EXPECTED_EXIT" ]; then
    EXPECTED_EXIT=0
fi

# If no CHECK directives, just verify exit code
if [ -z "$EXPECTED" ]; then
    if [ "$STATUS" -eq "$EXPECTED_EXIT" ]; then
        echo "PASS: $SUITE/$BINARY"
        exit 0
    else
        echo "FAIL: $SUITE/$BINARY (exit code: $STATUS, expected: $EXPECTED_EXIT)"
        echo "$OUTPUT"
        exit 1
    fi
fi

if [ "$STATUS" -ne "$EXPECTED_EXIT" ]; then
    echo "FAIL: $SUITE/$BINARY (exit code: $STATUS, expected: $EXPECTED_EXIT)"
    echo "$OUTPUT"
    exit 1
fi

# Compare output line by line (strip trailing whitespace for cleaner comparison)
EXPECTED_FILE=$(mktemp)
ACTUAL_FILE=$(mktemp)
trap "rm -f '$EXPECTED_FILE' '$ACTUAL_FILE'" EXIT

echo "$EXPECTED" | sed 's/[[:space:]]*$//' > "$EXPECTED_FILE"
echo "$OUTPUT" | sed 's/[[:space:]]*$//' > "$ACTUAL_FILE"

if diff -q "$EXPECTED_FILE" "$ACTUAL_FILE" > /dev/null 2>&1; then
    echo "PASS: $SUITE/$BINARY"
    exit 0
else
    echo "FAIL: $SUITE/$BINARY"
    echo "--- Expected ---"
    cat "$EXPECTED_FILE"
    echo "--- Actual ---"
    cat "$ACTUAL_FILE"
    echo "--- Diff ---"
    diff "$EXPECTED_FILE" "$ACTUAL_FILE"
    exit 1
fi
