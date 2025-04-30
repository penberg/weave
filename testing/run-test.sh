#!/bin/bash
# LLVM lit-like test runner for Weave
# Usage: run-test.sh <test-binary> <source-file> <suite-name>
#
# Extracts CHECK directives from source files and verifies test output.
# If no CHECK directives are present, only verifies exit code is 0.

BINARY="$1"
SOURCE="$2"
SUITE="$3"
WEAVE="../../target/debug/weave"

# Extract CHECK lines from source (supports // and # comments)
EXPECTED=$(grep -E '^[[:space:]]*(//|#)[[:space:]]*CHECK:' "$SOURCE" 2>/dev/null | \
           sed -E 's/^[[:space:]]*(\/\/|#)[[:space:]]*CHECK:[[:space:]]?//')

# Run test
OUTPUT=$($WEAVE -- "./$BINARY" 2>&1)
STATUS=$?

# If no CHECK directives, just verify exit code
if [ -z "$EXPECTED" ]; then
    if [ $STATUS -eq 0 ]; then
        echo "PASS: $SUITE/$BINARY"
        exit 0
    else
        echo "FAIL: $SUITE/$BINARY (exit code: $STATUS)"
        echo "$OUTPUT"
        exit 1
    fi
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
