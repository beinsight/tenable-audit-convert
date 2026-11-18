#!/bin/bash
#
# Name       Date       Description
# --------------------------------------------------------------------------------------
# R. Casagrande  29/01/2024  Ensure that Trellix HX agent executable version is approved

EXPECTED_VALUE=34.0
SERVICE_VERSION_COMMAND="/opt/fireeye/bin/xagt -v"

# Capture version output and errors
CMD_OUTPUT=$($SERVICE_VERSION_COMMAND 2>/dev/null)
STDERR_OUTPUT=$($SERVICE_VERSION_COMMAND 2>&1 >/dev/null)

# Extract actual service version
CAPTURE_ACTUAL_SERVICE_VERSION=$(echo "$CMD_OUTPUT" | grep -oP '^v\s*\K[\d.]+')

# Function to compare versions
compare_version_equal_or_greater_than() {
    [ "$1" = "$2" ] || [ "$(printf '%s\n' "$1" "$2" | sort -V | head -n 1)" != "$1" ]
}

# Assess actual service version against expected value
if [[ -n "$CAPTURE_ACTUAL_SERVICE_VERSION" ]]; then
    if compare_version_equal_or_greater_than "$CAPTURE_ACTUAL_SERVICE_VERSION" "$EXPECTED_VALUE"; then
        echo "Check status: Compliant."
        exit "${XCCDF_RESULT_PASS:-101}"
    else
        echo "Check status: Non-compliant. Current version $CAPTURE_ACTUAL_SERVICE_VERSION is outdated. The minimum required version is $EXPECTED_VALUE."
        exit "${XCCDF_RESULT_FAIL:-102}"
    fi
else
    if [[ -n "$STDERR_OUTPUT" ]]; then
        echo "Check status: Error. Error details: $STDERR_OUTPUT"
        exit "${XCCDF_RESULT_ERROR:-103}"
    fi
fi