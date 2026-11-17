#!/bin/bash
#
# Name       Date       Description
# -----------------------------------------------------------------
# TEST       17/11/2026  TEST - Ensure /etc/passwd exists (expected PASSED)

# /etc/passwd exists on every Linux system, so this check should always pass.
FILE="/etc/passwd"

if [[ -f "$FILE" ]]; then
    echo "Check status: Compliant. $FILE exists on $(hostname)."
else
    echo "Check status: Non-compliant. $FILE was not found on $(hostname)."
fi
