#!/bin/bash
#
# Name       Date       Description
# -----------------------------------------------------------------
# TEST       17/11/2026  TEST - Ensure test marker file exists (expected FAILED)

# This file does not exist on a normal machine, so this check should fail.
# To see it turn PASSED, create the file on the target and scan again:
#     sudo touch /tmp/tenable_audit_test
FILE="/tmp/tenable_audit_test"

if [[ -f "$FILE" ]]; then
    echo "Check status: Compliant. $FILE exists on $(hostname)."
else
    echo "Check status: Non-compliant. $FILE was not found on $(hostname)."
fi
