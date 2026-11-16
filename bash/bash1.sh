#!/bin/bash
#
# Name       Date       Description
# -----------------------------------------------------------------
# R. Casagrande  19/08/2025  Ensure X Window System is not installed

SERVICE_INSTALL_STATUS_COMMAND=$(rpm -qa xorg-x11-server-*)

if [[ -z $SERVICE_INSTALL_STATUS_COMMAND ]]; then
    echo "Check status: Compliant."
    exit "${XCCDF_RESULT_PASS:-101}"
else
    echo "Check status: Non-compliant. The following xorg-x11-server packages are installed: $SERVICE_INSTALL_STATUS_COMMAND"
    exit "${XCCDF_RESULT_FAIL:-102}"
fi
