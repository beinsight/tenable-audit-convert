# 
# Name       Date       Description
# ----------------------------------------------------------------
# K. Hamon  04/24/2024  Check Splunk execute Splunk and search log


try {
    # Define the command to run splunk.exe btool

        # Define the paths to the Splunk executable on both D: and C: drives
    $SPLUNK_PATH_D = "d:\Program Files\SplunkUniversalForwarder\bin\splunk.exe"
    $SPLUNK_PATH_C = "c:\Program Files\SplunkUniversalForwarder\bin\splunk.exe"
    $SPLUNK_PATH_E = "e:\Program Files\SplunkUniversalForwarder\bin\splunk.exe"

    # Check if the Splunk executable exists on the D: drive
    if (Test-Path $SPLUNK_PATH_D) {
        # If found, set the path to the D: drive version
        $SPLUNK_PATH = $SPLUNK_PATH_D
    } elseif (Test-Path $SPLUNK_PATH_E) {
        # If not found on D: drive, check and set the path to the C: drive version
        $SPLUNK_PATH = $SPLUNK_PATH_E
        
    }elseif (Test-Path $SPLUNK_PATH_C) {
        # If not found on D: drive, check and set the path to the C: drive version
        $SPLUNK_PATH = $SPLUNK_PATH_C
        
    } else {
        # If not found on both drives, output an error message and exit
        Write-Host "Check status: Error. Splunk executable not found on D: or C: or E: drives."
        exit 1
    }

# Run the Splunk command
$SPLUNK_COMMAND = & $SPLUNK_PATH btool inputs list WinEventLog://Microsoft-Windows-Sysmon/Operational


    # Run the command and capture the output
    $OUTPUT = $SPLUNK_COMMAND

    # Define expected values
    $EXPECTED_VALUE = @{
        "disabled"    = "0"
        "current_only" = "0"
        "start_from"  = "oldest"
    }

    # Parse the output into a hashtable
    $OUTPUT_LINES = $OUTPUT -split "`r`n"
    $OUTPUT_VALUES = @{}
    foreach ($LINE in $OUTPUT_LINES) {
        if ($LINE -match "(\S+)\s*=\s*(\S+)") {
            $OUTPUT_VALUES[$MATCHES[1]] = $MATCHES[2]
        }
    }

    # Initialize compliance status
    $COMPLIANCE_CHECK  = $TRUE

    # Check each expected value and provide detailed feedback
    foreach ($KEY in $EXPECTED_VALUE.Keys) {
        if ($OUTPUT_VALUES.ContainsKey($KEY)) {
            if ($OUTPUT_VALUES[$KEY] -ne $EXPECTED_VALUE[$KEY]) {
                $COMPLIANCE_CHECK = $FALSE
            }
        } else {
            $COMPLIANCE_CHECK = $FALSE
        }
    }

    # Final result output
    if ($COMPLIANCE_CHECK) {
        Write-Host "Check status: Compliant"
    } else {
        Write-Host "Check status: Non-Compliant. "$OUTPUT" are incorrect."
    }
} catch {
    Write-Host "Check status: Error. Details: $_"
    break
}
