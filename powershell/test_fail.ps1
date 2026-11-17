# Name         Date         Description
# -----------------------------------------------------------------
# TEST         17/11/2026   TEST - Ensure test marker file exists (expected FAILED)

# This file does not exist on a normal machine, so this check should fail.
# To see it turn PASSED, create the file on the target (as administrator) and scan again:
#     New-Item -Path "$env:ProgramData\tenable_audit_test.txt" -ItemType File
Try {
    $File = Join-Path $env:ProgramData "tenable_audit_test.txt"
    $Hostname = [System.Environment]::MachineName

    if (Test-Path -Path $File) {
        Write-Output "Check Status : Compliant. $File exists on $Hostname."
    } else {
        Write-Output "Check Status : Non-Compliant. $File was not found on $Hostname."
    }
}
Catch {
    Write-Output "Check Status : Error. $_"
}
