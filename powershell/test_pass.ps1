# Name         Date         Description
# -----------------------------------------------------------------
# TEST         17/11/2026   TEST - Ensure the Windows System32 folder exists (expected PASSED)

# The System32 folder exists on every Windows machine, so this check should always pass.
Try {
    $Folder = Join-Path $env:SystemRoot "System32"
    $Hostname = [System.Environment]::MachineName

    if (Test-Path -Path $Folder) {
        Write-Output "Check Status : Compliant. $Folder exists on $Hostname."
    } else {
        Write-Output "Check Status : Non-Compliant. $Folder was not found on $Hostname."
    }
}
Catch {
    Write-Output "Check Status : Error. $_"
}
