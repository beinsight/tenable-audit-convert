# Name             Date         Description
# ---------------------------------------------------------------------------------------------------------------
# G. MOURNETAS     04/08/2026   'Ensure "Do not display the lock screen" is set to "Disable" or "Not Configured"'

Try {
    $IsCompliant = $true
    $Reasons     = @()
    $EXPECTED    = 0

    $LockBypassPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    if (Test-Path $LockBypassPath) {
        $Key = Get-Item -Path $LockBypassPath -ErrorAction SilentlyContinue
        $DisableLock = $Key.GetValue("DisableLockWorkstation")
        
        if ($null -ne $DisableLock -and [int]$DisableLock -eq 1) {
            $IsCompliant = $false
            $Reasons += "Bypass detected: DisableLockWorkstation is enabled (Value: 1)."
        }
    }

    $AutoLogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    if (Test-Path $AutoLogonPath) {
        $Key = Get-Item -Path $AutoLogonPath -ErrorAction SilentlyContinue
        $AutoAdminLogon = $Key.GetValue("AutoAdminLogon")
        
        if ($null -ne $AutoAdminLogon -and ([string]$AutoAdminLogon -eq "1" -or [int]$AutoAdminLogon -eq 1)) {
            $IsCompliant = $false
            $Reasons += "Bypass detected: AutoAdminLogon is active."
        }
    }

    $MDMPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\ADMX_ControlPanelDisplay"
    $MDMKeyName = "CPL_Personalization_NoLockScreen"

    if (Test-Path -Path $MDMPath) {
        $Key = Get-Item -Path $MDMPath -ErrorAction SilentlyContinue
        $MDMValue = $Key.GetValue($MDMKeyName)
        
        if ($null -ne $MDMValue) {
            $ValueAsString = [string]$MDMValue
            if ($ValueAsString -match "<enabled/>" -or $ValueAsString -eq "1") {
                $IsCompliant = $false
                $Reasons += "MDM Override: $MDMKeyName is enabled in Intune PolicyManager."
            }
        }
    }
    
    $SettingKey = "NoLockScreen"
    $PathsToCheck = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization",
        "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Personalization"
    )

    foreach ($Path in $PathsToCheck) {
        if (Test-Path -Path $Path) {
            $Key = Get-Item -Path $Path -ErrorAction SilentlyContinue
            $RawValue = $Key.GetValue($SettingKey)
            
            if ($null -ne $RawValue -and [int]$RawValue -ne $EXPECTED) {
                $IsCompliant = $false
                $Reasons += "GPO Override: $SettingKey is enabled (Value: $RawValue) in '$Path'."
            }
        }
    }


    if ($IsCompliant) {
        Write-Output "Check Status : Compliant."
    } else {
        $FailureDetails = $Reasons -join " | "
        Write-Output "Check Status : Non-Compliant. $FailureDetails"
    }

} Catch {
    Write-Output "Check Status : Error. $_"
}
