# Name         Date         Description
# -----------------------------------------------------------------------------------------------------------
# G.MOURNETAS  11/05/2026   Ensure there are no shared folders other than 'Printer Queues' and 'Admin shares'

Try {
    $RandomID = (New-Guid).Guid
    $ExportFile = "$env:TEMP\secexport_$RandomID.txt"
	
	$64Bit = [Environment]::Is64BitProcess
	$secedit = Test-Path -Path "C:\Windows\System32\secedit.exe"
	Write-Output "$env:PATH  $env:PATHEXT $64Bit $secedit"
    
    secedit /export /cfg $ExportFile /quiet

    $PASSING = $true
    $Violations = @()

    $AllowedSharesRegex = "^(IPC\$|print\$|ADMIN\$|[A-Za-z]\$|.*Brother.*|.*Canon.*|.*Epson.*|.*HP.*|.*LaserJet.*|.*Ricoh.*|.*Xerox.*)$"
    $AllowedTypes = @(1, 2147483648, 2147483649, 2147483650, 2147483651)


	$AltMethod = Get-SmbShare | Select-Object Name, Path, Description, ShareType
    $AllShares = Get-CimInstance -ClassName Win32_Share -ErrorAction Stop

    foreach ($Share in $AllShares) {
        $ShareName = $Share.Name
        $ShareType = $Share.Type

        if ($AllowedTypes -contains $ShareType) {
		$ShareNamesandTypes += " $ShareName $ShareType "
            continue 
        }

        if ($ShareName -imatch $AllowedSharesRegex) {
            continue 
        }

        $PASSING = $false
        $Violations += "$ShareName (Path: $($Share.Path))"
    }

    if ($PASSING -eq $true) {
        Write-Output "Check Status : Compliant. $ShareNamesandTypes"
    }
    else {
        $ViolationsString = $Violations -join ", "
        Write-Output "Check Status : Non-Compliant. $ShareNamesandTypes"
        Write-Output "Unauthorized shared folders found: $ViolationsString"
    }

    Remove-Item $ExportFile -ErrorAction SilentlyContinue
}
Catch {
    Write-Output "Check status : Error. $_ Altern method : $AltMethod"
}
