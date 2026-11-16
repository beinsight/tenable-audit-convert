## Name      Date         Description
# -----------------------------------------------------------------
# H.GADACHA  07/05/2026   Output members of local administrators group (S-1-5-32-544)

Try {
    $GroupSID = "S-1-5-32-544"
    $MemberList = @()

    $LocalGroup = Get-LocalGroup -SID $GroupSID -ErrorAction Stop
    $Members = Get-LocalGroupMember -Group $LocalGroup -ErrorAction SilentlyContinue

    foreach ($Member in $Members) {
        $MemberName = $Member.Name
        $MemberClass = $Member.ObjectClass.ToLower()
        
        $MemberProvider = "local"
        if ($Member.PrincipalSource -ne "Local") {
            $MemberProvider = "domain"
        }

        $MemberList += "[$MemberName;$MemberClass,$MemberProvider]"
    }

    if ($MemberList.Count -gt 0) {
        $OutputString = $MemberList -join " "
        Write-Output "Check Status : Compliant. list of member=$OutputString"
    }
    else {
        Write-Output "Check Status : Compliant. list of member=No members found"
    }
}
Catch {
    Write-Output "Check Status : Error. $_"
}
