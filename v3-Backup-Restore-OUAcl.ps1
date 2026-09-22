#Requires -Version 5.1
<#
.SYNOPSIS
    Backs up and restores a granular, hand-picked set of ACEs (Access Control Entries)
    on an Active Directory Organizational Unit (or any AD object).

.DESCRIPTION
    Unlike a full ACL backup, this script lets you select exactly which ACEs to capture
    and later re-apply, either by identity filter or interactively via a grid-view picker.

    - Backup:  Reads the object's ACL, optionally filters/lets you pick specific ACEs,
               and saves them (with full object/inheritance GUID fidelity) to a CLIXML file.
               A companion .csv is also written for easy human review.
    - Restore: Reads a previously saved CLIXML file, optionally filters/lets you pick which
               ACEs to re-apply, takes an automatic "pre-restore" safety backup of the
               target's current ACL, then adds the selected ACEs back onto the object.

    Only explicit (non-inherited) ACEs are captured by default, since inherited ACEs live
    on the parent and cannot be meaningfully restored onto a child. Use -IncludeInherited
    to capture them anyway (they will be skipped automatically on restore).

    Uses ADSI/System.DirectoryServices directly, so no ActiveDirectory/RSAT module is
    required. Supports -WhatIf/-Confirm.

.PARAMETER Action
    Backup or Restore.

.PARAMETER OU
    Distinguished Name of the target OU / AD object, e.g. "OU=Finance,DC=contoso,DC=com".

.PARAMETER Path
    File path for the backup data (CLIXML). On backup, this is the output file
    (a sibling .csv report is also created). On restore, this is the input file.

.PARAMETER Identity
    One or more wildcard patterns (e.g. "CONTOSO\Finance*", "*Domain Admins*") to filter
    which ACEs are considered, for both Backup and Restore.

.PARAMETER Interactive
    Show an Out-GridView multi-select picker so you can hand-pick ACEs, for both
    Backup (picking from the live ACL) and Restore (picking from the saved file).

.PARAMETER IncludeInherited
    Include inherited ACEs when backing up (informational only; they are not restorable).

.PARAMETER Server
    Optional domain controller / server name to bind against.

.PARAMETER Credential
    Optional alternate credentials to use for the LDAP bind.

.PARAMETER NoSafetyBackup
    Skip the automatic pre-restore safety backup (not recommended).

.EXAMPLE
    .\Backup-Restore-OUAcl.ps1 -Action Backup -OU "OU=Finance,DC=contoso,DC=com" `
        -Path C:\ACL\Finance.xml -Interactive

    Opens a grid-view of every explicit ACE on the Finance OU so you can pick which
    ones to save.

.EXAMPLE
    .\Backup-Restore-OUAcl.ps1 -Action Backup -OU "OU=Finance,DC=contoso,DC=com" `
        -Path C:\ACL\Finance.xml -Identity "CONTOSO\HelpDesk*","CONTOSO\Finance-Admins"

    Saves only ACEs whose identity matches the given patterns.

.EXAMPLE
    .\Backup-Restore-OUAcl.ps1 -Action Restore -OU "OU=Finance,DC=contoso,DC=com" `
        -Path C:\ACL\Finance.xml -Interactive -WhatIf

    Shows a grid-view of saved ACEs, lets you pick which to re-apply, and previews the
    change without committing it (remove -WhatIf to actually apply).

.NOTES
    Run from a machine that can resolve the target domain, as an account with
    "Modify Permissions" rights on the target OU (or as Domain Admin).
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Backup', 'Restore')]
    [string]$Action,

    [Parameter(Mandatory = $true)]
    [string]$OU,

    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string[]]$Identity,

    [switch]$Interactive,

    [switch]$IncludeInherited,

    [string]$Server,

    [pscredential]$Credential,

    [switch]$NoSafetyBackup
)

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
try {
    Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
} catch {
    Write-Verbose "System.DirectoryServices already loaded or unavailable: $_"
}

function Get-TargetEntry {
    param(
        [Parameter(Mandatory)][string]$DistinguishedName,
        [string]$Server,
        [pscredential]$Credential
    )

    $ldapPath = if ($Server) { "LDAP://$Server/$DistinguishedName" } else { "LDAP://$DistinguishedName" }

    try {
        if ($Credential) {
            $networkCred = $Credential.GetNetworkCredential()
            $de = New-Object System.DirectoryServices.DirectoryEntry(
                $ldapPath, $networkCred.UserName, $networkCred.Password
            )
        } else {
            $de = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        }
        # Force a bind now so we fail fast with a clear error if the DN is wrong.
        $null = $de.NativeGuid
    } catch {
        throw "Unable to bind to '$DistinguishedName'. Check the DN, connectivity, and permissions. Underlying error: $($_.Exception.Message)"
    }

    return $de
}

function ConvertTo-AceRecord {
    param(
        [Parameter(Mandatory)]$Rule,
        [Parameter(Mandatory)][string]$OU
    )

    [PSCustomObject]@{
        OU                    = $OU
        IdentityReference     = $Rule.IdentityReference.Value
        ActiveDirectoryRights = $Rule.ActiveDirectoryRights.ToString()
        AccessControlType     = $Rule.AccessControlType.ToString()
        ObjectType            = $Rule.ObjectType.ToString()
        InheritedObjectType   = $Rule.InheritedObjectType.ToString()
        InheritanceType       = $Rule.InheritanceType.ToString()
        IsInherited           = $Rule.IsInherited
        BackupDate            = (Get-Date)
    }
}

function ConvertFrom-AceRecord {
    param([Parameter(Mandatory)]$Record)

    $identity   = New-Object System.Security.Principal.NTAccount($Record.IdentityReference)
    $rights     = [System.DirectoryServices.ActiveDirectoryRights]$Record.ActiveDirectoryRights
    $type       = [System.Security.AccessControl.AccessControlType]$Record.AccessControlType
    $inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]$Record.InheritanceType
    $objectType         = [Guid]$Record.ObjectType
    $inheritedObjectType = [Guid]$Record.InheritedObjectType
    $emptyGuid = [Guid]::Empty

    if ($objectType -eq $emptyGuid -and $inheritedObjectType -eq $emptyGuid) {
        return New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $identity, $rights, $type, $inheritance
        )
    } elseif ($objectType -ne $emptyGuid -and $inheritedObjectType -eq $emptyGuid) {
        return New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $identity, $rights, $type, $objectType, $inheritance
        )
    } else {
        # Covers: inheritedObjectType set (with or without objectType set)
        return New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $identity, $rights, $type, $objectType, $inheritance, $inheritedObjectType
        )
    }
}

function Test-IdentityMatch {
    param([string]$IdentityValue, [string[]]$Patterns)
    if (-not $Patterns) { return $true }
    foreach ($p in $Patterns) {
        if ($IdentityValue -like $p) { return $true }
    }
    return $false
}

function Invoke-Backup {
    param(
        [string]$OU, [string]$Path, [string[]]$Identity,
        [switch]$Interactive, [switch]$IncludeInherited,
        [string]$Server, [pscredential]$Credential,
        [switch]$Quiet
    )

    $de = Get-TargetEntry -DistinguishedName $OU -Server $Server -Credential $Credential
    $sd = $de.PsBase.ObjectSecurity

    $rules = $sd.GetAccessRules($true, [bool]$IncludeInherited, [System.Security.Principal.NTAccount])

    if ($Identity) {
        $rules = $rules | Where-Object { Test-IdentityMatch -IdentityValue $_.IdentityReference.Value -Patterns $Identity }
    }

    if (-not $rules) {
        Write-Warning "No matching ACEs found on '$OU'. Nothing to back up."
        return
    }

    if ($Interactive) {
        $rules = $rules |
            Select-Object @{n='Identity';e={$_.IdentityReference.Value}}, ActiveDirectoryRights,
                          AccessControlType, InheritanceType, IsInherited, ObjectType, InheritedObjectType |
            Out-GridView -Title "Select ACEs to BACK UP from $OU" -PassThru

        if (-not $rules) {
            Write-Warning "No ACEs selected. Backup cancelled."
            return
        }

        # Re-fetch matching real rule objects so ConvertTo-AceRecord gets full fidelity
        $allRules = $sd.GetAccessRules($true, [bool]$IncludeInherited, [System.Security.Principal.NTAccount])
        $rules = $allRules | Where-Object {
            $r = $_
            $rules | Where-Object {
                $_.Identity -eq $r.IdentityReference.Value -and
                $_.ActiveDirectoryRights -eq $r.ActiveDirectoryRights -and
                $_.AccessControlType -eq $r.AccessControlType -and
                $_.InheritanceType -eq $r.InheritanceType -and
                $_.ObjectType -eq $r.ObjectType -and
                $_.InheritedObjectType -eq $r.InheritedObjectType
            }
        }
    }

    $records = $rules | ForEach-Object { ConvertTo-AceRecord -Rule $_ -OU $OU }

    $records | Export-Clixml -Path $Path -Force
    $csvPath = [System.IO.Path]::ChangeExtension($Path, 'csv')
    $records | Export-Csv -Path $csvPath -NoTypeInformation -Force

    if (-not $Quiet) {
        Write-Host "Backed up $($records.Count) ACE(s) from '$OU'." -ForegroundColor Green
        Write-Host "  Data file  : $Path"
        Write-Host "  Report CSV : $csvPath"
    }
}

function Invoke-Restore {
    param(
        [string]$OU, [string]$Path, [string[]]$Identity,
        [switch]$Interactive, [string]$Server, [pscredential]$Credential,
        [switch]$NoSafetyBackup
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Backup file '$Path' not found."
    }

    $records = Import-Clixml -Path $Path

    if ($Identity) {
        $records = $records | Where-Object { Test-IdentityMatch -IdentityValue $_.IdentityReference -Patterns $Identity }
    }

    $records = $records | Where-Object { -not $_.IsInherited }

    if (-not $records) {
        Write-Warning "No restorable (non-inherited) ACE records matched. Nothing to restore."
        return
    }

    if ($Interactive) {
        $records = $records | Out-GridView -Title "Select ACEs to RESTORE onto $OU" -PassThru
        if (-not $records) {
            Write-Warning "No ACEs selected. Restore cancelled."
            return
        }
    }

    if (-not $NoSafetyBackup) {
        $safetyPath = "{0}.pre-restore-{1}.xml" -f $Path, (Get-Date -Format 'yyyyMMdd-HHmmss')
        Write-Host "Taking safety backup of current ACL on '$OU' -> $safetyPath" -ForegroundColor Yellow
        Invoke-Backup -OU $OU -Path $safetyPath -Server $Server -Credential $Credential -Quiet
    }

    $de = Get-TargetEntry -DistinguishedName $OU -Server $Server -Credential $Credential
    $sd = $de.PsBase.ObjectSecurity

    $applied = 0
    foreach ($record in $records) {
        $desc = "Add ACE: $($record.IdentityReference) | $($record.ActiveDirectoryRights) | $($record.AccessControlType)"
        if ($PSCmdlet.ShouldProcess($OU, $desc)) {
            try {
                $rule = ConvertFrom-AceRecord -Record $record
                $sd.AddAccessRule($rule)
                $applied++
            } catch {
                Write-Warning "Failed to add ACE for '$($record.IdentityReference)': $($_.Exception.Message)"
            }
        }
    }

    if ($applied -gt 0) {
        if ($PSCmdlet.ShouldProcess($OU, "Commit $applied ACE change(s)")) {
            $de.PsBase.CommitChanges()
            Write-Host "Restored $applied ACE(s) onto '$OU'." -ForegroundColor Green
        }
    } else {
        Write-Warning "No ACEs were applied."
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
switch ($Action) {
    'Backup' {
        Invoke-Backup -OU $OU -Path $Path -Identity $Identity -Interactive:$Interactive `
            -IncludeInherited:$IncludeInherited -Server $Server -Credential $Credential
    }
    'Restore' {
        Invoke-Restore -OU $OU -Path $Path -Identity $Identity -Interactive:$Interactive `
            -Server $Server -Credential $Credential -NoSafetyBackup:$NoSafetyBackup
    }
}
