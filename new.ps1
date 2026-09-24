#Requires -Modules ActiveDirectory
<#
Backs up and restores specific ACEs (by trustee) on AD objects.

Backup takes a CSV with two columns, ObjectDN and Trustee (domain\user format,
trustee can be a group/computer account too, so it may end in $ and contain
spaces, dashes, underscores or &). For every object in the CSV it grabs the
current ACL, keeps only the ACEs belonging to the trustees you listed for
that object, and writes them out to <objectname>.xml in the current folder.

Restore takes one of those xml files, shows the ACEs in Out-GridView so you
can pick which ones to put back, asks for confirmation, then re-applies
them.

Usage:
    .\ADAclTool.ps1 -Backup  -CsvPath .\acl-selection.csv
    .\ADAclTool.ps1 -Restore -XmlPath .\Sales.xml

CSV format:
    ObjectDN,Trustee
    "OU=Sales,DC=contoso,DC=com",CONTOSO\jdoe
    "OU=Sales,DC=contoso,DC=com",CONTOSO\svc-backup$
    "CN=Finance Admins,OU=Groups,DC=contoso,DC=com","CONTOSO\Help Desk L2"
#>

param(
    [Parameter(ParameterSetName = 'Backup', Mandatory)]
    [switch]$Backup,

    [Parameter(ParameterSetName = 'Backup', Mandatory)]
    [string]$CsvPath,

    [Parameter(ParameterSetName = 'Restore', Mandatory)]
    [switch]$Restore,

    [Parameter(ParameterSetName = 'Restore', Mandatory)]
    [string]$XmlPath
)

Import-Module ActiveDirectory -ErrorAction Stop

function Backup-Acl {
    param($CsvPath)

    if (-not (Test-Path $CsvPath)) {
        Write-Error "Can't find $CsvPath"
        return
    }

    $rows = Import-Csv $CsvPath
    if (-not $rows) {
        Write-Error "CSV empty - expecting ObjectDN,Trustee columns ..."
        return
    }

    # one file per object.
    
    $groups = $rows | Group-Object ObjectDN

    foreach ($group in $groups) {
        $dn = $group.Name.Trim()
        $trustees = $group.Group.Trustee | ForEach-Object { $_.Trim() }

        try {
            $obj = Get-ADObject -Identity $dn -Properties Name
        }
        catch {
            Write-Warning "Skipping $dn - couldn't find that object ..."
            continue
        }

        $acl = Get-Acl "AD:\$dn"

        $matches = $acl.Access | Where-Object { $trustees -contains $_.IdentityReference.Value }

        if (-not $matches) {
            Write-Warning "None of the listed trustees have an ACE on $dn ..."
            continue
        }

        $export = foreach ($ace in $matches) {
            [PSCustomObject]@{
                ObjectDN              = $dn
                IdentityReference     = $ace.IdentityReference.Value
                ActiveDirectoryRights = $ace.ActiveDirectoryRights.ToString()
                AccessControlType     = $ace.AccessControlType.ToString()
                ObjectType            = $ace.ObjectType.ToString()
                InheritedObjectType   = $ace.InheritedObjectType.ToString()
                InheritanceType       = $ace.InheritanceType.ToString()
                IsInherited           = $ace.IsInherited
            }
        }

        # name the file after the object itself.
        
        $fileName = ($obj.Name -replace '[\\/:*?"<>|]', '_') + '.xml'
        $export | Export-Clixml -Path $fileName

        Write-Host "Saved $($export.Count) ACE(s) for '$($obj.Name)' -> $fileName"
    }
}

function Restore-Acl {
    param($XmlPath)

    if (-not (Test-Path $XmlPath)) {
        Write-Error "Can't find $XmlPath !!!"
        return
    }

    $entries = Import-Clixml $XmlPath

    $picked = $entries | Out-GridView -Title "Select the ACE(s) to restore ..." -OutputMode Multiple
    if (-not $picked) {
        Write-Host "Nothing selected ... Exiting."
        return
    }

    Write-Host "`n About to restore:"
    $picked | Format-Table ObjectDN, IdentityReference, ActiveDirectoryRights, AccessControlType -AutoSize | Out-Host

    $confirm = Read-Host "Type YES to apply these changes"
    if ($confirm -ne 'YES') {
        Write-Host "Cancelled ... Exiting."
        return
    }

    foreach ($group in ($picked | Group-Object ObjectDN)) {
        $dn = $group.Name
        $acl = Get-Acl "AD:\$dn"

        foreach ($entry in $group.Group) {
            $identity    = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            $rights      = [System.DirectoryServices.ActiveDirectoryRights]$entry.ActiveDirectoryRights
            $type        = [System.Security.AccessControl.AccessControlType]$entry.AccessControlType
            $inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]$entry.InheritanceType
            $objType     = [Guid]$entry.ObjectType
            $inhObjType  = [Guid]$entry.InheritedObjectType

            $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $identity, $rights, $type, $objType, $inheritance, $inhObjType
            )

            $acl.AddAccessRule($rule)
        }

        Set-Acl "AD:\$dn" $acl
        Write-Host "Restored $($group.Group.Count) ACE(s) on $dn ..."
    }
}

if ($Backup)  { Backup-Acl  -CsvPath $CsvPath }
if ($Restore) { Restore-Acl -XmlPath $XmlPath }
