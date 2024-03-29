Import-Module ActiveDirectory

# Select input file using File Dialog
Add-Type -AssemblyName System.Windows.Forms
$OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog -Property @{
    InitialDirectory = [Environment]::GetFolderPath('Desktop')
    Filter = 'txt (*.txt)|*.txt|csv (*.csv)|*.csv'
    }
$OpenFileDialog.ShowDialog() | Out-Null
$CSVPath = $OpenFileDialog.FileName

# Validate input file selection
if (!$CSVPath) {
    Write-Error "No input file was selected."
    break
}

# Create an array to hold the User information
$Users = @()
$Results = @()

# Sets counters to 0 for percentages
$counter1 = 0
$counter2 = 0

# Pulls from headerless CSV or TXT file, sets up filter, searches AD for users not in .Employee Email OU and adds them to Users array
# Writes any issues or errors to console and $Results array
foreach ($Line in (Get-Content $CSVPath | ConvertFrom-CSV -Header LastName,FirstName)) {
    $counter1++
    $Filter = "givenName -eq ""$($Line.FirstName)"" -and sn -eq ""$($Line.LastName)"""
    $UserSearch = Get-ADUser -Properties PrimaryGroup -Filter $Filter | Select-Object Name,UserPrincipalName,samAccountName,Enabled,DistinguishedName,PrimaryGroup

    # Change or remove this If statement if you do things differently
    if ($null -ne $UserSearch) {
        if ($UserSearch.DistinguishedName -NotLike "*OU=.Employee Email,OU=Employees*") {
            $Users += $UserSearch
        }
        else {
            Write-Host "$($UserSearch.Name) email is still being accessed by management."
            $Results += [PSCustomObject] @{
                Name = "$($UserSearch.Name)"
                UPN = "$($User.UserPrincipalName)"
                Status = "Email is still being accessed by management"
            }
        } 
    }
    else {
        Write-Host "$($Line.Firstname) $($Line.LastName) not found."
        $Results += [PSCustomObject] @{
            Name = "$($Line.FirstName)"+" "+"$($Line.LastName)"
            UPN = ""
            Status = "User not found"
        }
    }
    Write-Progress -Activity "Searcing for Users" -CurrentOperation $Line -PercentComplete (($counter1 / $CSVPath.count) * 100)
}

# Pulls from $Users array, disables account, removes all group memberships, and sets description
# Writes any issues or errors to console and $Results array
foreach ($User in $Users) {
    $counter2++
    Disable-ADAccount -Identity $User.samAccountName
    if ($User.PrimaryGroup -Like "*Domain Users*") {
        try {
            $ADGroups = Get-ADPrincipalGroupMembership -Identity $User.samAccountName | Where-Object {$_.Name -ne "Domain Users"}
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-Host "Unable to search $($User.Name) for groups." -ForegroundColor Red
            $Results += [PSCustomObject] @{
            Name = "$($User.Name)"
            UPN = "$($User.UserPrincipalName)"
            Status = "Unable to search $($User.Name) for groups"
            }
        }
        foreach ($ADGroup in $ADGroups) {
            Remove-ADPrincipalGroupMembership -Identity $User.samAccountName -MemberOf $ADGroup -Confirm:$False
        }
    }
    else {
        Write-Host "$($User.Name) default group is $($User.PrimaryGroup)." -ForegroundColor Red
        $Results += [PSCustomObject] @{
        Name = "$($User.Name)"
        UPN = "$($User.UserPrincipalName)"
        Status = "Default group is $($User.PrimaryGroup)"
        }
    }
    Set-ADUser -Identity $User.samAccountName -Description "***Disabled by $($env:UserName) on $(Get-Date -Format "MM/dd/yyyy") per ticket***"
    Write-Host "$($User.Name) has been disabled and groups are removed."
    $Results += [PSCustomObject] @{
        Name = "$($User.Name)"
        UPN = "$($User.UserPrincipalName)"
        Status = "User disabled and groups are removed"
    }
    Write-Progress -Activity "Disabling Users" -CurrentOperation $User -PercentComplete (($counter2 / $Users.count) * 100)
}

# Exports $Results array to same location as initial CSV or TXT import file, names it the same and appends _Results.cvs to the end
$Results | Export-CSV -Path "$($OpenFileDialog.FileName)_Results.csv" -NoTypeInformation
Invoke-Item "$($OpenFileDialog.FileName)_Results.csv"