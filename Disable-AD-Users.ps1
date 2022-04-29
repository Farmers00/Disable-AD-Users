Import-Module ActiveDirectory

Add-Type -AssemblyName System.Windows.Forms
$FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
    InitialDirectory = [Environment]::GetFolderPath('Desktop')
    Filter = 'txt (*.txt)|*.txt|csv (*.csv)|*.csv'
    }
$FileBrowser.ShowDialog() | Out-Null
$CSVPath = $FileBrowser.FileName

#Create an array to hold the User information
$Users = @()
$Results = @()

#Pulls from headerless CSV or TXT file, sets up filter, searches AD for users not in .Employee Email OU and adds them to Users array
#Writes any issues or errors to console and $Results array
ForEach ($Line in (Get-Content $CSVPath | ConvertFrom-CSV -Header LastName,FirstName))
{
    $Filter = "givenName -eq ""$($Line.FirstName)"" -and sn -eq ""$($Line.LastName)"""
    $UserSearch = Get-ADUser -Properties PrimaryGroup -Filter $Filter | Select Name,UserPrincipalName,samAccountName,Enabled,DistinguishedName,PrimaryGroup

    #Change or remove this If statement if you do things differently    
    If ($UserSearch -ne $null)
    {
        If ($UserSearch.DistinguishedName -NotLike "*OU=.Employee Email,OU=Employees*")
        {
            $Users += $UserSearch
        }
        Else {
            Write-Host "$($UserSearch.Name) email is still being accessed by management."
            $Results += [PSCustomObject]@{
                Name = "$($UserSearch.Name)"
                UPN = "$($User.UserPrincipalName)"
                Status = "Email is still being accessed by management"
            }
        } 
    }
    Else {
        Write-Host "$($Line.Firstname) $($Line.LastName) not found."
        $Results += [PSCustomObject]@{
            Name = "$($Line.FirstName)"+" "+"$($Line.LastName)"
            UPN = ""
            Status = "User not found"
        }
    }  
}

#Pulls from $Users array, disables account, removes all group memberships, and sets description
#Writes any issues or errors to console and $Results array
ForEach ($User in $Users)
{
    Disable-ADAccount -Identity $User.samAccountName
    If ($User.PrimaryGroup -Like "*Domain Users*")
    {
        Try {
            $ADGroups = Get-ADPrincipalGroupMembership -Identity $User.samAccountName | Where {$_.Name -ne "Domain Users"}
        }
        Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
        {
            Write-Host "Unable to search $($User.Name) for groups." -ForegroundColor Red
            $Results += [PSCustomObject]@{
            Name = "$($User.Name)"
            UPN = "$($User.UserPrincipalName)"
            Status = "Unable to search $($User.Name) for groups"
            }
        }
        ForEach ($ADGroup in $ADGroups)
        {
            Remove-ADPrincipalGroupMembership -Identity $User.samAccountName -MemberOf $ADGroup -Confirm:$False
        }
    }
    Else {
        Write-Host "$($User.Name) default group is $($User.PrimaryGroup)." -ForegroundColor Red
        $Results += [PSCustomObject]@{
        Name = "$($User.Name)"
        UPN = "$($User.UserPrincipalName)"
        Status = "Default group is $($User.PrimaryGroup)"
        }
    }
    Set-ADUser -Identity $User.samAccountName -Description "***Disabled by admin on $(Get-Date -Format "MM/dd/yyyy") per ticket***"
    Write-Host "$($User.Name) has been disabled and groups are removed."
    $Results += [PSCustomObject]@{
        Name = "$($User.Name)"
        UPN = "$($User.UserPrincipalName)"
        Status = "User disabled and groups are removed"
    }
}

#Exports $Results array to same location as initial CSV or TXT import file, names it the same and appends _Results.cvs to the end
$Results | Export-CSV -Path "$($FileBrowser.FileName)_Results.csv" -NoTypeInformation