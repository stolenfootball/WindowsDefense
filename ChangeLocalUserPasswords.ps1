# Script to change local account passwords on each computer
# * NEED TO CHANGE FIREWALL RULES TO WORK *

Import-Module ActiveDirectory

Function Get-RandomPassword {
    # Define parameter with password length
    param([int]$PasswordLength = 20)

    # Store password combinations into a set
    $CharacterSet = @{
        Lowercase = (97..122) | Get-Random -Count 10 | % {[char]$_}
        Uppercase = (65..90) | Get-Random -Count 10 | % {[char]$_}
        Numeric = (48..57) | Get-Random -Count 10 | %{[char]$_}
        SpecialChar = (33..47)+(58..64)+(91..96)+(123..126) | Get-Random -Count 10 | % {[char]$_}
    }

    # Frame random password
    $StringSet = $CharacterSet.Lowercase + $CharacterSet.Uppercase + $CharacterSet.Numeric + $CharacterSet.SpecialChar
    -join(Get-Random -Count $PasswordLength -InputObject $StringSet)
}


# Find and store all ad computers
$computers = Get-ADComputer -Filter { OperatingSystem -notlike "*Server*"}

# Get Credential of an admin account who has permission to run Invoke-Command
$cred = Get-Credential

foreach ($each in $computers) {
    $computer = $each.Name

    # Test connection status
    if (test-Connection -Cn $computer -quiet) {
        try {
            # get all local users on the computer
            # will need to enable wmi firewall rule for domain
            $users = Get-WmiObject -ComputerName $computer -Class win32_UserAccount -Filter "LocalAccount=True" | Select-Object -ExpandProperty name
            
            # alternative: $users = Invoke-Command -ComputerName $computer -ScriptBlock {Get-LocalUser -name "username" | select Username}
            
            # change password for each user
            foreach($user in $users) {
                $plainPassword = Get-RandomPassword
                $newPassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force
                Invoke-Command -ComputerName $computer -Credential $cred -ScriptBlock { Set-LocalUser -Name $user -Password $newPassword }
                Write-Output("Password change successful")
            }
        }
        catch {
            Write-Output("Password change failed")
        }

    }
    else {
        Write-Output("$computer is offline")
    }
}
