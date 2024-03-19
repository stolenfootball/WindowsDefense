<# READ
Download LAPS x64.msi:
https://www.microsoft.com/en-us/download/details.aspx?id=46899
Installation: 
Disable AdmPwd GPO Extension (it changes AD domain account passwords)
Management Tools -> Enable entire feature will be installed on local hard drive
Everything else uses default
Reboot to ensure script below works

*Do this after running this script*
Create a folder “laps” in sysvol ->copy and paste installed LAPS.x64 into the folder
Group Policy Management -> Create a new group policy->computer configurations->software settings->software installation->new package->paste path to “laps” folder
Administrative Templates->LAPS->Configure settings->Enable local admin password management ->Enable Password Settings (change stuff as needed) -> Enable Do not allow password expiration time longer than required
Link that GPO to OU with client computers
Run gpupdate /force on client computers ->reboot to take effect 
To check passwords: open LAPS UI or Get-AdmPwdPassword -ComputerName {computer name}
#>

# Script to deploy LAPS after installation and before creating a GPO
Import-Module ActiveDirectory
Import-Module AdmPwd.PS

# Update schema
Update-AdmPwdADSchema

# Set permission to OU with client computers
# *Need to change path*
Set-AdmPwdComputerSelfPermission -OrgUnit Workstations

# Create an OU and security group to give permission to view LAPS passwords
# *Need to change path*
New-ADOrganizationalUnit -Name "LAPS" -Path "DC=corp,DC=local"

# *Need to change path*
New-ADGroup -Name "LAPSAdmins" -GroupScope Global -Path "OU=LAPS,DC=corp,DC=local"
Add-ADGroupMember -Identity "LAPSAdmins" -Members "Domain Admins"

# *Need to change path*
Set-AdmPwdReadPasswordPermission -Identity Workstations -AllowedPrincipals "LAPSAdmins"

