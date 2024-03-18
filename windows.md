# Windows Checklist

## On Initial Connection
1. Find and label DC, CA, Alt Server, and two workstations.  Write down any other roles they have.
```powershell
Get-WindowsFeature -Name $COMPUTERNAME -Credential $PSCREDENTIAL | Where-Object {$_. installstate -eq "installed"}
```

2. Log into DC, change all domain user passwords
```powershell
// Use script from Lina
```

3. Find and remove all existing user sessions
```powershell
query user /server:$SERVER
```
```powershell
Invoke-Command -ComputerName $Computer -ScriptBlock { logoff $USERID }
```

4. Find and change local account passwords for each computer
```powershell
// Get script from Lina
```

5. Enable Firewall
```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
```

6. Check open ports
```powershell
netstat -anpos tcp
```

7. Create "break glass" account

8. Check Task Scheduler for potentially malicious tasks

9. Check Windows Services for potentially malicious tasks

## First hour
1. Run HitmanPro on each system.
```
https://download.sophos.com/endpoint/clients/HitmanPro_x64.exe
```

2. Enable Firewall Rules (**see Firewall Through GPO**)

3. Harden RDP

## Firewall Through GPO
### Enable Firewall
1. Create new Firewall GPO through GUI, link to domain root
2. Go to **Computer Configuration > Policies > Windows Settings > Security Settings > System Services**. Find **Windows Firewall** in the list of services and change the startup type to **Automatic** (Define this policy setting -> Service startup mode Automatic).
3. Go to **Computer Configuration > Policies > Administrative Templates > Network > Network Connections > Windows Defender > Firewall > Domain Profile** and enable the policy **Windows Defender Firewall: Protect all network connections**.
4. Within the GPO console, navigate to the **Computer Configuration > Windows Settings > Security Settings** section. Right-click **Windows Firewall with Advanced Security** and open the properties. Make sure to enable the **Firewall State** to **On(Recommended)** on each of the profiles you will be using (enabling on all is best practice).

### Configure Firewall Rule
1. In the global firewall GPO, go to **Computer Configuration > Policies > Windows Settings > Security Settings > Windows Firewall with Advanced Security**.
2. Select the rule type. You can allow access to:
    - Program – you can select a program executable (.exe);
    - Port – you can select a TCP/UDP port or a port range;
    - Predefined – select one of the standard Windows rules, which already contain access rules (both executable files and ports are described) to typical services (e. g., AD, HTTP(s), DFS, BranchCache, Remote restart, SNMP, KMS, WinRM, etc.);
    - Custom – here you can specify a program, a protocol (protocols other than TCP or UDP, like ICMP, GRE, L2TP, IGMP, etc.), client IP addresses, or an entire IP network (subnet).

## RDP Hardening
### Force TLS 1.2
1. Go to **Computer Policy > Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Hosts > Security**
2. Edit the **Set client encryption level** and set it to **HIGH**
3. Edit the **Require use of specific security layer for remote (RDP) connections** policy and set it to **SSL**

### Force secure RPC connections
1. Go to **Computer Policy > Computer Configuration > Policies > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security**
2. Edit the **Require secure RPC communication** key and set it to **Enabled**

### Disable Remote Assist
1. Go to **Computer Policy > Computer Configuration > Administrative Templates > System > Remote Assistance​**
2. Set the **Configure Solicited Remote Assistance** key to **Disabled**

### Disable sharing of remote drives over RDP
1. Go to **Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Device and Resource Redirection**
2. Set the **Do not allow Clipboard redirection** key to **Enabled**
3. Set the **Do not allow drive redirection** key to **Enabled**

### Prevent users from using RDP
NOTE -- MAKE SURE THIS ISN'T LINKED TO THE ROOT OU, IT WILL LOCK YOU OUT.  ONLY APPLY THIS TO UNPRIVILIGED USERS
1. Go to **Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Connections**
2. Set the **Disable users from connecting remotely using Remote Desktop Services** key to **Enabled**

## WinRM Hardening
### Disallow unencrypted WinRM traffic
1. Go to **Computer Configuration > Policies > Administrative Templates > Windows Components > Windows Remote Management (WinRM) > WinRM Client**
2. Set the **Allow unencrypted traffic** key to **Disabled**

### Disable WinRM
NOTE - THIS IS A POTENTIALLY DISRUPTIVE POLICY THAT COULD BREAK VARIOUS SERVICES.  ONLY APPLY THIS IF YOU ARE ABSOLUTELY CERTAIN.
1. Go to **"Computer Configuration" > "Policies" > "Administrative Templates" > "Windows Components" > "Windows Remote Management (WinRM)"**
2. Set the **Disallow remote server management through WinRM** key to **Enabled**

## SMB Hardening
Credit to [Ned Pyle at Microsoft](https://techcommunity.microsoft.com/t5/itops-talk-blog/beyond-the-edge-how-to-secure-smb-traffic-in-windows/ba-p/1447159?WT.mc_id=ITOPSTALK-blog-abartolo)

### Disable SMBv1
1. Go to **Computer Configuration > Preferences > Windows Settings > Registry**
2. Create a new Registry Item with the following settings:
```
Action: Update
Hive: HKEY_LOCAL_MACHINE
Key Path: SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
Value name: SMB1
Value type: REG_DWORD
Value data: 0
```

### Disable SMB Guest Fallback Access
1. Go to **Computer Configuration > Administrative Templates > Network > Lanman Workstation**
2. Set the **Enable insecure guest logons** key to **Disabled**

### Enable SMB Signing
1. Go to **Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options**
2. Set the **Microsoft network server: Digitally sign communications (always)** key to **Enabled**
3. Set the **Microsoft network client: Digitally sign communications (always)** key to **Enabled**

### Disable WebDAV Connections
1. Go to **Computer Configuration > Preferences > Control Panel Settings > Services**
2. Create a new Service Item
3. Set the item contents to:
```
Service Name: Webclient
Startup: Disabled
Service action: Stop service
```
## Remove Outdated Features
### Remove Powershellv2
On each machine, run the following command in an Administrative command prompt:
```powershell
dism.exe /Online /Disable-Feature /FeatureName:"MicrosoftWindowsPowerShellv2" /NoRestart
```
```powershell
dism.exe /Online /Disable-Feature /FeatureName:"MicrosoftWindowsPowerShellV2Root" /NoRestart
```

### Remove SMBv1
```powershell
dism.exe /Online /Disable-Feature /FeatureName:"SMB1Protocol" /NoRestart
```

## Remove Local Group Policies
On each machine, run the following command in an Administrative command prompt:
```powershell
RD /S /Q "%WinDir%System32GroupPolicyUsers"
```
```powershell
RD /S /Q "%WinDir%System32GroupPolicy"
```
```powershell
gpupdate /force
```
## Credential Delegation Hardening
There are tradeoffs involved with this.  Prevents the storing of admin hashes on remote machine, but makes RDP connections more vulnerable to Pass The Hash attacks.  Leaving it disabled for now, once storing of NTLM hashes is disabled this shouldn't help that much.

## UAC Hardening
### Prevent apps from bypassing UAC
1. Go to **Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options**
2. Set the **User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop** policy to **Disabled**

### Force the Administrator account to run in Admin Approval mode
1. Go to **Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options**
2. Set the **User Account Control: Admin Approval Mode for the Built-in Administrator account** policy to **Enabled**

### Make UAC prompt Administrators for consent
1. Go to **Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options**
2. Set the **User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode** policy to **Prompt for consent**

### Force UAC for all user accounts
1. Go to **Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options**
2. Set the **User Account Control: Behavior of the elevation prompt for standard users** policy to **Prompt for credentials on the secure desktop**

### Detect app installations and prompt UAC
1. Go to **Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options**
2. Set the **User Account Control: Detect application installations and prompt for elevation** policy to **Elevated**

### Force UAC on all applications, not just signed ones
1. Go to **Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options**
2. Set the **User Account Control: Only elevate executables that are signed and validated** policy to **Disabled**

### Only allow programs installed in secure locations to elevate to administrator
1. Go to **Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options**
2. Set the **User Account Control: Only elevate UIAccess applications that are installed in secure locations** policy to **Enabled**

### Prevent Administrators from bypassing UAC
1. Go to **Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options**
2. Set the **User Account Control: Run all administrators in Admin Approval Mode** policy to **Enabled**

### Force UAC to run in Secure Desktop mode
1. Go to **Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options**
2. Set the **User Account Control: Switch to the secure desktop when prompting for elevation** policy to **Enabled**

### Force UAC failures to run in virtualized user space
1. Go to **Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options**
2. Set the **User Account Control: Virtualize file and registry write failures to per-user locations** policy to **Enabled**

### Applying UAC restrictions to local accounts on network logons
Filtering out the privileged token for local administrator accounts will prevent the elevated privileges of these accounts from being used over the network.
1. Go to **Computer Configuration -> Administrative Templates -> MS Security Guide**
2. Set the **Apply UAC restrictions to local accounts on network logons** policy to **Enabled**

## LSASS Protections
###  Enabling LSA protection mode
1. Go to **Computer Configuration > Preferences > Windows Settings**
2. Right-click **Registry**, point to **New**, and then select **Registry Item**. The **New Registry Properties** dialog box appears.

3. In the Hive list, select HKEY_LOCAL_MACHINE.
4. In the Key Path list, browse to SYSTEM\CurrentControlSet\Control\Lsa.
5. In the Value name box, type RunAsPPL.
6. In the Value type box, select REG_DWORD.
7. In the Value data box, type:
    - 00000001 to enable LSA protection with a UEFI variable.
    - 00000002 to enable LSA protection without a UEFI variable, only enforced on Windows 11 version 22H2 and later.

### Enabling LSASS audit mode
1. Go to **Computer Configuration > Preferences > Windows Settings**
2. Right-click **Registry**, point to **New**, and then select **Registry Item**. The **New Registry Properties** dialog box appears.

3. In the Hive list, select HKEY_LOCAL_MACHINE.
4. In the Key Path list, browse to SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe.
5. In the Value name box, type AuditLevel.
6. In the Value type box, select REG_DWORD.
7. In the Value data box, type 00000008

### Don't allow accounts with blank passwords to access network resources
1. Go to **Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options**
2. Set the **Accounts: Limit local account use of blank passwords to console logon only** policy to **Enabled**

### Prevent anonymous users from enumerating resources
1. Go to **Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options**
2. Set the **Network access: Do not allow anonymous enumeration of SAM accounts and shares** policy to **Enabled**

### Prevent anonymous users from enumerating SAM accounts
1. Go to **Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options**
2. Set the **Network access: Do not allow anonymous enumeration of SAM accounts** policy to **Enabled**

### Stop storing LM hashes on password changes
1. Go to **Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options**
2. Set the **Network security: Do not store LAN Manager hash value on next password change** policy to **Enabled**

### Only allow administrators to schedule AT commands
1. Go to **Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options**
2. Set the **Domain Controller: Allow server operators to schedule tasks** to **Disabled**

### Do not allow network credentials to be stored on the local system
1. Go to **Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options**
2. Set the **Network access: Do not allow storage of passwords and credentials for network authentication** policy to **Enabled**

### Restricting access from anonymous users (treating them seperate from Everyone group)
1. Go to **Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options**
2. Set the **Network access: Let everyone permissions apply to anonymous users** to **Disabled**

### Setting amount of time to clear logged-off users' credentials from memory (secs)
1. Go to **Computer Configuration > Preferences > Windows Settings**
2. Right-click **Registry**, point to **New**, and then select **Registry Item**. The **New Registry Properties** dialog box appears.

3. In the Hive list, select HKEY_LOCAL_MACHINE.
4. In the Key Path list, browse to SYSTEM\CurrentControlSet\Control\Lsa
5. In the Value name box, type TokenLeakDetectDelaySecs.
6. In the Value type box, select REG_DWORD.
7. In the Value data box, type 30

### Restricting remote calls to SAM to just Administrators
1. Go to **Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options**
2. Edit the **Network access: Restrict clients allowed to make remote calls to SAM** policy
3. Select **Edit Security** to configure the **Security descriptor:**.
4. Add **Administrators** in **Group or user names:** if it is not already listed (this is the default).
5. Select **Administrators** in **Group or user names:**.
6. Select **Allow** for **Remote Access** in **Permissions** for **Administrators**.
7. Click **OK**.
8. The **Security descriptor:** must be populated with **O:BAG:BAD:(A;;RC;;;BA)** for the policy to be enforced. 

### Enabling Credential Guard (depends on if the VM can support it)
Note - make sure remote systems support credential guard.  This can be dangerous, be sure before enabling.
1. Go to **Computer Configuration >> Administrative Templates >> System >> Device Guard**
2. Set the **Turn On Virtualization Based Security** policy to **Enabled**
3. Set **Enabled with UEFI lock** to **Credential Guard Configuration**

### Disabling WDigest, removing storing plain text passwords in LSASS
1. Go to **Computer Configuration >> Administrative Templates >> MS Security Guide**
2. Set the **WDigest Authentication (disabling may require KB2871997)** policy to **Disabled**

### Disabling autologon
1. Go to **Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options**
2. Set the **MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)** policy to **Disabled**

### Set number of cached logons to 0
1. Go to **Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options**
2. Set the **Interactive logon: Number of previous logons to cache (in case domain controller is not available)** policy to **0**

