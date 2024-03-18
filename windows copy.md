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

## Remove Unnecessary Features
TODO: Remove OpenSSH Client, OpenSSH server, PowershellV2, PowershellV2 root, SMBv1

## Reset Local GPOs
TODO

## Credential Delegation Hardening
### Enabling support for Restricted Admin/Remote Credential Guard
TODO

### Enabling Restricted Admin mode
TODO

### Disabling Restricted Admin Outbound Creds
TODO

### Enabling Credential Delegation (Restrict Credential Delegation)
TODO

## UAC Hardening
### Enabling Restricted Admin mode
TODO

### Applying UAC restrictions to local accounts on network logons
TODO


## LSASS Protections
###  Enabling LSA protection mode
TODO

### Enabling LSASS audit mode
TODO

### Restricting access from anonymous users (treating them seperate from Everyone group)
TODO

### ## Setting amount of time to clear logged-off users' credentials from memory (secs)
TODO

### Restricting remote calls to SAM to just Administrators
TODO

### Enabling Credential Guard (depends on if the VM can support it)
TODO

### Disabling WDigest, removing storing plain text passwords in LSASS
TODO

### Disabling autologon
TODO

### Caching logons
TODO

### Clear cached credentials
TODO


## NTLM Hardening
### Could impact share access (configured to only send NTLMv2, refuse LM & NTLM) - CVE-2019-1040
TODO

### Allowing Local System to use computer identity for NTLM
TODO

### Preventing null session fallback for NTLM
TODO

### Setting NTLM SSP server and client to require NTLMv2 and 128-bit encryption
TODO

## System security
### Disable loading of test signed kernel-drivers
TODO

### Enabling driver signature enforcement
TODO

### Enable DEP for all processes
TODO

### Disabling crash dump generation
TODO

### Enabling automatic reboot after system crash
TODO

### Stopping Windows Installer from always installing w/elevated privileges
TODO

### Requiring a password on wakeup
TODO

## Explorer/file settings
### Changing file associations to make sure they have to be executed manually
TODO

### Disabling 8.3 filename creation
TODO

### Removing "Run As Different User" from context menus
TODO

### Enabling visibility of hidden files, showing file extensions
TODO

### Disabling autorun
TODO

### Enabling DEP and heap termination on corruption for File Explorer
TODO

### Enabling shell protocol protected mode
TODO

### Strengthening default permissions of internal system objects
TODO

## DLL Hardening
### Enabling Safe DLL search mode
TODO

### Blocking DLL loading from remote folders
TODO

### Blocking AppInit_DLLs
TODO

## Misc registry settings 
### Disabling remote access to registry paths
TODO

### Not processing RunOnce List
TODO

## WINDOWS DEFENDER/antimalware settings
### Enabling early launch antimalware boot-start driver scan (good, unknown, and bad but critical)
TODO

### Enabling SEHOP
TODO

### Starting Windows Defender service
TODO

### Enabling Windows Defender sandboxing
TODO

### Enabling a bunch of configuration settings
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "HideExclusionsFromLocalAdmins" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpCloudBlockLevel" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /v "ForceDefenderPassiveMode" /t REG_DWORD /d 0 /f | Out-Null

### Enabling Windows Defender PUP protection
TODO

### Enabling PUA Protection
TODO

### Enabling cloud functionality of Windows Defender
TODO

### Enabling Defender Exploit Guard network protection
TODO

### Removing and updating Windows Defender signatures
TODO

## Enabling ASR rules

    # Block Office applications from injecting code into other processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block Office applications from creating executable content
    Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block all Office applications from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EfC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block JavaScript or VBScript from launching downloaded executable content
    Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block execution of potentially obfuscated scripts
    Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block executable content from email client and webmail
    Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block Win32 API calls from Office macro
    Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block process creations originating from PSExec and WMI commands
    Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block untrusted and unsigned processes that run from USB
    Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Use advanced protection against ransomware
    Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block executable files from running unless they meet a prevalence, age, or trusted list criterion
    Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block credential stealing from the Windows local security authority subsystem (lsass.exe)
    Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block Office communication application from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49E8-8B27-EB1D0A1CE869 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block Adobe Reader from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block persistence through WMI event subscription
    Add-MpPreference -AttackSurfaceReductionRules_Ids E6DB77E5-3DF2-4CF1-B95A-636979351E5B -AttackSurfaceReductionRules_Actions Enabled | Out-Null

### Removing ASR exceptions
TODO

### Removing exclusions in Defender
TODO

### Attempt to enable tamper protection key
TODO

## Service Security
### Stopping psexec with the power of svchost
TODO

### Disabling offline files
TODO

### Disabling UPnP
TODO

### Disabling DCOM cuz why not
TODO

### Disabel Print Spooler
TODO

## Secure channel settings
### Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
TODO

### Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
TODO

### Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
TODO

## Disabling weak encryption protocols
### Encryption - Ciphers: AES only - IISCrypto (recommended options)
TODO

### Encryption - Hashes: All allowed - IISCrypto (recommended options)
TODO

### Encryption - Key Exchanges: All allowed
TODO

### Encryption - Protocols: TLS 1.0 and higher - IISCrypto (recommended options)
TODO

### Encryption - Cipher Suites (order) - All cipher included to avoid application problems
TODO

## SMB protections
### Disable SMB compression (CVE-2020-0796 - SMBGhost)
TODO

### Disabling SMB1 server-side processing (Win 7 and below)
TODO

### Disabling SMB1 client driver
TODO

### Disabling client-side processing of SMBv1 protocol (pre-Win8.1/2012R2)
TODO

### Enabling SMB2/3 and encryption (modern Windows)
TODO

### Enabling SMB2/3 (Win 7 and below)
TODO

### Disabling sending of unencrypted passwords to third-party SMB servers
TODO

### Disallowing guest logon
TODO

### Enable SMB signing
TODO

### Restricting access to null session pipes and shares
TODO

### Disabling SMB admin shares (Server)
TODO

### Disabling SMB admin shares (Workstation)
TODO

### Hide computer from browse list
TODO

### Microsoft-Windows-SMBServer\Audit event 3000 shows attempted connections 
TODO

## RPC settings
### Disabling RPC usage from a remote asset interacting with scheduled tasks
TODO

### Disabling RPC usage from a remote asset interacting with services
TODO

### Restricting unauthenticated RPC clients
TODO

## Printer NIGHTMARE NIGHTMARE NIGHTMARE
### Disabling downloading of print drivers over HTTP
TODO

### Disabling printing over HTTP
TODO

### Preventing regular users from installing printer drivers
TODO

## Limiting BITS transfer
TODO

## Prevent insecure encryption suites for Kerberos
TODO

## Networking Settings
### Disabling LLMNR
TODO

### Disabling smart multi-homed name resolution
TODO

### Disabling NBT-NS via registry for all interfaces (might break something)
TODO

### Disabling NetBIOS broadcast-based name resolution
TODO

### Enabling ability to ignore NetBIOS name release requests except from WINS servers
TODO

### Disabling mDNS
TODO

### Flushing DNS cache
TODO

### Disabling source routing for IPv4 and IPv6
TODO

### Disable password saving for dial-up (lol)
TODO

### Disable automatic detection of dead network gateways
TODO

### Enable ICMP redirect using OSPF
TODO

### Setting how often keep-alive packets are sent (ms)
TODO

### Disabling IRDP
TODO

### Disabling IGMP
TODO

### Setting SYN attack protection level
TODO

### Setting SYN-ACK retransmissions when a connection request is not acknowledged
TODO

### Setting how many times unacknowledged data is retransmitted for IPv4 and IPv6
TODO

### Configuring IPSec exemptions (Only ISAKMP is exempt)
TODO

## Set AD Audit Rules
TODO

## DC Security
### CVE-2020-1472 - ZeroLogon
TODO

### CVE-2021-42287/CVE-2021-42278 (SamAccountName / nopac)
TODO

### Enforcing LDAP server signing (always)
TODO

### Enabling extended protection for LDAP authentication (always)
TODO

### Only allowing DSRM Administrator account to be used when ADDS is stopped
TODO

### Disable unauthenticated LDAP
TODO

### Setting max connection time
TODO

### Setting dsHeuristics (disable anon LDAP)
TODO

### Resetting NTDS folder and file permissions
TODO

### Set RID Manager Auditing
TODO

### T1003.001 - delete vss shadow copies (removing copies of NTDS database)
TODO


