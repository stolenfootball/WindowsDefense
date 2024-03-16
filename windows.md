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

