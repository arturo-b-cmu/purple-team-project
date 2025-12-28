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
