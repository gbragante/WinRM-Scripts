$version = "WinRm-Collect (20180109)"
# by Gianni Bragante - gbrag@microsoft.com

Function Write-Log {
  param( [string] $msg )
  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
  Write-Host $msg
  $msg | Out-File -FilePath $outfile -Append
}

Function ExecQuery {
  param(
    [string] $NameSpace,
    [string] $Query
  )
  Write-Log ("Executing query " + $Query)
  if ($PSVersionTable.psversion.ToString() -ge "3.0") {
    $ret = Get-CimInstance -Namespace $NameSpace -Query $Query -ErrorAction Continue 2>>$errfile
  } else {
    $ret = Get-WmiObject -Namespace $NameSpace -Query $Query -ErrorAction Continue 2>>$errfile
  }
  Write-Log (($ret | measure).count.ToString() + " results")
  return $ret
}

$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
  Write-Output "This script needs to be run as Administrator"
  exit
}

$Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path

$resName = "WinRM-Results-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)
$resDir = $Root + "\" + $resName
$outfile = $resDir + "\script-output.txt"
$errfile = $resDir + "\script-errors.txt"
$RdrOut =  " >>""" + $outfile + """"
$RdrErr =  " 2>>""" + $errfile + """"

New-Item -itemtype directory -path $resDir | Out-Null

Write-Log $version
Write-Log "Retrieving WinRM configuration"
$config = Get-ChildItem WSMan:\localhost\ -Recurse -ErrorAction Continue 2>>$errfile
if (!$config) {
  $fqdn = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
  Write-Log ("Cannot connect to localhost, trying with FQDN " + $fqdn)
  Connect-WSMan -ComputerName $fqdn -ErrorAction Continue 2>>$errfile
  $config = Get-ChildItem WSMan:\$fqdn -Recurse -ErrorAction Continue 2>>$errfile
  Disconnect-WSMan -ComputerName $fqdn -ErrorAction Continue 2>>$errfile
}

$config | out-string -Width 500 | out-file -FilePath ($resDir + "\WinRM-config.txt")

if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
  $procdump = "procdump64.exe"
} else {
  $procdump = "procdump.exe"
}
if (-not (Test-Path ($root + "\" + $procdump))) {
  $confirm = Read-Host ("The file " + $root + "\" + $procdump + " does not exist, the process dumps cannot be collected.`r`nDo you want to continue ? [Y / N]")
  if ($confirm.ToLower() -ne "y") {exit}
}

Write-Log "Collecting dump of the svchost process hosting the WinRM service"
$cmd = "&""" + $Root + "\" +$procdump + """ -accepteula -ma WinRM """ + $resDir + "\Svchost.exe-WinRM.dmp""" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Collecing the dumps of wsmprovhost.exe processes"
$list = get-process -Name "wsmprovhost" -ErrorAction Continue 2>>$errfile
if (($list | measure).count -gt 0) {
  foreach ($proc in $list)
  {
    Write-Log ("Found wsmprovhost.exe with PID " + $proc.Id)
    $cmd = "&""" + $Root + "\" +$procdump + """ -accepteula -ma " + $proc.Id + " """+ $resDir + "\wsmprovhost.exe_"+ $proc.id + ".dmp"" >>""" + $outfile + """ 2>>""" + $errfile + """"
    Write-Log $cmd
    Invoke-Expression $cmd
  }
} else {
  Write-Log "No wsmprovhost.exe processes found"
}

Write-Log "Retrieving subscriptions configuration"
$cmd = "wecutil es 2>>""" + $errfile + """"
Write-log $cmd
$subList = Invoke-Expression $cmd

if ($subList -gt "") {
  foreach($sub in $subList) {
    Write-Log "Subsription: " + $sub
    ("Subsription: " + $sub) | out-file -FilePath ($resDir + "\Subscriptions.txt") -Append
    "-----------------------" | out-file -FilePath ($resDir + "\Subscriptions.txt") -Append
    $cmd = "wecutil gs """ + $sub + """ /f:xml" + $RdrErr
    Write-Log $cmd
    Invoke-Expression ($cmd) | out-file -FilePath ($resDir + "\Subscriptions.txt") -Append

    $cmd = "wecutil gr """ + $sub + """" + $RdrErr
    Write-Log $cmd
    Invoke-Expression ($cmd) | out-file -FilePath ($resDir + "\Subscriptions.txt") -Append

    " " | out-file -FilePath ($resDir + "\Subscriptions.txt") -Append
  }
}

Write-Log "Listing members of Event Log Readers group"
$cmd = "net localgroup ""Event Log Readers"" >>""" + $resDir + "\Groups.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Listing members of WinRMRemoteWMIUsers__ group"
$cmd = "net localgroup ""WinRMRemoteWMIUsers__"" >>""" + $resDir + "\Groups.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Finding SID of WinRMRemoteWMIUsers__ group"
$objUser = New-Object System.Security.Principal.NTAccount("WinRMRemoteWMIUsers__") -ErrorAction Continue 2>>$errfile
$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]).value

$objSID = New-Object System.Security.Principal.SecurityIdentifier($strSID)
$group = $objSID.Translate( [System.Security.Principal.NTAccount]).Value

(" ") | Out-File -FilePath ($resDir + "\Groups.txt") -Append
($group + " = " + $strSID) | Out-File -FilePath ($resDir + "\Groups.txt") -Append

Write-Log "Get-NetConnectionProfile output"
Get-NetConnectionProfile | Out-File -FilePath ($resDir + "\NetConnectionProfile.txt") -Append

Write-Log "Exporting firewall rules"
$cmd = "netsh advfirewall firewall show rule name=all >""" + $resDir + "\FirewallRules.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Exporting netstat output"
$cmd = "netstat -anob >""" + $resDir + "\netstat.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Exporting ipconfig /all output"
$cmd = "ipconfig /all >""" + $resDir + "\ipconfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Copying hosts and lmhosts"
Copy-Item C:\Windows\system32\drivers\etc\hosts $resDir\hosts.txt -ErrorAction Continue 2>>$errfile
Copy-Item C:\Windows\system32\drivers\etc\lmhosts $resDir\lmhosts.txt -ErrorAction Continue 2>>$errfile

$dir = $env:windir + "\system32\logfiles\HTTPERR"
$last = Get-ChildItem -path ($dir) | Sort CreationTime -Descending | Select Name -First 1 
Copy-Item ($dir + "\" + $last.name) $resDir\httperr.log -ErrorAction Continue 2>>$errfile

Write-Log "WinHTTP proxy configuration"
$cmd = "netsh winhttp show proxy >""" + $resDir + "\WinHTTP-Proxy.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Collecing GPResult output"
$cmd = "gpresult /h """ + $resDir + "\gpresult.html""" + $RdrErr
write-log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

$cmd = "gpresult /r >""" + $resDir + "\gpresult.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM"
$cmd = "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM """ + $resDir + "\WinRM.reg.txt"" /y " + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN """+ $resDir + "\WSMAN.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM"
$cmd = "reg export HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM """+ $resDir + "\WinRM-Pol.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd


Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector """+ $resDir + "\EventCollector.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EventForwarding"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EventForwarding """+ $resDir + "\EventForwarding.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
$cmd = "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL """+ $resDir + "\SCHANNEL.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography"
$cmd = "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography """+ $resDir + "\Cryptography.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography """+ $resDir + "\Cryptography-Policy.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
$cmd = "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa """+ $resDir + "\LSA.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\HTTP"
$cmd = "reg export HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\HTTP """+ $resDir + "\HTTP.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting CAPI2 log"
$cmd = "wevtutil epl Microsoft-Windows-CAPI2/Operational """+ $resDir + "\" + $env:computername + "-capi2.evtx""" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting Windows Remote Management log"
$cmd = "wevtutil epl Microsoft-Windows-WinRM/Operational """+ $resDir + "\" + $env:computername + "-WindowsRemoteManagement.evtx""" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting EventCollector log"
$cmd = "wevtutil epl Microsoft-Windows-EventCollector/Operational """+ $resDir + "\" + $env:computername + "-EventCollector.evtx""" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting Event-ForwardingPlugin log"
$cmd = "wevtutil epl Microsoft-Windows-Forwarding/Operational """+ $resDir + "\" + $env:computername + "-Event-ForwardingPlugin.evtx""" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting PowerShell log"
$cmd = "wevtutil epl Microsoft-Windows-PowerShell/Operational """+ $resDir + "\" + $env:computername + "-PowerShell.evtx""" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting Application log"
$cmd = "wevtutil epl Application """+ $resDir + "\" + $env:computername + "-Application.evtx""" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting System log"
$cmd = "wevtutil epl System """+ $resDir + "\" + $env:computername + "-System.evtx""" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting netsh http settings"
$cmd = "netsh http show sslcert >>""" + $resDir + "\netsh-http.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

$cmd = "netsh http show urlacl >>""" + $resDir + "\netsh-http.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

$cmd = "netsh http show servicestate >>""" + $resDir + "\netsh-http.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

$cmd = "setspn -L " + $env:computername + " >>""" + $resDir + "\SPN.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
" " | Out-File ($resDir + "\SPN.txt") -Append

"Searching HTTP/" + $env:computername + " in the domain" | Out-File ($resDir + "\SPN.txt") -Append
$cmd = "setspn -Q HTTP/" + $env:computername + " >>""" + $resDir + "\SPN.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
" " | Out-File ($resDir + "\SPN.txt") -Append

"Searching HTTP/" + $env:computername + " in the forest" | Out-File ($resDir + "\SPN.txt") -Append
$cmd = "setspn -F -Q HTTP/" + $env:computername + " >>""" + $resDir + "\SPN.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
" " | Out-File ($resDir + "\SPN.txt") -Append

"Searching WSMAN/" + $env:computername + " in the domain" | Out-File ($resDir + "\SPN.txt") -Append
$cmd = "setspn -Q WSMAN/" + $env:computername + " >>""" + $resDir + "\SPN.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
" " | Out-File ($resDir + "\SPN.txt") -Append

"Searching WSMAN/" + $env:computername + " in the forest" | Out-File ($resDir + "\SPN.txt") -Append
$cmd = "setspn -F -Q WSMAN/" + $env:computername + " >>""" + $resDir + "\SPN.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
" " | Out-File ($resDir + "\SPN.txt") -Append

Write-Log "Collecting certificates details"
$cmd = "Certutil -verifystore -v MY > """ + $resDir + "\Certificates-My.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

$cmd = "Certutil -verifystore -v ROOT > """ + $resDir + "\Certificates-Root.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

$cmd = "Certutil -verifystore -v CA > """ + $resDir + "\Certificates-Intermediate.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "PowerShell version"
$PSVersionTable | Out-File -FilePath ($resDir + "\PSVersion.txt") -Append

Write-Log "Copying ServerManager configuration"
copy-item $env:APPDATA\Microsoft\Windows\ServerManager\ServerList.xml $resDir\ServerList.xml -ErrorAction Continue 2>>$errfile

Write-Log "Collecting the list of installed hotfixes"
Get-HotFix -ErrorAction SilentlyContinue 2>>$errfile | Sort-Object -Property InstalledOn | Out-File $resDir\hotfixes.txt

Write-Log "Collecting details about running processes"
$proc = ExecQuery -Namespace "root\cimv2" -Query "select CreationDate, ProcessId, ParentProcessId, WorkingSetSize, UserModeTime, KernelModeTime, ThreadCount, HandleCount, CommandLine from Win32_Process"
if ($PSVersionTable.psversion.ToString() -ge "3.0") {
  $StartTime= @{e={$_.CreationDate.ToString("yyyyMMdd HH:mm:ss")};n="Start time"}
} else {
  $StartTime= @{n='StartTime';e={$_.ConvertToDateTime($_.CreationDate)}}
}

if ($proc) {
  $proc | Sort-Object Name |
  Format-Table -AutoSize -property @{e={$_.ProcessId};Label="PID"}, @{e={$_.ParentProcessId};n="Parent"}, Name,
  @{N="WorkingSet";E={"{0:N0}" -f ($_.WorkingSetSize/1kb)};a="right"},
  @{e={[DateTime]::FromFileTimeUtc($_.UserModeTime).ToString("HH:mm:ss")};n="UserTime"}, @{e={[DateTime]::FromFileTimeUtc($_.KernelModeTime).ToString("HH:mm:ss")};n="KernelTime"},
  @{N="Threads";E={$_.ThreadCount}}, @{N="Handles";E={($_.HandleCount)}}, $StartTime, CommandLine |
  Out-String -Width 500 | Out-File -FilePath ($resDir + "\processes.txt")

  Write-Log "Collecting services details"
  $svc = ExecQuery -NameSpace "root\cimv2" -Query "select  ProcessId, DisplayName, StartMode,State, Name, PathName, StartName from Win32_Service"

  if ($svc) {
    $svc | Sort-Object DisplayName | Format-Table -AutoSize -Property ProcessId, DisplayName, StartMode,State, Name, PathName, StartName |
    Out-String -Width 400 | Out-File -FilePath ($resDir + "\services.txt")
  }

  Write-Log "Collecting system information"
  $pad = 27
  $OS = ExecQuery -Namespace "root\cimv2" -Query "select Caption, CSName, OSArchitecture, BuildNumber, InstallDate, LastBootUpTime, LocalDateTime, TotalVisibleMemorySize, FreePhysicalMemory, SizeStoredInPagingFiles, FreeSpaceInPagingFiles from Win32_OperatingSystem"
  $CS = ExecQuery -Namespace "root\cimv2" -Query "select Model, Manufacturer, SystemType, NumberOfProcessors, NumberOfLogicalProcessors, TotalPhysicalMemory, DNSHostName, Domain, DomainRole from Win32_ComputerSystem"
  $BIOS = ExecQuery -Namespace "root\cimv2" -query "select BIOSVersion, Manufacturer, ReleaseDate, SMBIOSBIOSVersion from Win32_BIOS"
  $TZ = ExecQuery -Namespace "root\cimv2" -Query "select Description from Win32_TimeZone"
  $PR = ExecQuery -Namespace "root\cimv2" -Query "select Name, Caption from Win32_Processor"

  "Computer name".PadRight($pad) + " : " + $OS.CSName | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Model".PadRight($pad) + " : " + $CS.Model | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Manufacturer".PadRight($pad) + " : " + $CS.Manufacturer | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "BIOS Version".PadRight($pad) + " : " + $BIOS.BIOSVersion | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "BIOS Manufacturer".PadRight($pad) + " : " + $BIOS.Manufacturer | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "BIOS Release date".PadRight($pad) + " : " + $BIOS.ReleaseDate | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "SMBIOS Version".PadRight($pad) + " : " + $BIOS.SMBIOSBIOSVersion | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "SystemType".PadRight($pad) + " : " + $CS.SystemType | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Processor".PadRight($pad) + " : " + $PR.Name + " / " + $PR.Caption | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Processors physical/logical".PadRight($pad) + " : " + $CS.NumberOfProcessors + " / " + $CS.NumberOfLogicalProcessors | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Memory physical/visible".PadRight($pad) + " : " + ("{0:N0}" -f ($CS.TotalPhysicalMemory/1mb)) + " MB / " + ("{0:N0}" -f ($OS.TotalVisibleMemorySize/1kb)) + " MB" | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Free physical memory".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.FreePhysicalMemory/1kb)) + " MB" | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Paging files size / free".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.SizeStoredInPagingFiles/1kb)) + " MB / " + ("{0:N0}" -f ($OS.FreeSpaceInPagingFiles/1kb)) + " MB" | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Operating System".PadRight($pad) + " : " + $OS.Caption + " " + $OS.OSArchitecture | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Build Number".PadRight($pad) + " : " + $OS.BuildNumber | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Time zone".PadRight($pad) + " : " + $TZ.Description | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Install date".PadRight($pad) + " : " + $OS.InstallDate | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Last boot time".PadRight($pad) + " : " + $OS.LastBootUpTime | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Local time".PadRight($pad) + " : " + $OS.LocalDateTime | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "DNS Hostname".PadRight($pad) + " : " + $CS.DNSHostName | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Domain".PadRight($pad) + " : " + $CS.Domain | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  $roles = "Standalone Workstation", "Member Workstation", "Standalone Server", "Member Server", "Backup Domain Controller", "Primary Domain Controller"
  "Domain role".PadRight($pad) + " : " + $roles[$CS.DomainRole] | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
} else {
  $proc = Get-Process | Where-Object {$_.Name -ne "Idle"}
  $proc | Format-Table -AutoSize -property id, name, @{N="WorkingSet";E={"{0:N0}" -f ($_.workingset/1kb)};a="right"},
  @{N="VM Size";E={"{0:N0}" -f ($_.VirtualMemorySize/1kb)};a="right"},
  @{N="Proc time";E={($_.TotalProcessorTime.ToString().substring(0,8))}}, @{N="Threads";E={$_.threads.count}},
  @{N="Handles";E={($_.HandleCount)}}, StartTime, Path | 
  Out-String -Width 300 | Out-File -FilePath ($resDir + "\processes.txt")
}