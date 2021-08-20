param( [string]$Path, [switch]$AcceptEula )

$version = "WinRM-Collect (20210820)"
$DiagVersion = "WinRM-Diag (20210820)"

# by Gianni Bragante - gbrag@microsoft.com

Function Write-Diag {
  param( [string] $msg )
  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
  Write-Host $msg
  $msg | Out-File -FilePath $diagfile -Append
}

Function EvtLogDetails {
  param(
    [string] $LogName
  )
  Write-Log ("Collecting the details for the " + $LogName + " log")
  $cmd = "wevtutil gl " + $logname + " >>""" + $resDir + "\EventLogs.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

  Write-Log ("Collecting the details for the " + $LogName + " log")
  $cmd = "wevtutil gli " + $logname + " >>""" + $resDir + "\EventLogs.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

  "" | Out-File -FilePath ($resDir + "\EventLogs.txt") -Append

  if ($logname -ne "ForwardedEvents") {
    $evt = (Get-WinEvent -Logname $LogName -MaxEvents 1 -Oldest)
    "Oldest " + $evt.TimeCreated + " (" + $evt.RecordID + ")" | Out-File -FilePath ($resDir + "\EventLogs.txt") -Append
    $evt = (Get-WinEvent -Logname $LogName -MaxEvents 1)
    "Newest " + $evt.TimeCreated + " (" + $evt.RecordID + ")" | Out-File -FilePath ($resDir + "\EventLogs.txt") -Append
    "" | Out-File -FilePath ($resDir + "\EventLogs.txt") -Append
  }
}

Function GetStore($store) {
  $certlist = Get-ChildItem ("Cert:\LocalMachine\" + $store)

  foreach ($cert in $certlist) {
    $EKU = ""
    foreach ($item in $cert.EnhancedKeyUsageList) {
      if ($item.FriendlyName) {
        $EKU += $item.FriendlyName + " / "
      } else {
        $EKU += $item.ObjectId + " / "
      }
    }

    $row = $tbcert.NewRow()

    foreach ($ext in $cert.Extensions) {
      if ($ext.oid.value -eq "2.5.29.14") {
        $row.SubjectKeyIdentifier = $ext.SubjectKeyIdentifier.ToLower()
      } elseif (($ext.oid.value -eq "2.5.29.35") -or ($ext.oid.value -eq "2.5.29.1")) { 
        $asn = New-Object Security.Cryptography.AsnEncodedData ($ext.oid,$ext.RawData)
        $aki = $asn.Format($true).ToString().Replace(" ","")
        $aki = (($aki -split '\n')[0]).Replace("KeyID=","").Trim()
        $row.AuthorityKeyIdentifier = $aki
      } elseif (($ext.oid.value -eq "1.3.6.1.4.1.311.21.7") -or ($ext.oid.value -eq "1.3.6.1.4.1.311.20.2")) { 
        $asn = New-Object Security.Cryptography.AsnEncodedData ($ext.oid,$ext.RawData)
        $tmpl = $asn.Format($true).ToString().Replace(" ","")
        $template = (($tmpl -split '\n')[0]).Replace("Template=","").Trim()
        $row.Template = $template
      }
    }
    if ($EKU) {$EKU = $eku.Substring(0, $eku.Length-3)} 
    $row.Store = $store
    $row.Thumbprint = $cert.Thumbprint.ToLower()
    $row.Subject = $cert.Subject
    $row.Issuer = $cert.Issuer
    $row.NotAfter = $cert.NotAfter
    $row.EnhancedKeyUsage = $EKU
    $row.SerialNumber = $cert.SerialNumber.ToLower()
    $tbcert.Rows.Add($row)
  } 
}

Function ChkCert($cert, $store, $descr) {
  $cert = $cert.ToLower()
  if ($cert) {
    if ("0123456789abcdef".Contains($cert[0])) {
      $aCert = $tbCert.Select("Thumbprint = '" + $cert + "' and $store")
      if ($aCert.Count -gt 0) {
        Write-Diag ("[INFO] The $descr certificate was found, the subject is " + $aCert[0].Subject)
        if (($aCert[0].NotAfter) -gt (Get-Date)) {
          Write-Diag ("[INFO] The $descr certificate will expire on " + $aCert[0].NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") )
        } else {
          Write-Diag ("[ERROR] The $descr certificate expired on " + $aCert[0].NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") )
        }
      }  else {
        Write-Diag "[ERROR] The certificate with thumbprint $cert was not found in $store"
      }
    } else {
      Write-Diag "[ERROR] Invalid character in the $cert certificate thumbprint $cert"
    }
  } else {
    Write-Diag "[ERROR] The thumbprint of $descr certificate is empty"
  }
}

Function GetSubVal {
  param( [string]$SubName, [string]$SubValue)
  $SubProp = (Get-Item -Path ("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions\" + $SubName) | Get-ItemProperty)
  if ($SubProp.($SubValue)) {
    return $SubProp.($SubValue)
  } else {
    $cm = $SubProp.ConfigurationMode
    $subVal = (Get-Item -Path ("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\ConfigurationModes\" + $cm) | Get-ItemProperty)
    return $SubVal.($SubValue)
  }
}

Function GetOwnerCim{
  param( $prc )
  $ret = Invoke-CimMethod -InputObject $prc -MethodName GetOwner
  return ($ret.Domain + "\" + $ret.User)
}

Function GetOwnerWmi{
  param( $prc )
  $ret = $prc.GetOwner()
  return ($ret.Domain + "\" + $ret.User)
}

$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
  Write-Output "This script needs to be run as Administrator"
  exit
}

$global:Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path

$resName = "WinRM-Results-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)
$global:resDir = $global:Root + "\" + $resName
$diagfile = $global:resDir + "\WinRM-Diag.txt"

$global:outfile = $global:resDir + "\script-output.txt"
$global:errfile = $global:resDir + "\script-errors.txt"

Import-Module ($global:Root + "\Collect-Commons.psm1") -Force -DisableNameChecking

$RdrOut =  " >>""" + $global:outfile + """"
$RdrErr =  " 2>>""" + $global:errfile + """"
$fqdn = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName

$OSVer = ([environment]::OSVersion.Version.Major) + ([environment]::OSVersion.Version.Minor) /10

New-Item -itemtype directory -path $global:resDir | Out-Null

Write-Log $version
if ($AcceptEula) {
  Write-Log "AcceptEula switch specified, silently continuing"
  $eulaAccepted = ShowEULAIfNeeded "WinRM-Collect" 2
} else {
  $eulaAccepted = ShowEULAIfNeeded "WinRM-Collect" 0
  if($eulaAccepted -ne "Yes")
   {
     Write-Log "EULA declined, exiting"
     exit
   }
 }
Write-Log "EULA accepted, continuing"

"Logman create counter FwdEvtPerf -o """ + $global:resDir + "\FwdEvtPerf.blg"" -f bin -v mmddhhmm -c ""\Process(*)\*"" ""\Processor(*)\*"" ""\PhysicalDisk(*)\*"" ""\Event Tracing for Windows Session(EventLog-*)\Events Lost"" ""\Event Tracing for Windows Session(EventLog-*)\Events Logged per sec"" ""\HTTP Service Request Queues(*)\*"" -si 00:00:01" | Out-File -FilePath ($global:resDir + "\WEF-Perf.bat") -Append -Encoding ascii
"Logman start FwdEvtPerf" | Out-File -FilePath ($global:resDir + "\WEF-Perf.bat") -Append -Encoding ascii
"timeout 60" | Out-File -FilePath ($global:resDir + "\WEF-Perf.bat") -Append -Encoding ascii
"Logman stop FwdEvtPerf" | Out-File -FilePath ($global:resDir + "\WEF-Perf.bat") -Append -Encoding ascii
"Logman delete FwdEvtPerf" | Out-File -FilePath ($global:resDir + "\WEF-Perf.bat") -Append -Encoding ascii

$cmd = $global:resDir + "\WEF-Perf.bat"
Write-Log $cmd
Start-Process $cmd -WindowStyle Minimized

Write-Log "Retrieving WinRM configuration"
$config = Get-ChildItem WSMan:\localhost\ -Recurse -ErrorAction Continue 2>>$global:errfile
if (!$config) {
  Write-Log ("Cannot connect to localhost, trying with FQDN " + $fqdn)
  Connect-WSMan -ComputerName $fqdn -ErrorAction Continue 2>>$global:errfile
  $config = Get-ChildItem WSMan:\$fqdn -Recurse -ErrorAction Continue 2>>$global:errfile
  Disconnect-WSMan -ComputerName $fqdn -ErrorAction Continue 2>>$global:errfile
}

$config | out-string -Width 500 | out-file -FilePath ($global:resDir + "\WinRM-config.txt")

Write-Log "winrm get winrm/config"
$cmd = "winrm get winrm/config >>""" + $global:resDir + "\WinRM-config.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "winrm e winrm/config/listener"
$cmd = "winrm e winrm/config/listener >>""" + $global:resDir + "\WinRM-config.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "winrm enum winrm/config/service/certmapping"
$cmd = "winrm enum winrm/config/service/certmapping >>""" + $global:resDir + "\WinRM-config.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Collecting dump of the svchost process hosting the WinRM service"
$pidWinRM = FindServicePid "WinRM"
if ($pidWinRM) {
  CreateProcDump $pidWinRM $global:resDir "scvhost-WinRM"
}

Write-Log "Collecing the dumps of wsmprovhost.exe processes"
$list = get-process -Name "wsmprovhost" -ErrorAction SilentlyContinue 2>>$global:errfile
if (($list | measure).count -gt 0) {
  foreach ($proc in $list)
  {
    Write-Log ("Found wsmprovhost.exe with PID " + $proc.Id)
    CreateProcDump $proc.id $global:resDir
  }
} else {
  Write-Log "No wsmprovhost.exe processes found"
}

if ($pidWinRM) {
  Write-Log ("The PID of the WinRM service is: " + $pidWinRM)
  $pidWEC = FindServicePid "WecSvc"
  if ($pidWEC) {
    Write-Log ("The PID of the WecSvc service is: " + $pidWEC)
    if ($pidWinRM -ne $pidWEC) {
      Write-Log "WinRM and WecSvc are not in the same process"
      CreateProcDump $pidWEC $global:resDir "scvhost-WEC"
    }
  }
}

Write-Log "Collecting dump of the SME.exe process"
$proc = get-process "SME" -ErrorAction SilentlyContinue
if ($proc) {
  Write-Log "Process SME.EXE found with PID $proc.id"
  CreateProcDump $proc.id $global:resDir
}

FileVersion -Filepath ($env:windir + "\system32\wsmsvc.dll") -Log $true

if (Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions) {
  Write-Log "Retrieving subscriptions configuration"
  $cmd = "wecutil es 2>>""" + $global:errfile + """"
  Write-log $cmd
  $subList = Invoke-Expression $cmd

  if ($subList -gt "") {
    foreach($sub in $subList) {
      Write-Log "Subscription: " + $sub
      ("Subscription: " + $sub) | out-file -FilePath ($global:resDir + "\Subscriptions.txt") -Append
      "-----------------------" | out-file -FilePath ($global:resDir + "\Subscriptions.txt") -Append
      $cmd = "wecutil gs """ + $sub + """ /f:xml" + $RdrErr
      Write-Log $cmd
      Invoke-Expression ($cmd) | out-file -FilePath ($global:resDir + "\Subscriptions.txt") -Append

      $cmd = "wecutil gr """ + $sub + """" + $RdrErr
      Write-Log $cmd
      Invoke-Expression ($cmd) | out-file -FilePath ($global:resDir + "\Subscriptions.txt") -Append

      " " | out-file -FilePath ($global:resDir + "\Subscriptions.txt") -Append
    }
  }
}

Write-Log "Listing members of Event Log Readers group"
$cmd = "net localgroup ""Event Log Readers"" >>""" + $global:resDir + "\Groups.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Listing members of WinRMRemoteWMIUsers__ group"
$cmd = "net localgroup ""WinRMRemoteWMIUsers__"" >>""" + $global:resDir + "\Groups.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

# We don't need this part because it is already covered by the WinRM-Diag output
#Write-Log "Finding SID of WinRMRemoteWMIUsers__ group"
#$objUser = New-Object System.Security.Principal.NTAccount("WinRMRemoteWMIUsers__") -ErrorAction SilentlyContinue 2>>$global:errfile
#$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]).value
#$objSID = New-Object System.Security.Principal.SecurityIdentifier($strSID)
#$group = $objSID.Translate( [System.Security.Principal.NTAccount]).Value

(" ") | Out-File -FilePath ($global:resDir + "\Groups.txt") -Append
($group + " = " + $strSID) | Out-File -FilePath ($global:resDir + "\Groups.txt") -Append

Write-Log "Get-Culture output"
"Get-Culture" | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append
Get-Culture | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append

Write-Log "Exporting registry key HKEY_USERS\S-1-5-20\Control Panel\International"
$cmd = "reg export ""HKEY_USERS\S-1-5-20\Control Panel\International"" """ + $global:resDir + "\InternationalNetworkService.reg.txt"" /y " + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Get-WinSystemLocale output"
"Get-WinSystemLocale" | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append
Get-WinSystemLocale | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append

Write-Log "Get-WinHomeLocation output"
"Get-WinHomeLocation" | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append
Get-WinHomeLocation | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append

Write-Log "Get-WinUILanguageOverride output"
"Get-WinUILanguageOverride" | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append
Get-WinUILanguageOverride | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append

Write-Log "Get-WinUserLanguageList output"
"Get-WinUserLanguageList" | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append
Get-WinUserLanguageList | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append

Write-Log "Get-WinAcceptLanguageFromLanguageListOptOut output"
"Get-WinAcceptLanguageFromLanguageListOptOut" | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append
Get-WinAcceptLanguageFromLanguageListOptOut | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append

Write-Log "Get-WinCultureFromLanguageListOptOut output"
"Get-Get-WinCultureFromLanguageListOptOut" | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append
Get-WinCultureFromLanguageListOptOut | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append

Write-Log "Get-WinDefaultInputMethodOverride output"
"Get-WinDefaultInputMethodOverride" | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append
Get-WinDefaultInputMethodOverride | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append

Write-Log "Get-WinLanguageBarOption output"
"Get-WinLanguageBarOption" | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append
Get-WinLanguageBarOption | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append

Write-Log "Get-NetConnectionProfile output"
Get-NetConnectionProfile | Out-File -FilePath ($global:resDir + "\NetConnectionProfile.txt") -Append

Write-Log "Get-WSManCredSSP output"
Get-WSManCredSSP | Out-File -FilePath ($global:resDir + "\WSManCredSSP.txt") -Append

Write-Log "Exporting firewall rules"
$cmd = "netsh advfirewall firewall show rule name=all >""" + $global:resDir + "\FirewallRules.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Exporting netstat output"
$cmd = "netstat -anob >""" + $global:resDir + "\netstat.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Exporting ipconfig /all output"
$cmd = "ipconfig /all >""" + $global:resDir + "\ipconfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Copying hosts and lmhosts"
if (Test-path -path C:\Windows\system32\drivers\etc\hosts) {
  Copy-Item C:\Windows\system32\drivers\etc\hosts $global:resDir\hosts.txt -ErrorAction Continue 2>>$global:errfile
}
if (Test-Path -Path C:\Windows\system32\drivers\etc\lmhosts) {
  Copy-Item C:\Windows\system32\drivers\etc\lmhosts $global:resDir\lmhosts.txt -ErrorAction Continue 2>>$global:errfile
}

$dir = $env:windir + "\system32\logfiles\HTTPERR"
if (Test-Path -path $dir) {
  $last = Get-ChildItem -path ($dir) | Sort CreationTime -Descending | Select Name -First 1 
  Copy-Item ($dir + "\" + $last.name) $global:resDir\httperr.log -ErrorAction Continue 2>>$global:errfile
}

Write-Log "WinHTTP proxy configuration"
$cmd = "netsh winhttp show proxy >""" + $global:resDir + "\WinHTTP-Proxy.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "NSLookup WPAD"
"------------------" | Out-File -FilePath ($global:resDir + "\WinHTTP-Proxy.txt") -Append
"NSLookup WPAD" | Out-File -FilePath ($global:resDir + "\WinHTTP-Proxy.txt") -Append
"" | Out-File -FilePath ($global:resDir + "\WinHTTP-Proxy.txt") -Append
$cmd = "nslookup wpad >>""" + $global:resDir + "\WinHTTP-Proxy.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Collecing GPResult output"
$cmd = "gpresult /h """ + $global:resDir + "\gpresult.html""" + $RdrErr
write-log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

$cmd = "gpresult /r >""" + $global:resDir + "\gpresult.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM"
$cmd = "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM """ + $global:resDir + "\WinRM.reg.txt"" /y " + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN """+ $global:resDir + "\WSMAN.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

if (Test-Path HKLM:\Software\Policies\Microsoft\Windows\WinRM) {
  Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM"
  $cmd = "reg export HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM """+ $global:resDir + "\WinRM-Policies.reg.txt"" /y" + $RdrOut + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd
} else {
  Write-Log "The registry key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM is not present"
}

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System """+ $global:resDir + "\System-Policies.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector """+ $global:resDir + "\EventCollector.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EventForwarding"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EventForwarding """+ $global:resDir + "\EventForwarding.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog """+ $global:resDir + "\EventLog-Policies.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
$cmd = "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL """+ $global:resDir + "\SCHANNEL.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography"
$cmd = "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography """+ $global:resDir + "\Cryptography.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography """+ $global:resDir + "\Cryptography-Policy.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
$cmd = "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa """+ $global:resDir + "\LSA.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\HTTP"
$cmd = "reg export HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\HTTP """+ $global:resDir + "\HTTP.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials) {
  Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials"
  $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials """+ $global:resDir + "\AllowFreshCredentials.reg.txt"" /y" + $RdrOut + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd
} else {
  Write-Log "The registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials is not present"
}

Write-Log "Exporting System log"
$cmd = "wevtutil epl System """+ $global:resDir + "\" + $env:computername + "-System.evtx""" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "System"

Write-Log "Exporting Application log"
$cmd = "wevtutil epl Application """+ $global:resDir + "\" + $env:computername + "-Application.evtx""" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "Application"

Write-Log "Exporting CAPI2 log"
$cmd = "wevtutil epl Microsoft-Windows-CAPI2/Operational """+ $global:resDir + "\" + $env:computername + "-capi2.evtx""" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "capi2"

Write-Log "Exporting Windows Remote Management log"
$cmd = "wevtutil epl Microsoft-Windows-WinRM/Operational """+ $global:resDir + "\" + $env:computername + "-WindowsRemoteManagement.evtx""" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "WindowsRemoteManagement"

Write-Log "Exporting EventCollector log"
$cmd = "wevtutil epl Microsoft-Windows-EventCollector/Operational """+ $global:resDir + "\" + $env:computername + "-EventCollector.evtx""" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "EventCollector"

Write-Log "Exporting Event-ForwardingPlugin log"
$cmd = "wevtutil epl Microsoft-Windows-Forwarding/Operational """+ $global:resDir + "\" + $env:computername + "-Event-ForwardingPlugin.evtx""" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "Event-ForwardingPlugin"

Write-Log "Exporting PowerShell/Operational log"
$cmd = "wevtutil epl Microsoft-Windows-PowerShell/Operational """+ $global:resDir + "\" + $env:computername + "-PowerShell-Operational.evtx""" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "PowerShell-Operational"

Write-Log "Exporting Windows PowerShell log"
$cmd = "wevtutil epl ""Windows PowerShell"" """+ $global:resDir + "\" + $env:computername + "-WindowsPowerShell.evtx""" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "WindowsPowerShell"

Write-Log "Exporting Windows Group Policy log"
$cmd = "wevtutil epl ""Microsoft-Windows-GroupPolicy/Operational"" """+ $global:resDir + "\" + $env:computername + "-GroupPolicy.evtx""" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "GroupPolicy"

Write-Log "Exporting Kernel-EventTracing log"
$cmd = "wevtutil epl ""Microsoft-Windows-Kernel-EventTracing/Admin"" """+ $global:resDir + "\" + $env:computername + "-EventTracing.evtx""" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "EventTracing"

if (Get-WinEvent -ListLog Microsoft-ServerManagementExperience -ErrorAction SilentlyContinue) {
  Write-Log "Exporting Windows Admin Center log"
  $cmd = "wevtutil epl Microsoft-ServerManagementExperience """+ $global:resDir + "\" + $env:computername + "-WindowsAdminCenter.evtx""" + $RdrOut + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd
  ArchiveLog "WindowsAdminCenter"
}

EvtLogDetails "Application"
EvtLogDetails "System"
EvtLogDetails "Security"
EvtLogDetails "ForwardedEvents"

Write-Log "Autologgers configuration"
Get-AutologgerConfig -Name EventLog-ForwardedEvents -ErrorAction SilentlyContinue | Out-File -FilePath ($global:resDir + "\AutoLoggersConfiguration.txt") -Append
Get-AutologgerConfig -Name EventLog-System -ErrorAction SilentlyContinue | Out-File -FilePath ($global:resDir + "\AutoLoggersConfiguration.txt") -Append
Get-AutologgerConfig -Name EventLog-Security -ErrorAction SilentlyContinue | Out-File -FilePath ($global:resDir + "\AutoLoggersConfiguration.txt") -Append
Get-AutologgerConfig -Name EventLog-Application -ErrorAction SilentlyContinue | Out-File -FilePath ($global:resDir + "\AutoLoggersConfiguration.txt") -Append

if ($OSVer -gt 6.1 ) {
  Write-Log "Copying ServerManager configuration"
  copy-item $env:APPDATA\Microsoft\Windows\ServerManager\ServerList.xml $global:resDir\ServerList.xml -ErrorAction Continue 2>>$global:errfile

  Write-Log "Exporting Microsoft-Windows-ServerManager-ConfigureSMRemoting/Operational log"
  $cmd = "wevtutil epl Microsoft-Windows-ServerManager-ConfigureSMRemoting/Operational """+ $global:resDir + "\" + $env:computername + "-ServerManager-ConfigureSMRemoting.evtx""" + $RdrOut + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd

  Write-Log "Exporting Microsoft-Windows-ServerManager-DeploymentProvider/Operational log"
  $cmd = "wevtutil epl Microsoft-Windows-ServerManager-DeploymentProvider/Operational """+ $global:resDir + "\" + $env:computername + "-ServerManager-DeploymentProvider.evtx""" + $RdrOut + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd

  Write-Log "Exporting Microsoft-Windows-ServerManager-MgmtProvider/Operational log"
  $cmd = "wevtutil epl Microsoft-Windows-ServerManager-MgmtProvider/Operational """+ $global:resDir + "\" + $env:computername + "-ServerManager-MgmtProvider.evtx""" + $RdrOut + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd

  Write-Log "Exporting Microsoft-Windows-ServerManager-MultiMachine/Operational log"
  $cmd = "wevtutil epl Microsoft-Windows-ServerManager-MultiMachine/Operational """+ $global:resDir + "\" + $env:computername + "-ServerManager-MultiMachine.evtx""" + $RdrOut + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd

  Write-Log "Exporting Microsoft-Windows-FileServices-ServerManager-EventProvider/Operational log"
  $cmd = "wevtutil epl Microsoft-Windows-FileServices-ServerManager-EventProvider/Operational """+ $global:resDir + "\" + $env:computername + "-ServerManager-EventProvider.evtx""" + $RdrOut + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd
  
  Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache"
  $cmd = "reg export ""HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache"" """ + $global:resDir + "\ServerComponentCache.reg.txt"" /y " + $RdrOut + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd
}

Write-Log "Exporting netsh http settings"
$cmd = "netsh http show sslcert >>""" + $global:resDir + "\netsh-http.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

$cmd = "netsh http show urlacl >>""" + $global:resDir + "\netsh-http.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

$cmd = "netsh http show servicestate >>""" + $global:resDir + "\netsh-http.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

$cmd = "netsh http show iplisten >>""" + $global:resDir + "\netsh-http.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

if (Test-Path HKLM:\SOFTWARE\Microsoft\InetStp) {
  Write-Log "Exporting IIS configuration"
  $cmd = $env:SystemRoot + "\system32\inetsrv\APPCMD list app >>""" + $global:resDir + "\iisconfig.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd

  $cmd = $env:SystemRoot + "\system32\inetsrv\APPCMD list apppool >>""" + $global:resDir + "\iisconfig.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd

  $cmd = $env:SystemRoot + "\system32\inetsrv\APPCMD list site >>""" + $global:resDir + "\iisconfig.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd

  $cmd = $env:SystemRoot + "\system32\inetsrv\APPCMD list module >>""" + $global:resDir + "\iisconfig.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd

  $cmd = $env:SystemRoot + "\system32\inetsrv\APPCMD list wp >>""" + $global:resDir + "\iisconfig.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd

  $cmd = $env:SystemRoot + "\system32\inetsrv\APPCMD list vdir >>""" + $global:resDir + "\iisconfig.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd

  $cmd = $env:SystemRoot + "\system32\inetsrv\APPCMD list config >>""" + $global:resDir + "\iisconfig.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd
} else { 
  Write-Log "IIS is not installed"
}

$cmd = "setspn -L " + $env:computername + " >>""" + $global:resDir + "\SPN.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
" " | Out-File ($global:resDir + "\SPN.txt") -Append

"Searching HTTP/" + $env:computername + " in the domain" | Out-File ($global:resDir + "\SPN.txt") -Append
$cmd = "setspn -Q HTTP/" + $env:computername + " >>""" + $global:resDir + "\SPN.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
" " | Out-File ($global:resDir + "\SPN.txt") -Append

"Searching HTTP/" + $fqdn + " in the domain" | Out-File ($global:resDir + "\SPN.txt") -Append
$cmd = "setspn -Q HTTP/" + $fqdn + " >>""" + $global:resDir + "\SPN.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
" " | Out-File ($global:resDir + "\SPN.txt") -Append

"Searching HTTP/" + $env:computername + " in the forest" | Out-File ($global:resDir + "\SPN.txt") -Append
$cmd = "setspn -F -Q HTTP/" + $env:computername + " >>""" + $global:resDir + "\SPN.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
" " | Out-File ($global:resDir + "\SPN.txt") -Append

"Searching HTTP/" + $fqdn + " in the forest" | Out-File ($global:resDir + "\SPN.txt") -Append
$cmd = "setspn -F -Q HTTP/" + $fqdn + " >>""" + $global:resDir + "\SPN.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
" " | Out-File ($global:resDir + "\SPN.txt") -Append

"Searching WSMAN/" + $env:computername + " in the domain" | Out-File ($global:resDir + "\SPN.txt") -Append
$cmd = "setspn -Q WSMAN/" + $env:computername + " >>""" + $global:resDir + "\SPN.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
" " | Out-File ($global:resDir + "\SPN.txt") -Append

"Searching WSMAN/" + $fqdn + " in the domain" | Out-File ($global:resDir + "\SPN.txt") -Append
$cmd = "setspn -Q WSMAN/" + $fqdn + " >>""" + $global:resDir + "\SPN.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
" " | Out-File ($global:resDir + "\SPN.txt") -Append

"Searching WSMAN/" + $env:computername + " in the forest" | Out-File ($global:resDir + "\SPN.txt") -Append
$cmd = "setspn -F -Q WSMAN/" + $env:computername + " >>""" + $global:resDir + "\SPN.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
" " | Out-File ($global:resDir + "\SPN.txt") -Append

"Searching WSMAN/" + $fqdn + " in the forest" | Out-File ($global:resDir + "\SPN.txt") -Append
$cmd = "setspn -F -Q WSMAN/" + $fqdn + " >>""" + $global:resDir + "\SPN.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
" " | Out-File ($global:resDir + "\SPN.txt") -Append

Write-Log "Collecting certificates details"
$cmd = "Certutil -verifystore -v MY > """ + $global:resDir + "\Certificates-My.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

$cmd = "Certutil -verifystore -v ROOT > """ + $global:resDir + "\Certificates-Root.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

$cmd = "Certutil -verifystore -v CA > """ + $global:resDir + "\Certificates-Intermediate.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

$tbCert = New-Object system.Data.DataTable
$col = New-Object system.Data.DataColumn Store,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn Thumbprint,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn Subject,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn Issuer,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn NotAfter,([DateTime]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn IssuerThumbprint,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn EnhancedKeyUsage,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn SerialNumber,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn SubjectKeyIdentifier,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn AuthorityKeyIdentifier,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn Template,([string]); $tbCert.Columns.Add($col)

GetStore "My"
GetStore "CA"
GetStore "Root"

Write-Log "Matching issuer thumbprints"
$aCert = $tbCert.Select("Store = 'My' or Store = 'CA'")
foreach ($cert in $aCert) {
  $aIssuer = $tbCert.Select("SubjectKeyIdentifier = '" + ($cert.AuthorityKeyIdentifier).tostring() + "'")
  if ($aIssuer.Count -gt 0) {
    $cert.IssuerThumbprint = ($aIssuer[0].Thumbprint).ToString()
  }
}
$tbcert | Export-Csv ($global:resDir + "\certificates.tsv") -noType -Delimiter "`t"

Write-Log "PowerShell version"
$PSVersionTable | Out-File -FilePath ($global:resDir + "\PSVersion.txt") -Append

Write-Log "Collecting the list of installed hotfixes"
Get-HotFix -ErrorAction SilentlyContinue 2>>$global:errfile | Sort-Object -Property InstalledOn -ErrorAction SilentlyContinue | Out-File $global:resDir\hotfixes.txt

Write-Log "Collecting details about running processes"
$proc = ExecQuery -Namespace "root\cimv2" -Query "select Name, CreationDate, ProcessId, ParentProcessId, WorkingSetSize, UserModeTime, KernelModeTime, ThreadCount, HandleCount, CommandLine, ExecutablePath, ExecutionState from Win32_Process"
if ($PSVersionTable.psversion.ToString() -ge "3.0") {
  $StartTime= @{e={$_.CreationDate.ToString("yyyyMMdd HH:mm:ss")};n="Start time"}
  $Owner = @{N="User";E={(GetOwnerCim($_))}}
} else {
  $StartTime= @{n='StartTime';e={$_.ConvertToDateTime($_.CreationDate)}}
  $Owner = @{N="User";E={(GetOwnerWmi($_))}}
}

if ($proc) {
  $proc | Sort-Object Name |
  Format-Table -AutoSize -property @{e={$_.ProcessId};Label="PID"}, @{e={$_.ParentProcessId};n="Parent"}, Name,
  @{N="WorkingSet";E={"{0:N0}" -f ($_.WorkingSetSize/1kb)};a="right"},
  @{e={[DateTime]::FromFileTimeUtc($_.UserModeTime).ToString("HH:mm:ss")};n="UserTime"}, @{e={[DateTime]::FromFileTimeUtc($_.KernelModeTime).ToString("HH:mm:ss")};n="KernelTime"},
  @{N="Threads";E={$_.ThreadCount}}, @{N="Handles";E={($_.HandleCount)}}, @{N="State";E={($_.ExecutionState)}}, $StartTime, $Owner, CommandLine |
  Out-String -Width 500 | Out-File -FilePath ($global:resDir + "\processes.txt")

  Write-Log "Retrieving file version of running binaries"
  $binlist = $proc | Group-Object -Property ExecutablePath
  foreach ($file in $binlist) {
    if ($file.Name) {
      FileVersion -Filepath ($file.name) -Log $true
    }
  }

  Write-Log "Collecting services details"
  $svc = ExecQuery -NameSpace "root\cimv2" -Query "select  ProcessId, DisplayName, StartMode,State, Name, PathName, StartName from Win32_Service"

  if ($svc) {
    $svc | Sort-Object DisplayName | Format-Table -AutoSize -Property ProcessId, DisplayName, StartMode,State, Name, PathName, StartName |
    Out-String -Width 400 | Out-File -FilePath ($global:resDir + "\services.txt")
  }
  Collect-SystemInfoWMI
  ExecQuery -Namespace "root\cimv2" -Query "select * from Win32_Product" | Sort-Object Name | Format-Table -AutoSize -Property Name, Version, Vendor, InstallDate | Out-String -Width 400 | Out-File -FilePath ($global:resDir + "\products.txt")
} else {
  $proc = Get-Process | Where-Object {$_.Name -ne "Idle"}
  $proc | Format-Table -AutoSize -property id, name, @{N="WorkingSet";E={"{0:N0}" -f ($_.workingset/1kb)};a="right"},
  @{N="VM Size";E={"{0:N0}" -f ($_.VirtualMemorySize/1kb)};a="right"},
  @{N="Proc time";E={($_.TotalProcessorTime.ToString().substring(0,8))}}, @{N="Threads";E={$_.threads.count}},
  @{N="Handles";E={($_.HandleCount)}}, StartTime, Path | 
  Out-String -Width 300 | Out-File -FilePath ($global:resDir + "\processes.txt")
  Collect-SystemInfoNoWMI
}

Write-Diag ("[INFO] " + $DiagVersion)

# Diag start

Write-Diag "[INFO] Checking HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\ClientAuthTrustMode"
$ClientAuthTrustMode = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel" | Select-Object -ExpandProperty "ClientAuthTrustMode" -ErrorAction SilentlyContinue)

if ($ClientAuthTrustMode -eq $null -or $ClientAuthTrustMode -eq 0) {
  Write-Diag "[WARNING]   0 Machine Trust (default) - Requires that the client certificate is issued by a certificate in the Trusted Issuers list."  
} elseif ($ClientAuthTrustMode -eq 1) {
  Write-Diag "[WARNING]   1 Exclusive Root Trust - Requires that a client certificate chains to a root certificate contained in the caller-specified trusted issuer store. The certificate must also be issued by an issuer in the Trusted Issuers list"  
} elseif ($ClientAuthTrustMode -eq 2) {
  Write-Diag "[INFO]   2 Exclusive CA Trust - Requires that a client certificate chain to either an intermediate CA certificate or root certificate in the caller-specified trusted issuer store."  
} else {
  Write-Diag ("[ERROR]   Invalid value " + $ClientAuthTrustMode)
}

$OSVer = [environment]::OSVersion.Version.Major + [environment]::OSVersion.Version.Minor * 0.1

$subDom = $false
$subWG = $false
$Subscriptions = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions
foreach ($sub in $Subscriptions) {
  Write-Diag ("[INFO] Found subscription " + $sub.PSChildname)
  $SubProp = ($sub | Get-ItemProperty)
  Write-Diag ("[INFO]   SubscriptionType = " + $SubProp.SubscriptionType + ", ConfigurationMode = " + $SubProp.ConfigurationMode)
  Write-Diag ("[INFO]   MaxLatencyTime = " + (GetSubVal $sub.PSChildname "MaxLatencyTime") + ", HeartBeatInterval = " + (GetSubVal $sub.PSChildname "HeartBeatInterval"))

  if ($SubProp.AllowedSourceDomainComputers) {
    Write-Diag "[INFO]   AllowedSourceDomainComputers"
    $ACL = (FindSep -FindIn $SubProp.AllowedSourceDomainComputers -Left ":P" -Right ")S:").replace(")(", ",").Split(",")
    foreach ($ACE in $ACL) {
      $SID = FindSep -FindIn $ACE -left ";;;"
      $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
      $group = $objSID.Translate( [System.Security.Principal.NTAccount]).Value
      Write-Diag "[INFO]      $group ($SID)"
    }
  }

  if ($SubProp.Locale) {
    if ($SubProp.Locale -eq "en-US") {
      Write-Diag "[INFO]   The subscription's locale is set to en-US"
    } else {
      Write-Diag ("[WARNING] The subscription's locale is set to " + $SubProp.Locale)
    }
  } else {
   Write-Diag "[INFO]   The subscription's locale is not set, the default locale will be used."    
  }

  if ($SubProp.AllowedSubjects) {
    $subWG = $true
    Write-Diag "[INFO]   Listed non-domain computers:"
    $list = $SubProp.AllowedSubjects -split ","
    foreach ($item in $list) {
      Write-Diag ("[INFO]   " + $item)
    }
  } else {
    Write-Diag "[INFO]   No non-domain computers listed, that's ok if this is not a collector in workgroup environment"
  }

  if ($SubProp.AllowedIssuerCAs) {
    $subWG = $true
    Write-Diag "[INFO]   Listed Issuer CAs:"
    $list = $SubProp.AllowedIssuerCAs -split ","
    foreach ($item in $list) {
      Write-Diag ("[INFO]   " + $item)
      ChkCert -cert $item -store "(Store = 'CA' or Store = 'Root')" -descr "Issuer CA"
    }
  } else {
    Write-Diag "[INFO]   No Issuer CAs listed, that's ok if this is not a collector in workgroup environment"
  }

  $RegKey = (($sub.Name).replace("HKEY_LOCAL_MACHINE\","HKLM:\") + "\EventSources")
  if (Test-Path -Path $RegKey) {
    $sources = Get-ChildItem -Path $RegKey
    if ($sources.Count -gt 4000) {
      Write-Diag ("[WARNING] There are " + $sources.Count + " sources for this subscription")
    } else {
      Write-Diag ("[INFO]   There are " + $sources.Count + " sources for this subscription")
    }
  } else {
    Write-Diag ("[INFO]   No sources found for the subscription " + $sub.Name)
  }
}

if ($Subscriptions) {
 $EventLost = (Get-Counter "\\$env:computername\Event Tracing for Windows Session(EventLog-ForwardedEvents)\Events Lost").CounterSamples[0].CookedValue
  if ($EventLost -gt 100) {
    Write-Diag ("[WARNING] " + $EventLost + " events lost for EventLog-ForwardedEvents")
  } else {
    Write-Diag ("[INFO] " + $EventLost + " events lost for EventLog-ForwardedEvents")
  }
}


if ($OSVer -gt 6.1) {
  Write-Diag "[INFO] Retrieving machine's IP addresses"
  $iplist = Get-NetIPAddress
}

Write-Diag "[INFO] Browsing listeners"
$listeners = Get-ChildItem WSMan:\localhost\Listener
foreach ($listener in $listeners) {
  Write-Diag ("[INFO] Inspecting listener " + $listener.Name)
  $prop = Get-ChildItem $listener.PSPath
  foreach ($value in $prop) {
    if ($value.Name -eq "CertificateThumbprint") {
      if ($listener.keys[0].Contains("HTTPS")) {
        Write-Diag "[INFO] Found HTTPS listener"
        $listenerThumbprint = $value.Value.ToLower()
        Write-Diag "[INFO] Found listener certificate $listenerThumbprint"
        if ($listenerThumbprint) {
          ChkCert -cert $listenerThumbprint -descr "listener" -store "Store = 'My'"
        }
      }
    }
    if ($value.Name.Contains("ListeningOn")) {
      $ip = ($value.value).ToString()
      Write-Diag "[INFO] Listening on $ip"
      if ($OSVer -gt 6.1) {
        if (($iplist | Where-Object {$_.IPAddress -eq $ip } | measure-object).Count -eq 0 ) {
          Write-Diag "[ERROR] IP address $ip not found"
        }
      }
    }
  } 
} 

$svccert = Get-Item WSMan:\localhost\Service\CertificateThumbprint
if ($svccert.value ) {
  Write-Diag ("[INFO] The Service Certificate thumbprint is " + $svccert.value)
  ChkCert -cert $svccert.value -descr "Service" -store "Store = 'My'"
}

$remoteaccess = Get-Item WSMan:\localhost\Service\AllowRemoteAccess
if ($remoteaccess.Value -eq "true") {
  Write-Diag "[INFO] AllowRemoteAccess = true"
} elseif ($remoteaccess.Value -eq "false") {
  Write-Diag "[ERROR] AllowRemoteAccess = false, this machine will not accept remote WinRM connections"
} else {
  Write-Diag "[ERROR] AllowRemoteAccess has an invalid value"
}

$ipfilter = Get-Item WSMan:\localhost\Service\IPv4Filter
if ($ipfilter.Value) {
  if ($ipfilter.Value -eq "*") {
    Write-Diag "[INFO] IPv4Filter = *"
  } else {
    Write-Diag ("[WARNING] IPv4Filter = " + $ipfilter.Value)
  }
} else {
  Write-Diag ("[WARNING] IPv4Filter is empty, WinRM will not listen on IPv4")
}

$ipfilter = Get-Item WSMan:\localhost\Service\IPv6Filter
if ($ipfilter.Value) {
  if ($ipfilter.Value -eq "*") {
    Write-Diag "[INFO] IPv6Filter = *"
  } else {
    Write-Diag ("[WARNING] IPv6Filter = " + $ipfilter.Value)
  }
} else {
  Write-Diag ("[WARNING] IPv6Filter is empty, WinRM will not listen on IPv6")
}

if (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager") {
  $isForwarder = $True
  $RegKey = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager')

  Write-Diag "[INFO] Enumerating SubscriptionManager URLs at HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
  $RegKey.PSObject.Properties | ForEach-Object {
    If($_.Name -notlike '*PS*'){
      Write-Diag ("[INFO] " + $_.Name + " " + $_.Value)
      $IssuerCA = (FindSep -FindIn $_.Value -Left "IssuerCA=" -Right ",").ToLower()
      if (-not $IssuerCA) {
        $IssuerCA = (FindSep -FindIn $_.Value -Left "IssuerCA=" -Right "").ToLower()
      }
      if ($IssuerCA) {
        if ("0123456789abcdef".Contains($IssuerCA[0])) {
          Write-Diag ("[INFO] Found issuer CA certificate thumbprint " + $IssuerCA)
          $aCert = $tbCert.Select("Thumbprint = '" + $IssuerCA + "' and (Store = 'CA' or Store = 'Root')")
          if ($aCert.Count -eq 0) {
            Write-Diag "[ERROR] The Issuer CA certificate was not found in CA or Root stores"
          } else {
            Write-Diag ("[INFO] Issuer CA certificate found in store " + $aCert[0].Store + ", subject = " + $aCert[0].Subject)
            if (($aCert[0].NotAfter) -gt (Get-Date)) {
              Write-Diag ("[INFO] The Issuer CA certificate will expire on " + $aCert[0].NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") )
            } else {
              Write-Diag ("[ERROR] The Issuer CA certificate expired on " + $aCert[0].NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") )
            }
          }

          $aCliCert = $tbCert.Select("IssuerThumbprint = '" + $IssuerCA + "' and Store = 'My'")
          if ($aCliCert.Count -eq 0) {
            Write-Diag "[ERROR] Cannot find any certificate issued by this Issuer CA"
          } else {
            if ($PSVersionTable.psversion.ToString() -ge "3.0") {
              Write-Diag "[INFO] Listing available client certificates from this IssuerCA"
              $num = 0
              foreach ($cert in $aCliCert) {
                if ($cert.EnhancedKeyUsage.Contains("Client Authentication")) {
                  Write-Diag ("[INFO]   Found client certificate " + $cert.Thumbprint + " " + $cert.Subject)
                  if (($Cert.NotAfter) -gt (Get-Date)) {
                    Write-Diag ("[INFO]   The client certificate will expire on " + $cert.NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") )
                  } else {
                    Write-Diag ("[ERROR]   The client certificate expired on " + $cert.NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") )
                  }
                  $certobj = Get-Item ("CERT:\Localmachine\My\" + $cert.Thumbprint)
                  $keypath = [io.path]::combine("$env:ProgramData\microsoft\crypto\rsa\machinekeys", $certobj.privatekey.cspkeycontainerinfo.uniquekeycontainername)
                  if ([io.file]::exists($keypath)) {
                    $acl = ((get-acl -path $keypath).Access | Where-Object {$_.IdentityReference -eq "NT AUTHORITY\NETWORK SERVICE"})
                    if ($acl) {
                      $rights = $acl.FileSystemRights.ToString()
                      if ($rights.contains("Read") -or $rights.contains("FullControl") ) {
                        Write-Diag ("[INFO]   The NETWORK SERVICE account has permissions on the private key of this certificate: " + $rights)
                      } else {
                        Write-Diag ("[ERROR]  Incorrect permissions for the NETWORK SERVICE on the private key of this certificate: " + $rights)
                      }
                    } else {
                      Write-Diag "[ERROR]  Missing permissions for the NETWORK SERVICE account on the private key of this certificate"
                    }
                  } else {
                    Write-Diag "[ERROR]  Cannot find the private key"
                  } 
                  $num++
                }
              }
              if ($num -eq 0) {
                Write-Diag "[ERROR] Cannot find any client certificate issued by this Issuer CA"
              } elseif ($num -gt 1) {
                Write-Diag "[WARNING] More than one client certificate issued by this Issuer CA, the first certificate will be used by WinRM"
              }
            }
          }
        } else {
         Write-Diag "[ERROR] Invalid character for the IssuerCA certificate in the SubscriptionManager URL"
        }
      }
    } 
  }
  $RegKey = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding')
  if ($regkey.MaxForwardingRate) {
    Write-Diag "[ERROR] MaxForwardingRate is configured, this feature does not work. Please remove this setting and see bug 33554568."
  }
} else {
  $isForwarder = $false
  Write-Diag "[INFO] No SubscriptionManager URL configured. It's ok if this machine is not supposed to forward events."
}

if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) {
  $search = New-Object DirectoryServices.DirectorySearcher([ADSI]"GC://$env:USERDNSDOMAIN") # The SPN is searched in the forest connecting to a Global catalog

  $SPNReg = ""
  $SPN = "HTTP/" + $env:COMPUTERNAME
  Write-Diag ("[INFO] Searching for the SPN $SPN")
  $search.filter = "(servicePrincipalName=$SPN)"
  $results = $search.Findall()
  if ($results.count -gt 0) {
    foreach ($result in $results) {
      Write-Diag ("[INFO] The SPN HTTP/$env:COMPUTERNAME is registered for DNS name = " + $result.properties.dnshostname + ", DN = " + $result.properties.distinguishedname + ", Category = " + $result.properties.objectcategory)
      if ($result.properties.objectcategory[0].Contains("Computer")) {
        if (-not $result.properties.dnshostname[0].Contains($env:COMPUTERNAME)) {
          Write-Diag ("[ERROR] The The SPN $SPN is registered for different DNS host name: " + $result.properties.dnshostname[0])
          $SPNReg = "OTHER"
        }
      } else {
        Write-Diag "[ERROR] The The SPN $SPN is NOT registered for a computer account"
        $SPNReg = "OTHER"
      }
    }
    if ($results.count -gt 1) {
      Write-Diag "[ERROR] The The SPN $SPN is duplicate"
    }
  } else {
    Write-Diag "[INFO] The The SPN $SPN was not found. That's ok, the SPN HOST/$env:COMPUTERNAME will be used"
  }

  $SPN = "HTTP/" + $env:COMPUTERNAME + ":5985"
  Write-Diag ("[INFO] Searching for the SPN $SPN")
  $search.filter = "(servicePrincipalName=$SPN)"
  $results = $search.Findall()
  if ($results.count -gt 0) {
    foreach ($result in $results) {
      Write-Diag ("[INFO] The SPN HTTP/$env:COMPUTERNAME is registered for DNS name = " + $result.properties.dnshostname + ", DN = " + $result.properties.distinguishedname + ", Category = " + $result.properties.objectcategory)
      if ($result.properties.objectcategory[0].Contains("Computer")) {
        if (-not $result.properties.dnshostname[0].Contains($env:COMPUTERNAME)) {
          Write-Diag ("[ERROR] The The SPN $SPN is registered for different DNS host name: " + $result.properties.dnshostname[0])
        }
      } else {
        Write-Diag "[ERROR] The The SPN $SPN is NOT registered for a computer account"
      }
    }
    if ($results.count -gt 1) {
      Write-Diag "[ERROR] The The SPN $SPN is duplicate"
    }
  } else {
    if ($SPNReg -eq "OTHER") {
      Write-Diag "[WARNING] The The SPN $SPN was not found. It is required to accept WinRM connections since the HTTP/$env:COMPUTERNAME is reqistered to another name"
    }
  }

  Write-Diag "[INFO] Checking the WinRMRemoteWMIUsers__ group"
  $search = New-Object DirectoryServices.DirectorySearcher([ADSI]"")  # This is a Domain local group, therefore we need to collect to a non-global catalog
  $search.filter = "(samaccountname=WinRMRemoteWMIUsers__)"
  $results = $search.Findall()
  if ($results.count -gt 0) {
    Write-Diag ("[INFO] Found " + $results.Properties.distinguishedname)
    if ($results.Properties.grouptype -eq  -2147483644) {
      Write-Diag "[INFO] WinRMRemoteWMIUsers__ is a Domain local group"
    } elseif ($results.Properties.grouptype -eq -2147483646) {
      Write-Diag "[WARNING] WinRMRemoteWMIUsers__ is a Global group"
    } elseif ($results.Properties.grouptype -eq -2147483640) {
      Write-Diag "[WARNING] WinRMRemoteWMIUsers__ is a Universal group"
    }
    if (Get-WmiObject -query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
      Write-Diag "[INFO] The group WinRMRemoteWMIUsers__ is also present as machine local group"
    }
  } else {
    Write-Diag "[ERROR] The WinRMRemoteWMIUsers__ was not found in the domain" 
    if (Get-WmiObject -query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
      Write-Diag "[INFO] The group WinRMRemoteWMIUsers__ is present as machine local group"
    } else {
      Write-Diag "[ERROR] The group WinRMRemoteWMIUsers__ is not even present as machine local group"
    }
  }
  if ((Get-ChildItem WSMan:\localhost\Service\Auth\Kerberos).value -eq "true") {
    Write-Diag "[INFO] Kerberos authentication is enabled for the service"
  }  else {
    Write-Diag "[WARNING] Kerberos authentication is disabled for the service"
  }
} else {
  Write-Diag "[INFO] The machine is not joined to a domain"
  if (Get-WmiObject -query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
    Write-Diag "[INFO] The group WinRMRemoteWMIUsers__ is present as machine local group"
  } else {
    Write-Diag "[ERROR] The group WinRMRemoteWMIUsers__ is not present as machine local group"
  }
  if ((Get-ChildItem WSMan:\localhost\Service\Auth\Certificate).value -eq "false") {
    Write-Diag "[WARNING] Certificate authentication is disabled for the service"
  }  else {
    Write-Diag "[INFO] Certificate authentication is enabled for the service"
  }
}

$iplisten = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" | Select-Object -ExpandProperty "ListenOnlyList" -ErrorAction SilentlyContinue)
if ($iplisten) {
  Write-Diag ("[WARNING] The IPLISTEN list is not empty, the listed addresses are " + $iplisten)
} else {
  Write-Diag "[INFO] The IPLISTEN list is empty. That's ok: WinRM will listen on all IP addresses"
}

$binval = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name WinHttpSettings).WinHttPSettings            
$proxylength = $binval[12]            
if ($proxylength -gt 0) {
  $proxy = -join ($binval[(12+3+1)..(12+3+1+$proxylength-1)] | % {([char]$_)})            
  Write-Diag ("[WARNING] A NETSH WINHTTP proxy is configured: " + $proxy)
  $bypasslength = $binval[(12+3+1+$proxylength)]            
  if ($bypasslength -gt 0) {            
    $bypasslist = -join ($binval[(12+3+1+$proxylength+3+1)..(12+3+1+$proxylength+3+1+$bypasslength)] | % {([char]$_)})            
    Write-Diag ("[WARNING] Bypass list: " + $bypasslist)
   } else {            
    Write-Diag "[WARNING] No bypass list is configured"
  }            
  Write-Diag "[WARNING] WinRM does not work very well through proxies, make sure that the target machine is in the bypass list or remove the proxy"
} else {
  Write-Diag "[INFO] No NETSH WINHTTP proxy is configured"
}

$th = (get-item WSMan:\localhost\Client\TrustedHosts).value
if ($th) {
  Write-Diag ("[INFO] TrustedHosts contains: $th")
} else {
  Write-Diag ("[INFO] TrustedHosts is not configured, it's ok it this machine is not supposed to connect to other machines using NTLM")
}

$psver = $PSVersionTable.PSVersion.Major.ToString() + $PSVersionTable.PSVersion.Minor.ToString()
if ($psver -eq "50") {
  Write-Diag ("[WARNING] Windows Management Framework version " + $PSVersionTable.PSVersion.ToString() + " is no longer supported")
} else { 
  Write-Diag ("[INFO] Windows Management Framework version is " + $PSVersionTable.PSVersion.ToString() )
}

$clientcert = Get-ChildItem WSMan:\localhost\ClientCertificate
if ($clientcert.Count -gt 0) {
  Write-Diag "[INFO] Client certificate mappings"
  foreach ($certmap in $clientcert) {
    Write-Diag ("[INFO] Certificate mapping " + $certmap.Name)
    $prop = Get-ChildItem $certmap.PSPath
    foreach ($value in $prop) {
      Write-Diag ("[INFO]   " + $value.Name + " " + $value.Value)
      if ($value.Name -eq "Issuer") {
        ChkCert -cert $value.Value -descr "mapping" -store "(Store = 'Root' or Store = 'CA')"
      } elseif ($value.Name -eq "UserName") {
        $usr = Get-WmiObject -class Win32_UserAccount | Where {$_.Name -eq $value.value}
        if ($usr) {
          if ($usr.Disabled) {
            Write-Diag ("[ERROR]    The local user account " + $value.value + " is disabled")
          } else {
            Write-Diag ("[INFO]     The local user account " + $value.value + " is enabled")
          }
        } else {
          Write-Diag ("[ERROR]    The local user account " + $value.value + " does not exist")
        }
      } elseif ($value.Name -eq "Subject") {
        if ($value.Value[0] -eq '"') {
          Write-Diag "[ERROR]    The subject does not have to be included in double quotes"
        }
      }
    }
  }
} else {
  if ($subWG) {
    Write-Diag "[ERROR] No client certificate mapping configured"
  }
}

$aCert = $tbCert.Select("Store = 'Root' and Subject <> Issuer")
if ($aCert.Count -gt 0) {
  Write-Diag "[ERROR] Found for non-Root certificates in the Root store"
  foreach ($cert in $acert) {
    Write-Diag ("[ERROR]  Misplaced certificate " + $cert.Subject)
  }
}

if ($isForwarder) {
  $evtLogReaders = (Get-WmiObject -Query ("Associators of {Win32_Group.Domain='" + $env:COMPUTERNAME + "',Name='Event Log Readers'} where Role=GroupComponent") | Where {$_.Name -eq "NETWORK SERVICE"} | Measure-Object)
  if ($evtLogReaders.Count -gt 0) {
    Write-Diag "[INFO] The NETWORK SERVICE account is member of the Event Log Readers group"
  } else {
    Write-Diag "[WARNING] The NETWORK SERVICE account is NOT member of the Event Log Readers group, the events in the Security log cannot be forwarded"
  }
}

$fwrules = (Get-NetFirewallPortFilter –Protocol TCP | Where { $_.localport –eq ‘5986’ } | Get-NetFirewallRule)
if ($fwrules.count -eq 0) {
  Write-Diag "[INFO] No firewall rule for port 5986"
} else {
  Write-Diag "[INFO] Found firewall rule for port 5986"
}

$dir = $env:windir + "\system32\logfiles\HTTPERR"
if (Test-Path -path $dir) {
  $httperrfiles = Get-ChildItem -path ($dir)
  if ($httperrfiles.Count -gt 100) {
    Write-Diag ("[WARNING] There are " + $httperrfiles.Count + " files in the folder " + $dir)
  } else {
   Write-Diag ("[INFO] There are " + $httperrfiles.Count + " files in the folder " + $dir)
  }
  $size = 0 
  foreach ($file in $httperrfiles) {
    $size += $file.Length
  }
  $size = [System.Math]::Ceiling($size / 1024 / 1024) # Convert to MB
  if ($size -gt 100) {
    Write-Diag ("[WARNING] The folder " + $dir + " is using " + $size.ToString() + " MB of disk space")
  } else {
    Write-Diag ("[INFO] The folder " + $dir + " is using " + $size.ToString() + " MB of disk space")
  }
}

