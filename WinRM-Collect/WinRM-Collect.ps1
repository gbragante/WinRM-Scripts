param( [string]$DataPath, `
       [switch]$AcceptEula, `
       [switch]$Trace, `
       [switch]$Logs, `
       [switch]$Activity, `
       [switch]$Fwd, `
       [switch]$FwdCli, `
       [switch]$RemShell, `
       [switch]$HTTP, `
       [switch]$CAPI, `
       [switch]$Kerberos, `
       [switch]$NTLM, `
       [switch]$PKU2U, `
       [switch]$Schannel, `
       [switch]$EventLog, `
       [switch]$Network, `
       [switch]$PerfMon, `
       [switch]$Kernel 
)

$version = "WinRM-Collect (20230421)"
$DiagVersion = "WinRM-Diag (20230207)"

# by Gianni Bragante - gbrag@microsoft.com

Function Write-Diag {
  param( [string] $msg )
  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
  Write-Host $msg
  $msg | Out-File -FilePath $diagfile -Append
}

Function WinRMTraceCapture {
  Invoke-CustomCommand ("logman create trace 'WinRM-Trace' -ow -o '" + $TracesDir + "\WinRM-Trace-$env:COMPUTERNAME.etl" + "' -p 'Microsoft-Windows-WinRM' 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets")  
  
  Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{04C6E16D-B99F-4A3A-9B3E-B8325BBC781E}' 0xffffffffffffffff 0xff -ets" # Windows Remote Management Trace

  if (-not $Activity -or $Fwd) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{699E309C-E782-4400-98C8-E21D162D7B7B}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-Forwarding
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{B977CF02-76F6-DF84-CC1A-6A4B232322B6}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-EventCollector
  }

  if (-not $Activity -or $RemShell) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{F1CAB2C0-8BEB-4FA2-90E1-8F17E0ACDD5D}' 0xffffffffffffffff 0xff -ets" # RemoteShellClient
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{03992646-3DFE-4477-80E3-85936ACE7ABB}' 0xffffffffffffffff 0xff -ets" # RemoteShell
  }
  if (-not $Activity -or $HTTP) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{72B18662-744E-4A68-B816-8D562289A850}' 0xffffffffffffffff 0xff -ets" # Windows HTTP Services
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{7D44233D-3055-4B9C-BA64-0D47CA40A232}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-WinHttp
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{B3A7698A-0C45-44DA-B73D-E181C9B5C8E6}' 0xffffffffffffffff 0xff -ets" # WinHttp
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{DD5EF90A-6398-47A4-AD34-4DCECDEF795F}' 0xffffffffffffffff 0xff -ets" # HTTP Service Trace
  }
  if (-not $Activity -or $CAPI) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{5BBCA4A8-B209-48DC-A8C7-B23D3E5216FB}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-CAPI2
  }
  if (-not $Activity -or $Kerberos) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{6B510852-3583-4E2D-AFFE-A67F9F223438}' 0xffffffffffffffff 0xff -ets" # Kerberos Authentication
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{BBA3ADD2-C229-4CDB-AE2B-57EB6966B0C4}' 0xffffffffffffffff 0xff -ets" # Kerberos Client
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{98E6CFCB-EE0A-41E0-A57B-622D4E1B30B1}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-Security-Kerberos
  }
  if (-not $Activity -or $CredSSP) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{6165F3E2-AE38-45D4-9B23-6B4818758BD9}' 0xffffffffffffffff 0xff -ets" # TSPkg
  }
  if (-not $Activity -or $NTLM) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{AC43300D-5FCC-4800-8E99-1BD3F85F0320}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-NTLM
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{C92CF544-91B3-4DC0-8E11-C580339A0BF8}' 0xffffffffffffffff 0xff -ets" # NTLM Security Protocol
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{5BBB6C18-AA45-49B1-A15F-085F7ED0AA90}' 0xffffffffffffffff 0xff -ets" # NTLM Authentication
  }
  if ($PKU2U) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{2A6FAF47-5449-4805-89A3-A504F3E221A6}' 0xffffffffffffffff 0xff -ets" # Pku2u Authentication
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{B1108F75-3252-4B66-9239-80FD47E06494}' 0xffffffffffffffff 0xff -ets" # IdentityCommonLib
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{D93FE84A-795E-4608-80EC-CE29A96C8658}' 0xffffffffffffffff 0xff -ets" # IdentityListenerControlGuid
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{82C7D3DF-434D-44FC-A7CC-453A8075144E}' 0xffffffffffffffff 0xff -ets" # IDStore
  }
  if (-not $Activity -or $Schannel) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{1F678132-5938-4686-9FDC-C8FF68F15C85}' 0xffffffffffffffff 0xff -ets" # Schannel
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{37D2C3CD-C5D4-4587-8531-4696C44244C8}' 0xffffffffffffffff 0xff -ets" # SchannelWppGuid
  }

  if ($FwdCli) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{9D11915C-C654-4D73-A6D6-591570E011A0}' 0xffffffffffffffff 0xff -ets" # EvtFwdrWpp
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{6FCDF39A-EF67-483D-A661-76D715C6B008}' 0xffffffffffffffff 0xff -ets" # ForwarderTrace
  }
  if ($FwdCli -or $EventLog) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{FC65DDD8-D6EF-4962-83D5-6E5CFE9CE148}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-Eventlog
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{B0CA1D82-539D-4FB0-944B-1620C6E86231}' 0xffffffffffffffff 0xff -ets" # EventlogTrace
  }
  if ($Network) {
    Invoke-CustomCommand ("netsh trace start capture=yes scenario=netconnection maxsize=2048 report=disabled tracefile='" + $TracesDir + "NETCAP-" + $env:COMPUTERNAME + ".etl'")
  }  
  if ($Kernel) {
    Invoke-CustomCommand ("logman create trace 'NT Kernel Logger' -ow -o '" + $TracesDir + "\WinRM-Trace-kernel-$env:COMPUTERNAME.etl" + "' -p '{9E814AAD-3204-11D2-9A82-006008A86939}' 0x1 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 512 -ets")
  }
  if ($PerfMon) {
    Invoke-CustomCommand ("Logman create counter 'WinRM-Trace-PerfMon' -f bincirc  -max 2048 -c '\Process(*)\*' '\Processor(*)\*' '\PhysicalDisk(*)\*' '\Event Tracing for Windows Session(EventLog-*)\Events Lost' '\Event Tracing for Windows Session(EventLog-*)\Events Logged per sec' '\HTTP Service Request Queues(*)\*' -si 00:00:01 -o '" + $TracesDir + "WinRM-trace-$env:COMPUTERNAME.blg'")
    Invoke-CustomCommand ("logman start 'WinRM-Trace-PerfMon'")
  }

  Write-Log "Trace capture started"
  read-host "Press ENTER to stop the capture"
  Invoke-CustomCommand "logman stop 'WinRM-Trace' -ets"
  if ($Network) {
    Invoke-CustomCommand "netsh trace stop"
  }  
  if ($Kernel) {
    Invoke-CustomCommand "logman stop 'NT Kernel Logger' -ets"
  }
  if ($PerfMon) {
    Invoke-CustomCommand ("logman stop 'WinRM-Trace-PerfMon'")
    Invoke-CustomCommand ("logman delete 'WinRM-Trace-PerfMon'")
  }


  Invoke-CustomCommand "tasklist /svc" -DestinationFile ("Traces\tasklist-$env:COMPUTERNAME.txt")
}
Function GetPlugins{
  # This function is a contribution from Ga�tan Rabier
  param(
    [string] $WinRMPluginPath = "WSMan:\localhost\plugin"
  )
  Write-Log ("Parsing plugins from path " + $WinRMPluginPath)
  $WinRMPlugins = Get-ChildItem $WinRMPluginPath

  foreach ($Plugin in $WinRMPlugins) {
    $PluginName = $Plugin.Name
    $PluginURIs = (Get-ChildItem $WinRMPluginPath\$PluginName\Resources).Name
    $PluginDLL = (Get-ChildItem $WinRMPluginPath\$PluginName\Filename).Value
    $PluginName  | Out-File -FilePath ($resDir + "\Plugins.txt") -Append
    ("  DLL: " + $PluginDLL) | Out-File -FilePath ($resDir + "\Plugins.txt") -Append
    foreach ($PluginURI in $PluginURIs) {
      $Capability = (Get-ChildItem $WinRMPluginPath\$PluginName\Resources\$PluginURI\Capability).Value
      $SecurityContainerName = (Get-ChildItem $WinRMPluginPath\$PluginName\Resources\$PluginURI\Security).Name
      $SecurityContainer = Get-ChildItem $WinRMPluginPath\$PluginName\Resources\$PluginURI\Security\$SecurityContainerName
      $SecuritySddl = ($SecurityContainer |Where-Object {$_.Name -eq 'Sddl'}).Value
      $SecuritySddlConverted = (ConvertFrom-SddlString $SecuritySddl).DiscretionaryAcl
      $ResourceURI = ($SecurityContainer | Where-Object {$_.Name -eq 'ParentResourceUri'}).Value

      ("  URI: " + $ResourceURI) | Out-File -FilePath ($resDir + "\Plugins.txt") -Append
      ("    Capabilities: " + $Capability) | Out-File -FilePath ($resDir + "\Plugins.txt") -Append
      ("    Security descriptor : " + $SecuritySddlConverted) | Out-File -FilePath ($resDir + "\Plugins.txt") -Append
      " " | Out-File -FilePath ($resDir + "\Plugins.txt") -Append
      Remove-Variable SecurityContainerName,SecurityContainer,ResourceURI,Capability,SecuritySddlConverted,SecuritySddl
    }
  }
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
if ($DataPath) {
  if (-not (Test-Path $DataPath)) {
    Write-Host "The folder $DataPath does not exist"
    exit
  }
  $global:resDir = $DataPath + "\" + $resName
} else {

  $global:resDir = $global:Root + "\" + $resName
} if ($DataPath) {
  if (-not (Test-Path $DataPath)) {
    Write-Host "The folder $DataPath does not exist"
    exit
  }
  $global:resDir = $DataPath + "\" + $resName
} else {

  $global:resDir = $global:Root + "\" + $resName
}

$diagfile = $global:resDir + "\WinRM-Diag.txt"
$global:outfile = $global:resDir + "\script-output.txt"
$global:errfile = $global:resDir + "\script-errors.txt"

Import-Module ($global:Root + "\Collect-Commons.psm1") -Force -DisableNameChecking

if (-not $Trace -and -not $Logs) {
  Write-Host "WinRM-Collect: a data collection tools for WinRM troubleshooting"
  Write-Host ""
  Write-Host "Usage:"
  Write-Host "WinRM-Collect -Logs"
  Write-Host "  Collects dumps, logs, registry keys, command outputs"
  Write-Host ""
  Write-Host "WinRM-Collect -Trace [[-Activity][-Fwd][-RemShell][-HTTP][-CAPI][-Kerberos][-CredSSP][-NTLM][-Schannel]] [-FwdCli][-EventLog][-Network][-Kernel][-PerfMon]"
  Write-Host "  Collects live trace"
  Write-Host ""
  Write-Host "WMI-Collect -Logs -Trace [[-Activity][-Fwd][-RemShell][-HTTP][-CAPI][-Kerberos][-CredSSP][-NTLM][-Schannel]] [-FwdCli][-EventLog][-Network][-Kernel][-PerfMon]"
  Write-Host "  Collects live trace then -Logs data"
  Write-Host ""
  Write-Host "Parameters for -Trace :"
  Write-Host "  -Activity : Only trace WinRM basic log, less detailed and less noisy)"
  Write-Host "    -Fwd : Event Log Forwarding (enabled by default without -Activity)"
  Write-Host "    -RemShell : Remote Shell (enabled by default without -Activity)"
  Write-Host "    -HTTP : WinHTTP and HTTP.SYS (enabled by default without -Activity)"
  Write-Host "    -CAPI : CAPI (enabled by default without -Activity)"
  Write-Host "    -Kerberos : Kerberos (enabled by default without -Activity)"
  Write-Host "    -CredSSP : CredSSP (enabled by default without -Activity)"
  Write-Host "    -NTLM : NTLM (enabled by default without -Activity)"
  Write-Host "    -Schannel : Schannel (enabled by default without -Activity)"
  Write-Host ""
  Write-Host "  -FwdCli : Additional client side treacing for EventLog forwarding"
  Write-Host "  -EventLog : Event Log tracing (included in -FwdCli)"
  Write-Host "  -Network : Network capture"
  Write-Host "  -Kernel : Kernel Trace for process start and stop"
  Write-Host "  -PerfMon : Performance counters"
  Write-Host ""
  exit
}
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

if ($Trace) {
  $TracesDir = $global:resDir + "\Traces\"
  New-Item -itemtype directory -path $TracesDir | Out-Null
  WinRMTraceCapture
  if (-not $Logs) {
    exit
  }
}

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
  GetPlugins -WinRMPluginPath (WSMan:\$fqdn\Plugin)
  Disconnect-WSMan -ComputerName $fqdn -ErrorAction Continue 2>>$global:errfile
} else {
  GetPlugins
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
  CreateProcDump $pidWinRM $global:resDir "svchost-WinRM"
}

Write-Log "Collecing the dumps of wsmprovhost.exe processes"
$list = get-process -Name "wsmprovhost" -ErrorAction SilentlyContinue 2>>$global:errfile
if (($list | Measure-Object).count -gt 0) {
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
FileVersion -Filepath ($env:windir + "\system32\pwrshplugin.dll") -Log $true

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

if ($OSVer -le 6.3) {
  Write-Log "Listing members of WinRMRemoteWMIUsers__ group"
  $cmd = "net localgroup ""WinRMRemoteWMIUsers__"" >>""" + $global:resDir + "\Groups.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append
} else {
  Write-Log "Listing members of Remote Management Users group"
  $cmd = "net localgroup ""Remote Management Users"" >>""" + $global:resDir + "\Groups.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append
}

Write-Log "Listing members of Windows Admin Center CredSSP Administrators group"
$cmd = "net localgroup ""Windows Admin Center CredSSP Administrators"" >>""" + $global:resDir + "\Groups.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

(" ") | Out-File -FilePath ($global:resDir + "\Groups.txt") -Append
($group + " = " + $strSID) | Out-File -FilePath ($global:resDir + "\Groups.txt") -Append

Write-Log "Getting the output of WHOAMI /all"
$cmd = "WHOAMI /all >>""" + $global:resDir + "\WHOAMI.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

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

Invoke-CustomCommand -Command "netstat -anob" -DestinationFile "netstat.txt"
Invoke-CustomCommand -Command "ipconfig /all" -DestinationFile "ipconfig.txt"
Invoke-CustomCommand -Command "auditpol /get /category:*" -DestinationFile "auditpol.txt"

Write-Log "Copying hosts and lmhosts"
if (Test-path -path C:\Windows\system32\drivers\etc\hosts) {
  Copy-Item C:\Windows\system32\drivers\etc\hosts $global:resDir\hosts.txt -ErrorAction Continue 2>>$global:errfile
}
if (Test-Path -Path C:\Windows\system32\drivers\etc\lmhosts) {
  Copy-Item C:\Windows\system32\drivers\etc\lmhosts $global:resDir\lmhosts.txt -ErrorAction Continue 2>>$global:errfile
}

$dir = $env:windir + "\system32\logfiles\HTTPERR"
if (Test-Path -path $dir) {
  $last = Get-ChildItem -path ($dir) | Sort-Object CreationTime -Descending | Select-Object Name -First 1 
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

Export-EventLog "System"
Export-EventLog "Application"
Export-EventLog "Microsoft-Windows-CAPI2/Operational"
Export-EventLog "Microsoft-Windows-WinRM/Operational"
Export-EventLog "Microsoft-Windows-EventCollector/Operational"
Export-EventLog "Microsoft-Windows-Forwarding/Operational"
Export-EventLog "Microsoft-Windows-PowerShell/Operational"
Export-EventLog "Windows PowerShell"
Export-EventLog "PowerShellCore/Operational"
Export-EventLog "Microsoft-Windows-GroupPolicy/Operational"
Export-EventLog "Microsoft-Windows-Kernel-EventTracing/Admin"
Export-EventLog "Microsoft-ServerManagementExperience"
Export-EventLog "Microsoft-Windows-ServerManager-ConfigureSMRemoting/Operational"
Export-EventLog "Microsoft-Windows-ServerManager-DeploymentProvider/Operational"
Export-EventLog "Microsoft-Windows-ServerManager-MgmtProvider/Operational"
Export-EventLog "Microsoft-Windows-ServerManager-MultiMachine/Operational"
Export-EventLog "Microsoft-Windows-FileServices-ServerManager-EventProvider/Operational"

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

Write-Log "Collecting details about running processes"
if (ListProcsAndSvcs) {
  CollectSystemInfoWMI
  ExecQuery -Namespace "root\cimv2" -Query "select * from Win32_Product" | Sort-Object Name | Format-Table -AutoSize -Property Name, Version, Vendor, InstallDate | Out-String -Width 400 | Out-File -FilePath ($global:resDir + "\products.txt")

  Write-Log "Collecting the list of installed hotfixes"
  Get-HotFix -ErrorAction SilentlyContinue 2>>$global:errfile | Sort-Object -Property InstalledOn -ErrorAction Ignore | Out-File $global:resDir\hotfixes.txt

  Write-Log "Collecing GPResult output"
  $cmd = "gpresult /h """ + $global:resDir + "\gpresult.html""" + $RdrErr
  write-log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

  $cmd = "gpresult /r >""" + $global:resDir + "\gpresult.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append
} else {
  Write-Log "WMI is not working"
  $proc = Get-Process | Where-Object {$_.Name -ne "Idle"}
  $proc | Format-Table -AutoSize -property id, name, @{N="WorkingSet";E={"{0:N0}" -f ($_.workingset/1kb)};a="right"},
  @{N="VM Size";E={"{0:N0}" -f ($_.VirtualMemorySize/1kb)};a="right"},
  @{N="Proc time";E={($_.TotalProcessorTime.ToString().substring(0,8))}}, @{N="Threads";E={$_.threads.count}},
  @{N="Handles";E={($_.HandleCount)}}, StartTime, Path | 
  Out-String -Width 300 | Out-File -FilePath ($global:resDir + "\processes.txt")
  CollectSystemInfoNoWMI
}

Write-Diag ("[INFO] " + $DiagVersion)

# Diag start

Write-Diag "[INFO] Checking HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\ClientAuthTrustMode"
$ClientAuthTrustMode = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel" | Select-Object -ExpandProperty "ClientAuthTrustMode" -ErrorAction SilentlyContinue)

if ($null -eq $ClientAuthTrustMode -or $ClientAuthTrustMode -eq 0) {
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
  Write-Diag ("[INFO]    SubscriptionType = " + $SubProp.SubscriptionType + ", ConfigurationMode = " + $SubProp.ConfigurationMode)
  Write-Diag ("[INFO]    MaxLatencyTime = " + (GetSubVal $sub.PSChildname "MaxLatencyTime") + ", HeartBeatInterval = " + (GetSubVal $sub.PSChildname "HeartBeatInterval"))
  
  $logFile = (GetSubVal $sub.PSChildname "LogFile")
  if ($logFile -ne "ForwardedEvents") {
    Write-Diag ("[WARNING] LogFile = " + $logFile + ", this is a CUSTOM LOG")
  } else { 
    Write-Diag ("[INFO]    LogFile = " + $logFile)
  }

  if ($SubProp.AllowedSourceDomainComputers) {
    Write-Diag "[INFO]    AllowedSourceDomainComputers"
    $ACL = (FindSep -FindIn $SubProp.AllowedSourceDomainComputers -Left ":P" -Right ")S:").replace(")(", ",").Split(",")
    foreach ($ACE in $ACL) {
      $SID = FindSep -FindIn $ACE -left ";;;"
      $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
      $group = $objSID.Translate( [System.Security.Principal.NTAccount]).Value
      Write-Diag "[INFO]       $group ($SID)"
    }
  }

  if ($SubProp.Locale) {
    if ($SubProp.Locale -eq "en-US") {
      Write-Diag "[INFO]    The subscription's locale is set to en-US"
    } else {
      Write-Diag ("[WARNING] The subscription's locale is set to " + $SubProp.Locale)
    }
  } else {
   Write-Diag "[INFO]    The subscription's locale is not set, the default locale will be used."    
  }

  if ($SubProp.AllowedSubjects) {
    $subWG = $true
    Write-Diag "[INFO]    Listed non-domain computers:"
    $list = $SubProp.AllowedSubjects -split ","
    foreach ($item in $list) {
      Write-Diag ("[INFO]    " + $item)
    }
  } else {
    Write-Diag "[INFO]    No non-domain computers listed, that's ok if this is not a collector in workgroup environment"
  }

  if ($SubProp.AllowedIssuerCAs) {
    $subWG = $true
    Write-Diag "[INFO]    Listed Issuer CAs:"
    $list = $SubProp.AllowedIssuerCAs -split ","
    foreach ($item in $list) {
      Write-Diag ("[INFO]    " + $item)
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
$HTTPListenerFound = $false
$listeners = Get-ChildItem WSMan:\localhost\Listener
foreach ($listener in $listeners) {
  Write-Diag ("[INFO] Inspecting listener " + $listener.Name)
  $prop = Get-ChildItem $listener.PSPath
  if ($listener.keys[0] -eq "Transport=HTTP") {
    $HTTPListenerFound = $true
  }
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

if ($HTTPListenerFound) {
  Write-Diag ("[INFO] HTTP listener found")
} else {
  Write-Diag ("[ERROR] The HTTP listener is missing")
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

  $MaxFwd = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding').MaxForwardingRate
  if ($MaxFwd) {
    Write-Diag ("[ERROR] HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\MaxForwardingRate is set to " + $MaxFwd + ". This functionality is broken, see Bug 33554568. Remove the setting Configure Forwarder Resource Usage from the GPO to avoid performance issues")
  }

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
    Write-Diag "[ERROR] MaxForwardingRate is configured, this feature does not work. Please remove this setting and see bug 33554568"
  }
} else {
  $isForwarder = $false
  Write-Diag "[INFO] No SubscriptionManager URL configured. It's ok if this machine is not supposed to forward events."
}

if ((Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain) {
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

  if ($OSVer -le 6.3) {
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
      if (Get-CimInstance -Query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
        Write-Diag "[INFO] The group WinRMRemoteWMIUsers__ is also present as machine local group"
      }
    } else {
      Write-Diag "[WARNING] The WinRMRemoteWMIUsers__ was not found in the domain" 
      if (Get-CimInstance -Query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
        Write-Diag "[INFO] The group WinRMRemoteWMIUsers__ is present as machine local group"
      } else {
        Write-Diag "[ERROR] The group WinRMRemoteWMIUsers__ is not even present as machine local group"
      }
    }
  }
  if ((Get-ChildItem WSMan:\localhost\Service\Auth\Kerberos).value -eq "true") {
    Write-Diag "[INFO] Kerberos authentication is enabled for the service"
  }  else {
    Write-Diag "[WARNING] Kerberos authentication is disabled for the service"
  }
} else {
  Write-Diag "[INFO] The machine is not joined to a domain"
  if (Get-CimInstance -Query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
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

$HHTPParam = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"
if (($HHTPParam.MaxFieldLength -gt 0) -and ($HHTPParam.MaxRequestBytes -gt 0)) {
  Write-Diag ("[INFO] HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\MaxFieldLength = " + $HHTPParam.MaxFieldLength)
  Write-Diag ("[INFO] HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\MaxRequestBytes = " + $HHTPParam.MaxRequestBytes)
} else {
  Write-Diag ("[WARNING] MaxFieldLength and/or MaxRequestBytes are not defined in HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters. This may cause the request to fail with error 400 in complex AD environemnts. See KB 820129")
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
        $usr = Get-CimInstance -ClassName Win32_UserAccount | Where {$_.Name -eq $value.value}
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
  $evtLogReaders = (Get-CimInstance -Query ("Associators of {Win32_Group.Domain='" + $env:COMPUTERNAME + "',Name='Event Log Readers'} where Role=GroupComponent") | Where {$_.Name -eq "NETWORK SERVICE"} | Measure-Object)
  if ($evtLogReaders.Count -gt 0) {
    Write-Diag "[INFO] The NETWORK SERVICE account is member of the Event Log Readers group"
  } else {
    Write-Diag "[WARNING] The NETWORK SERVICE account is NOT member of the Event Log Readers group, the events in the Security log cannot be forwarded"
  }
}

$fwrules = (Get-NetFirewallPortFilter -Protocol TCP | Where { $_.localport -eq "5986" } | Get-NetFirewallRule)
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

