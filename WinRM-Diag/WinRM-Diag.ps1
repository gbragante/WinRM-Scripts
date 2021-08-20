param( [string]$Path, [switch]$AcceptEula )
$DiagVersion = "WinRM-Diag (20210820)"
# by Gianni Bragante gbrag@microsoft.com

Function FindSep {
  param( [string]$FindIn, [string]$Left,[string]$Right )

  if ($left -eq "") {
    $Start = 0
  } else {
    $Start = $FindIn.IndexOf($Left) 
    if ($Start -gt 0 ) {
      $Start = $Start + $Left.Length
    } else {
       return ""
    }
  }

  if ($Right -eq "") {
    $End = $FindIn.Substring($Start).Length
  } else {
    $End = $FindIn.Substring($Start).IndexOf($Right)
    if ($end -le 0) {
      return ""
    }
  }
  $Found = $FindIn.Substring($Start, $End)
  return $Found
}

Function Write-Diag {
  param( [string] $msg )
  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
  Write-Host $msg
  $msg | Out-File -FilePath $diagfile -Append
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

[void][System.Reflection.Assembly]::Load('System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
[void][System.Reflection.Assembly]::Load('System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')

function ShowEULAPopup($mode)
{
    $EULA = New-Object -TypeName System.Windows.Forms.Form
    $richTextBox1 = New-Object System.Windows.Forms.RichTextBox
    $btnAcknowledge = New-Object System.Windows.Forms.Button
    $btnCancel = New-Object System.Windows.Forms.Button

    $EULA.SuspendLayout()
    $EULA.Name = "EULA"
    $EULA.Text = "Microsoft Diagnostic Tools End User License Agreement"

    $richTextBox1.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $richTextBox1.Location = New-Object System.Drawing.Point(12,12)
    $richTextBox1.Name = "richTextBox1"
    $richTextBox1.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Vertical
    $richTextBox1.Size = New-Object System.Drawing.Size(776, 397)
    $richTextBox1.TabIndex = 0
    $richTextBox1.ReadOnly=$True
    $richTextBox1.Add_LinkClicked({Start-Process -FilePath $_.LinkText})
    $richTextBox1.Rtf = @"
{\rtf1\ansi\ansicpg1252\deff0\nouicompat{\fonttbl{\f0\fswiss\fprq2\fcharset0 Segoe UI;}{\f1\fnil\fcharset0 Calibri;}{\f2\fnil\fcharset0 Microsoft Sans Serif;}}
{\colortbl ;\red0\green0\blue255;}
{\*\generator Riched20 10.0.19041}{\*\mmathPr\mdispDef1\mwrapIndent1440 }\viewkind4\uc1 
\pard\widctlpar\f0\fs19\lang1033 MICROSOFT SOFTWARE LICENSE TERMS\par
Microsoft Diagnostic Scripts and Utilities\par
\par
{\pict{\*\picprop}\wmetafile8\picw26\pich26\picwgoal32000\pichgoal15 
0100090000035000000000002700000000000400000003010800050000000b0200000000050000
000c0202000200030000001e000400000007010400040000000701040027000000410b2000cc00
010001000000000001000100000000002800000001000000010000000100010000000000000000
000000000000000000000000000000000000000000ffffff00000000ff040000002701ffff0300
00000000
}These license terms are an agreement between you and Microsoft Corporation (or one of its affiliates). IF YOU COMPLY WITH THESE LICENSE TERMS, YOU HAVE THE RIGHTS BELOW. BY USING THE SOFTWARE, YOU ACCEPT THESE TERMS.\par
{\pict{\*\picprop}\wmetafile8\picw26\pich26\picwgoal32000\pichgoal15 
0100090000035000000000002700000000000400000003010800050000000b0200000000050000
000c0202000200030000001e000400000007010400040000000701040027000000410b2000cc00
010001000000000001000100000000002800000001000000010000000100010000000000000000
000000000000000000000000000000000000000000ffffff00000000ff040000002701ffff0300
00000000
}\par
\pard 
{\pntext\f0 1.\tab}{\*\pn\pnlvlbody\pnf0\pnindent0\pnstart1\pndec{\pntxta.}}
\fi-360\li360 INSTALLATION AND USE RIGHTS. Subject to the terms and restrictions set forth in this license, Microsoft Corporation (\ldblquote Microsoft\rdblquote ) grants you (\ldblquote Customer\rdblquote  or \ldblquote you\rdblquote ) a non-exclusive, non-assignable, fully paid-up license to use and reproduce the script or utility provided under this license (the "Software"), solely for Customer\rquote s internal business purposes, to help Microsoft troubleshoot issues with one or more Microsoft products, provided that such license to the Software does not include any rights to other Microsoft technologies (such as products or services). \ldblquote Use\rdblquote  means to copy, install, execute, access, display, run or otherwise interact with the Software. \par
\pard\widctlpar\par
\pard\widctlpar\li360 You may not sublicense the Software or any use of it through distribution, network access, or otherwise. Microsoft reserves all other rights not expressly granted herein, whether by implication, estoppel or otherwise. You may not reverse engineer, decompile or disassemble the Software, or otherwise attempt to derive the source code for the Software, except and to the extent required by third party licensing terms governing use of certain open source components that may be included in the Software, or remove, minimize, block, or modify any notices of Microsoft or its suppliers in the Software. Neither you nor your representatives may use the Software provided hereunder: (i) in a way prohibited by law, regulation, governmental order or decree; (ii) to violate the rights of others; (iii) to try to gain unauthorized access to or disrupt any service, device, data, account or network; (iv) to distribute spam or malware; (v) in a way that could harm Microsoft\rquote s IT systems or impair anyone else\rquote s use of them; (vi) in any application or situation where use of the Software could lead to the death or serious bodily injury of any person, or to physical or environmental damage; or (vii) to assist, encourage or enable anyone to do any of the above.\par
\par
\pard\widctlpar\fi-360\li360 2.\tab DATA. Customer owns all rights to data that it may elect to share with Microsoft through using the Software. You can learn more about data collection and use in the help documentation and the privacy statement at {{\field{\*\fldinst{HYPERLINK https://aka.ms/privacy }}{\fldrslt{https://aka.ms/privacy\ul0\cf0}}}}\f0\fs19 . Your use of the Software operates as your consent to these practices.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 3.\tab FEEDBACK. If you give feedback about the Software to Microsoft, you grant to Microsoft, without charge, the right to use, share and commercialize your feedback in any way and for any purpose.\~ You will not provide any feedback that is subject to a license that would require Microsoft to license its software or documentation to third parties due to Microsoft including your feedback in such software or documentation. \par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 4.\tab EXPORT RESTRICTIONS. Customer must comply with all domestic and international export laws and regulations that apply to the Software, which include restrictions on destinations, end users, and end use. For further information on export restrictions, visit {{\field{\*\fldinst{HYPERLINK https://aka.ms/exporting }}{\fldrslt{https://aka.ms/exporting\ul0\cf0}}}}\f0\fs19 .\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360\qj 5.\tab REPRESENTATIONS AND WARRANTIES. Customer will comply with all applicable laws under this agreement, including in the delivery and use of all data. Customer or a designee agreeing to these terms on behalf of an entity represents and warrants that it (i) has the full power and authority to enter into and perform its obligations under this agreement, (ii) has full power and authority to bind its affiliates or organization to the terms of this agreement, and (iii) will secure the permission of the other party prior to providing any source code in a manner that would subject the other party\rquote s intellectual property to any other license terms or require the other party to distribute source code to any of its technologies.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360\qj 6.\tab DISCLAIMER OF WARRANTY. THE SOFTWARE IS PROVIDED \ldblquote AS IS,\rdblquote  WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL MICROSOFT OR ITS LICENSORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\par
\pard\widctlpar\qj\par
\pard\widctlpar\fi-360\li360\qj 7.\tab LIMITATION ON AND EXCLUSION OF DAMAGES. IF YOU HAVE ANY BASIS FOR RECOVERING DAMAGES DESPITE THE PRECEDING DISCLAIMER OF WARRANTY, YOU CAN RECOVER FROM MICROSOFT AND ITS SUPPLIERS ONLY DIRECT DAMAGES UP TO U.S. $5.00. YOU CANNOT RECOVER ANY OTHER DAMAGES, INCLUDING CONSEQUENTIAL, LOST PROFITS, SPECIAL, INDIRECT, OR INCIDENTAL DAMAGES. This limitation applies to (i) anything related to the Software, services, content (including code) on third party Internet sites, or third party applications; and (ii) claims for breach of contract, warranty, guarantee, or condition; strict liability, negligence, or other tort; or any other claim; in each case to the extent permitted by applicable law. It also applies even if Microsoft knew or should have known about the possibility of the damages. The above limitation or exclusion may not apply to you because your state, province, or country may not allow the exclusion or limitation of incidental, consequential, or other damages.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 8.\tab BINDING ARBITRATION AND CLASS ACTION WAIVER. This section applies if you live in (or, if a business, your principal place of business is in) the United States.  If you and Microsoft have a dispute, you and Microsoft agree to try for 60 days to resolve it informally. If you and Microsoft can\rquote t, you and Microsoft agree to binding individual arbitration before the American Arbitration Association under the Federal Arbitration Act (\ldblquote FAA\rdblquote ), and not to sue in court in front of a judge or jury. Instead, a neutral arbitrator will decide. Class action lawsuits, class-wide arbitrations, private attorney-general actions, and any other proceeding where someone acts in a representative capacity are not allowed; nor is combining individual proceedings without the consent of all parties. The complete Arbitration Agreement contains more terms and is at {{\field{\*\fldinst{HYPERLINK https://aka.ms/arb-agreement-4 }}{\fldrslt{https://aka.ms/arb-agreement-4\ul0\cf0}}}}\f0\fs19 . You and Microsoft agree to these terms. \par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 9.\tab LAW AND VENUE. If U.S. federal jurisdiction exists, you and Microsoft consent to exclusive jurisdiction and venue in the federal court in King County, Washington for all disputes heard in court (excluding arbitration). If not, you and Microsoft consent to exclusive jurisdiction and venue in the Superior Court of King County, Washington for all disputes heard in court (excluding arbitration).\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 10.\tab ENTIRE AGREEMENT. This agreement, and any other terms Microsoft may provide for supplements, updates, or third-party applications, is the entire agreement for the software.\par
\pard\sa200\sl276\slmult1\f1\fs22\lang9\par
\pard\f2\fs17\lang2057\par
}
"@
    $richTextBox1.BackColor = [System.Drawing.Color]::White
    $btnAcknowledge.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
    $btnAcknowledge.Location = New-Object System.Drawing.Point(544, 415)
    $btnAcknowledge.Name = "btnAcknowledge";
    $btnAcknowledge.Size = New-Object System.Drawing.Size(119, 23)
    $btnAcknowledge.TabIndex = 1
    $btnAcknowledge.Text = "Accept"
    $btnAcknowledge.UseVisualStyleBackColor = $True
    $btnAcknowledge.Add_Click({$EULA.DialogResult=[System.Windows.Forms.DialogResult]::Yes})

    $btnCancel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
    $btnCancel.Location = New-Object System.Drawing.Point(669, 415)
    $btnCancel.Name = "btnCancel"
    $btnCancel.Size = New-Object System.Drawing.Size(119, 23)
    $btnCancel.TabIndex = 2
    if($mode -ne 0)
    {
	    $btnCancel.Text = "Close"
    }
    else
    {
	    $btnCancel.Text = "Decline"
    }
    $btnCancel.UseVisualStyleBackColor = $True
    $btnCancel.Add_Click({$EULA.DialogResult=[System.Windows.Forms.DialogResult]::No})

    $EULA.AutoScaleDimensions = New-Object System.Drawing.SizeF(6.0, 13.0)
    $EULA.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font
    $EULA.ClientSize = New-Object System.Drawing.Size(800, 450)
    $EULA.Controls.Add($btnCancel)
    $EULA.Controls.Add($richTextBox1)
    if($mode -ne 0)
    {
	    $EULA.AcceptButton=$btnCancel
    }
    else
    {
        $EULA.Controls.Add($btnAcknowledge)
	    $EULA.AcceptButton=$btnAcknowledge
        $EULA.CancelButton=$btnCancel
    }
    $EULA.ResumeLayout($false)
    $EULA.Size = New-Object System.Drawing.Size(800, 650)

    Return ($EULA.ShowDialog())
}

function ShowEULAIfNeeded($toolName, $mode)
{
	$eulaRegPath = "HKCU:Software\Microsoft\CESDiagnosticTools"
	$eulaAccepted = "No"
	$eulaValue = $toolName + " EULA Accepted"
	if(Test-Path $eulaRegPath)
	{
		$eulaRegKey = Get-Item $eulaRegPath
		$eulaAccepted = $eulaRegKey.GetValue($eulaValue, "No")
	}
	else
	{
		$eulaRegKey = New-Item $eulaRegPath
	}
	if($mode -eq 2) # silent accept
	{
		$eulaAccepted = "Yes"
       		$ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
	}
	else
	{
		if($eulaAccepted -eq "No")
		{
			$eulaAccepted = ShowEULAPopup($mode)
			if($eulaAccepted -eq [System.Windows.Forms.DialogResult]::Yes)
			{
	        		$eulaAccepted = "Yes"
	        		$ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
			}
		}
	}
	return $eulaAccepted
}

$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
  Write-Output "This script needs to be run as Administrator"
  exit
}

$Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path
$resName = "WinRM-Diag-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)
$resDir = $Root + "\" + $resName
$diagfile = $resDir + "\WinRM-Diag.txt"
New-Item -itemtype directory -path $resDir | Out-Null

Write-Diag ("[INFO] " + $DiagVersion)
if ($AcceptEula) {
  Write-Diag "AcceptEula switch specified, silently continuing"
  $eulaAccepted = ShowEULAIfNeeded "WinRM-Diag" 2
} else {
  $eulaAccepted = ShowEULAIfNeeded "WinRM-Diag" 0
  if($eulaAccepted -ne "Yes") {
    Write-Diag "EULA declined, exiting"
    exit
  }
}
Write-Diag "EULA accepted, continuing"

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

Write-Diag ("[INFO] " + $DiagVersion)
Write-Diag "[INFO] Retrieving certificates from LocalMachine\My store"
GetStore "My"
Write-Diag "[INFO] Retrieving certificates from LocalMachine\CA store"
GetStore "CA"
Write-Diag "[INFO] Retrieving certificates from LocalMachine\Root store"
GetStore "Root"

Write-Diag "[INFO] Matching issuer thumbprints"
$aCert = $tbCert.Select("Store = 'My' or Store = 'CA'")
foreach ($cert in $aCert) {
  $aIssuer = $tbCert.Select("SubjectKeyIdentifier = '" + ($cert.AuthorityKeyIdentifier).tostring() + "'")
  if ($aIssuer.Count -gt 0) {
    $cert.IssuerThumbprint = ($aIssuer[0].Thumbprint).ToString()
  }
}
Write-Diag "[INFO] Exporting certificates.tsv"
$tbcert | Export-Csv ($resDir + "\certificates.tsv") -noType -Delimiter "`t"

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
    Write-Diag "[ERROR] MaxForwardingRate is configured, this feature does not work. Please remove this setting and see bug 33554568"
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

