# WinRM-TraceParse - by Gianni Bragante gbrag@microsoft.com
# Version 20230605

param (
  [string]$InputFile,
  [switch]$OneTrailingSpace
)

Function ReadLine {
  $line = ""
  while ($line.Length -le 0) {
   $line = $sr.ReadLine()
  }
  return $line
}
Function Write-Error {
  param( [string] $msg )
  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
  Write-Host $msg
  $msg | Out-File -FilePath ($dirName + "\script-errors.txt") -Append
}

Function TrimTrailing {
  param ( [string] $InputStr,
          [string] $TrimStr )

  $TrimLen = $TrimStr.Length
  if ($InputStr.Substring($InputStr.Length - $TrimLen, $TrimLen) -eq $TrimStr) {
    return $InputStr.Substring(0, $InputStr.Length - $TrimLen)
  } else {
    return $InputStr
  }
}

Function ToTime{
  param( [string]$time)
  return (Get-Date -Year (2000 + $time.Substring(6,2)) -Month $time.Substring(0,2) -Day $time.Substring(3,2) -Hour $time.Substring(9,2) -Minute $time.Substring(12,2) -Second $time.Substring(15,2) -Millisecond $time.Substring(18,3))
}

Function ToLocalTime{
  param( [string]$time)
  $UTC = Get-Date -Year $time.Substring(0,4) -Month $time.Substring(5,2) -Day $time.Substring(8,2) -Hour $time.Substring(11,2) -Minute $time.Substring(14,2) -Second $time.Substring(17,2) -Millisecond $time.Substring(20,3)
  $UTC = [System.DateTime]::SpecifyKind($UTC, [System.DateTimeKind]::Utc)
  return [System.TimeZoneInfo]::ConvertTimeFromUtc($UTC, $TZ)
}

Function LineParam {
  $npos=$line.IndexOf("::")
  $time = ($line.Substring($nPos + 2 , 25))
  $thread = $line.Substring(0,20).Replace(" ","")
  $npos = $thread.indexof("]")
  $thread = $thread.Substring($npos + 1, $thread.IndexOf("::") - $npos -1)
  $LinePid = [int32]("0x" + $thread.Substring(0,$thread.IndexOf(".")))
  $LineTid = [int32]("0x" + $thread.Substring($thread.IndexOf(".")+1))
  return @{ Time = $time; Thread = $thread; PID = $LinePid; TID = $LineTid }
}

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

Function ConvertIP {
  param( [string]$Addr)

  if ($Addr.Substring(0,4) -eq "0x02") {
    $IPAddr = ([int32]("0x" + $Addr.Substring(10,2))).ToString() + "." + ([int32]("0x" + $Addr.Substring(12,2))).ToString() + "." + ([int32]("0x" + $Addr.Substring(14,2))).ToString() + "." + ([int32]("0x" + $Addr.Substring(16,2))).ToString()
    return $IPAddr
  } else {
    return $Addr
  }
}

if ($InputFile -eq "") {
  Write-Host "Trace filename not specified"
  exit
}

$time = ""
$LineThread = ""
$LinePid = ""
$LineTid = ""

$lines = 0
$xmlLine = @{}
$dirName = $InputFile + "-" + $(get-date -f yyyyMMdd_HHmmss)
Write-Host $dirname
New-Item -itemtype directory -path $dirname | Out-Null

$tbEvt = New-Object system.Data.DataTable
$col = New-Object system.Data.DataColumn Time,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn PID,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn TID,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Type,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn To,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Action,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Message,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Command,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn RetObj,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Bookmarks,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Items,([int32]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Dates,([string]); $tbEvt.Columns.Add($col)
#$col = New-Object system.Data.DataColumn ClientIP,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Computer,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn OperationTimeout,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn EnumerationContext,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn SessionID,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn ShellID,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn CommandID,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn ActivityID,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn OperationID,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn MessageID,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn RelatesTo,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn FileName,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn FileSize,([string]); $tbEvt.Columns.Add($col)

$tbCAPI = New-Object system.Data.DataTable
$col = New-Object system.Data.DataColumn Time,([string]); $tbCAPI.Columns.Add($col)
$col = New-Object system.Data.DataColumn Operation,([string]); $tbCAPI.Columns.Add($col)
$col = New-Object system.Data.DataColumn ProcessName,([string]); $tbCAPI.Columns.Add($col)
$col = New-Object system.Data.DataColumn Result,([string]); $tbCAPI.Columns.Add($col)
$col = New-Object system.Data.DataColumn Subject,([string]); $tbCAPI.Columns.Add($col)
$col = New-Object system.Data.DataColumn FileRef,([string]); $tbCAPI.Columns.Add($col)
$col = New-Object system.Data.DataColumn URL,([string]); $tbCAPI.Columns.Add($col)
$col = New-Object system.Data.DataColumn TaskID,([string]); $tbCAPI.Columns.Add($col)
$col = New-Object system.Data.DataColumn Seq,([string]); $tbCAPI.Columns.Add($col)
$col = New-Object system.Data.DataColumn FileName,([string]); $tbCAPI.Columns.Add($col)

$tbHTTP = New-Object system.Data.DataTable
$col = New-Object system.Data.DataColumn Time,([string]); $tbHTTP.Columns.Add($col)
$col = New-Object system.Data.DataColumn SysTID,([string]); $tbHTTP.Columns.Add($col)
$col = New-Object system.Data.DataColumn AppPID,([string]); $tbHTTP.Columns.Add($col)
$col = New-Object system.Data.DataColumn AppTID,([string]); $tbHTTP.Columns.Add($col)
$col = New-Object system.Data.DataColumn RequestID,([string]); $tbHTTP.Columns.Add($col)
$col = New-Object system.Data.DataColumn ConnectionID,([string]); $tbHTTP.Columns.Add($col)
$col = New-Object system.Data.DataColumn RemoteAddress,([string]); $tbHTTP.Columns.Add($col)
$col = New-Object system.Data.DataColumn Method,([string]); $tbHTTP.Columns.Add($col)
$col = New-Object system.Data.DataColumn URI,([string]); $tbHTTP.Columns.Add($col)
$col = New-Object system.Data.DataColumn Status,([string]); $tbHTTP.Columns.Add($col)
$col = New-Object system.Data.DataColumn Duration,([string]); $tbHTTP.Columns.Add($col)

$tbStats = New-Object system.Data.DataTable
$col = New-Object system.Data.DataColumn Server,([string]); $tbStats.Columns.Add($col)
$col = New-Object system.Data.DataColumn FirstPacket,([datetime]); $tbStats.Columns.Add($col)
$col = New-Object system.Data.DataColumn LastPacket,([datetime]); $tbStats.Columns.Add($col)
$col = New-Object system.Data.DataColumn SpanPkt,([string]); $tbStats.Columns.Add($col)
$col = New-Object system.Data.DataColumn Pckts,([int32]); $tbStats.Columns.Add($col)
$col = New-Object system.Data.DataColumn Events,([int32]); $tbStats.Columns.Add($col)
$col = New-Object system.Data.DataColumn EvtSecPkt,([string]); $tbStats.Columns.Add($col)
$col = New-Object system.Data.DataColumn EvtFirst,([datetime]); $tbStats.Columns.Add($col)
$col = New-Object system.Data.DataColumn EvtLast,([datetime]); $tbStats.Columns.Add($col)
$col = New-Object system.Data.DataColumn SpanEvt,([string]); $tbStats.Columns.Add($col)
$col = New-Object system.Data.DataColumn EvtSecSrv,([string]); $tbStats.Columns.Add($col)
$col = New-Object system.Data.DataColumn DelayStart,([string]); $tbStats.Columns.Add($col)
$col = New-Object system.Data.DataColumn DelayEnd,([string]); $tbStats.Columns.Add($col)
$col = New-Object system.Data.DataColumn PktPrc,([long]); $tbStats.Columns.Add($col)
$col = New-Object system.Data.DataColumn AvgmsPkt,([long]); $tbStats.Columns.Add($col)

if ($OneTrailingSpace) {
  $TrimStr = " "
} else {
  $TrimStr = "  "
}
$TotEvents = 0
$TotPkt = 0
$nErrors = 0
$maxErrors = 10
$dtStart = Get-Date
$TZName = (Get-WmiObject win32_timezone).StandardName
$TZ = [System.TimeZoneInfo]::FindSystemTimeZoneById($TZName)

$sr = new-object System.io.streamreader(get-item $InputFile)
$line = $sr.ReadLine()
$lines = $lines + 1
while (-not $sr.EndOfStream) {
  if ($line -match  "\] SOAP \[") {
    $thread = $line.Substring(0,20).Replace(" ","")
    $npos = $thread.indexof("]")
    $thread = $thread.Substring($npos + 1, $thread.IndexOf("::") - $npos -1)
    if ($line -match  "client sending index") { 
        $msgtype = "CS"
    } else {
      if ($line -match  "client receiving index") { 
        $msgtype = "CR" 
      } else {
        if ($line -match  "client receiving index") { 
          $msgtype = "CR" 
        } else {
          if ($line -match  "listener receiving index") { 
            $msgtype = "LR" 
          } else {
            if ($line -match  "listener sending index") { 
              $msgtype = "LS" 
            } else { 
              $msgtype = "NA" 
            }
          }
        }
      }
    }

    $nPos = $line.IndexOf("bytes)] ")
    $xmlPart = $line.Substring($nPos+8, $line.Length - $nPos - 8)
    if ($xmlPart.Length -gt 1) {
      $xmlPart = (TrimTrailing $xmlPart $TrimStr)
    }
    $chunkIndex = (FindSep -FindIn $line -Left "index " -right " total").Split(" ")

    # This is one of the SOAP lines
    # if ($line -match  "index 1 of") {
    if ($chunkIndex[0] -eq 1) {
      if ($xmlLine[$thread]) {
        Write-Error ("Unclosed tag for thread " + $thread + " before " + $time)
        $xmlLine.Remove($thread)
      }
      $sb = [System.Text.StringBuilder]::new()
      [void]$sb.Append($xmlpart) 
      $xmlLine.Add($thread,$sb)
      #sb $xmlLine.Add($thread,$xmlpart)
      
      $npos=$line.IndexOf("::")
      $time = ($line.Substring($nPos + 2 , 25))
      $timeFile = $time.Substring(9).Replace(":","").Replace(".","-")
    } else {
      if ($xmlLine[$thread]) {
        #sb $xmlLine[$thread] = $xmlLine[$thread] + $xmlPart
        [void]$xmlLine[$thread].Append($xmlPart)
      } else {
        # We missed the initial index, ignoring the entire conversation
        $line = $sr.ReadLine()
        Continue
      }
    }
 
    # Process extra content not included in the [SOAP] line
    $line = $sr.ReadLine()
    $lines = $lines + 1

    while (-not $sr.EndOfStream) {
      if ($line.Length -gt 1) {
        if (($line.Length -gt 25) -and ($line.Substring(0,25) -match "[A-Fa-f0-9]{4,5}.[A-Fa-f0-9]{4,5}::")) { break }  # If this is a trace line and not extra content it will treat this appropriately
        $xmlPart = (TrimTrailing $line $TrimStr)
        #sb $xmlLine[$thread] = $xmlLine[$thread] + $xmlPart
        [void]$xmlLine[$thread].Append($xmlPart) 
      }
      
      $line = $sr.ReadLine()
      $lines = $lines + 1
    }

    # Closing tag detection
    # if (($xmlLine[$thread].Substring($xmlLine[$thread].Length-20) -match "</s:Envelope>") -or ($xmlLine[$thread].Substring($xmlLine[$thread].Length-20) -match "</env:Envelope>")) {
    if ($chunkIndex[0] -eq $chunkIndex[2]) {
      $filename = "out-" + $timeFile + "-" + $msgtype + ".xml"

      # Trimming the lines containing two SOAP packets
      # I don't understand why it happens but it happens. We cannot load two envelopes in the same xml document so discarding the second envelope for now
      # 20210304 This has to be fixed because it is not always true: sometimes the two packets are the same level, other times they are nested.
      # When they are nested it is ok, for example for subscriptions
      # When there are two packet in the same SOAP envelope they are often related to the same operation, so it is ok to discard the second.

      #sb if (-not $xmlLine[$thread] -match "EnumerateResponse") {
      $xmlPkt = $xmlLine[$thread].ToString()
      if (-not $xmlPkt -match "EnumerateResponse") {
        #sb $ClosePos = $xmlLine[$thread].IndexOf("</s:Envelope>")
        $ClosePos = $xmlPkt.IndexOf("</s:Envelope>")
        if ($ClosePos) {
          if ($ClosePos + 13 -ne $xmlPkt.Length) {
            $xmlPkt = $xmlPkt.Substring(0, $ClosePos + 13)
          }
        }
      }

      $xmlPkt | Out-File -FilePath ($dirName + "\" + $FileName) 

      $xmlEvt = New-Object -TypeName System.Xml.XmlDocument
      $xmlPL = New-Object -TypeName System.Xml.XmlDocument
      $xmlShell = New-Object -TypeName System.Xml.XmlDocument
      $xmlT = New-Object -TypeName System.Xml.XmlDocument

      try {
        $xmlEvt.LoadXml($xmlPkt)
        $TotPkt++
      }
      catch {
        Write-Error $PSItem.Exception 
        Write-Error $xmlLine.Values
        $nErrors++
      }
      $xmlLine.Remove($thread)

      $row = $tbEvt.NewRow()
      $row.Time = $time
      $row.Pid = [int32]("0x" + $thread.Substring(0,$thread.IndexOf(".")))
      $row.Tid = [int32]("0x" + $thread.Substring($thread.IndexOf(".")+1))
      $row.Type = $msgtype
      $row.FileSize = (Get-Item ($dirName + "\" + $FileName)).Length
      
      if ($xmlEvt.Envelope.Body.FirstChild.LocalName) {
        $row.Message = $xmlEvt.Envelope.Body.FirstChild.LocalName
        if ($row.Message -eq "Fault") {
          $row.Message = $xmlEvt.Envelope.Body.Fault.Reason.text.'#text'
        }
      } else {
        if ($xmlEvt.Envelope.Header.Action.'#text') {
          $row.Message = ($xmlEvt.Envelope.Header.Action.'#text'| Split-Path -Leaf)
        } else {
          $row.Message = ($xmlEvt.Envelope.Header.Action | Split-Path -Leaf)
        }
      }

      if ($xmlEvt.Envelope.Header.MessageID.HasAttributes) {
        $msgId = ($xmlEvt.Envelope.Header.MessageID.'#text').substring(5)
      } else {
        $msgId = $xmlEvt.Envelope.Header.MessageID
        if ($msgId) {
          $msgId = $msgId.substring(5)
        }
      }

      $blist = ""
      $computer = ""
      if ($row.Message -eq "Events") {
        foreach ($bookmark in $xmlEvt.Envelope.Header.Bookmark.BookmarkList.Bookmark) {
          $blist += $bookmark.Channel + " = " + $bookmark.RecordId + " "
        }
        $row.Bookmarks = $blist
        if ($xmlEvt.Envelope.body.Events.Event.count) {
          $row.Items = $xmlEvt.Envelope.body.Events.Event.count
          $TotEvents += $row.Items
        } else {
          $row.Items = 1
        }

        # Get lowest and highest events date for the packet
        if ($xmlEvt.Envelope.Body.Events.FirstChild.'#cdata-section') {
          try {
            $xmlPL.LoadXml($xmlEvt.Envelope.Body.Events.FirstChild.'#cdata-section')
          }
          catch {
            Write-Error $PSItem.Exception 
            Write-Error $xmlEvt.Envelope.Body.Events.FirstChild.'#cdata-section'
            $nErrors++
          }
          $evtFirst = $xmlpl.Event.System.TimeCreated.SystemTime
          $row.dates = $evtFirst + " - "

          try {
            $xmlPL.LoadXml($xmlEvt.Envelope.Body.Events.LastChild.'#cdata-section')
          }
          catch {
            Write-Error $PSItem.Exception 
            Write-Error $xmlEvt.Envelope.Body.Events.LastChild.'#cdata-section'
            $nErrors++
          }
          $evtLast = $xmlpl.Event.System.TimeCreated.SystemTime
          $row.dates = $row.dates + $evtLast
          $Computer = $xmlpl.Event.System.Computer 

          # Update the statistics
          $aSrv = $tbStats.Select("Server = '" + $Computer + "'")        
          if ($aSrv.Count -eq 0) { 
            $rowStats = $tbStats.NewRow()
            $rowStats.Server = $Computer
            $rowStats.FirstPacket = ToTime $time
            $rowStats.LastPacket = $rowStats.FirstPacket
            $rowStats.Pckts = 1
            $rowStats.Events = $row.Items
            $rowStats.EvtFirst = ToLocalTime $evtFirst
            $rowStats.EvtLast = ToLocalTime $evtLast
            $rowStats.PktPrc = 0
            $tbStats.Rows.Add($rowStats)
          } else {
            $aSrv[0].LastPacket = ToTime $time
            $aSrv[0].Pckts = $aSrv[0].Pckts + 1
            $aSrv[0].Events = $aSrv[0].Events + $row.Items
            $aSrv[0].EvtLast = ToLocalTime $evtLast
          }          
        }

      } elseif ($row.Message -eq "EnumerateResponse") {
        if ($xmlEvt.Envelope.body.EnumerateResponse.Items.FirstChild.Name -eq "m:Subscription") {
          $row.Items = $xmlEvt.Envelope.body.EnumerateResponse.Items.ChildNodes.Count
          $filesub = $dirName + "\" + $FileName.Replace("xml","subscriptions.txt")
          foreach ($sub in $xmlEvt.Envelope.body.EnumerateResponse.Items.ChildNodes) {
            $sub.Envelope.Header.OptionSet.Option[0].'#text' | Out-File $filesub -Append #Subscription name
            $sub.Envelope.Body.Subscribe.EndTo.Address | Out-File $filesub -Append #Subscription address
  
            foreach ($qry in $sub.Envelope.Body.Subscribe.filter.QueryList) {
              $qry.Query.InnerXml | Out-File $filesub -Append
            }
  
            foreach ($bm in $sub.Envelope.Body.Subscribe.Bookmark.BookmarkList.Bookmark) {
              $bm.Channel + " = " + $bm.RecordId | Out-File $filesub -Append
            }
            "" | Out-File $filesub -Append
          }
        } elseif ($xmlEvt.Envelope.body.EnumerateResponse.Items.FirstChild.Name -eq "w:Item") {
          $row.Items = $xmlEvt.Envelope.body.EnumerateResponse.Items.ChildNodes.Count
          if ($xmlEvt.Envelope.Body.EnumerateResponse.EnumerationContext) {
            $row.EnumerationContext = $xmlEvt.Envelope.Body.EnumerateResponse.EnumerationContext.substring(5) 
            $aRel = $tbEvt.Select("MessageID = '" + $xmlEvt.Envelope.Header.RelatesTo.substring(5) + "'")
            $aRel[0].EnumerationContext = $row.EnumerationContext
          }
        }

      } elseif ($row.Message -eq "Enumerate") {
        $Computer = $xmlEvt.Envelope.Header.MachineID.'#text'
        $row.Command = $xmlevt.Envelope.Header.SelectorSet.Selector.'#text' + " " +  $xmlEvt.Envelope.Body.Enumerate.Filter.'#text'
        $row.RetObj = $xmlEvt.Envelope.Header.ResourceURI.'#text'.substring($xmlEvt.Envelope.Header.ResourceURI.'#text'.LastIndexOf("/")+1)

      } elseif ($row.Message -eq "Pull") {
        if ($xmlEvt.Envelope.Header.SelectorSet.Selector.Name -eq "__cimnamespace") {
          $row.Command = $xmlevt.Envelope.Header.SelectorSet.Selector.'#text'
          if ($xmlEvt.Envelope.Body.Pull.EnumerationContext.'#text') {
            $row.EnumerationContext = $xmlEvt.Envelope.Body.Pull.EnumerationContext.'#text'.Substring(5)
          }
        } elseif ($row.Command = $xmlEvt.Envelope.Header.OptionSet.FirstChild.'#text') {
          $row.Command = $xmlEvt.Envelope.Header.OptionSet.FirstChild.'#text'
        } 

      } elseif ($row.Message -eq "PullResponse") {
        $row.RetObj = $xmlEvt.Envelope.Body.PullResponse.Items.FirstChild.FirstChild.name
        $row.Items = $xmlEvt.Envelope.body.PullResponse.Items.ChildNodes.Count
        if ($xmlEvt.Envelope.Body.PullResponse.EnumerationContext) {
          $row.EnumerationContext = $xmlEvt.Envelope.Body.PullResponse.EnumerationContext.Substring(5)
        }
        if ($row.Items -gt 0) {
          $objName = $row.RetObj.Replace("p:","")
          $fileCSV = $dirName + "\" + $FileName.Replace("xml", $objName + ".csv")
          $ColNames = ""
          ForEach ($RetCol in $xmlEvt.Envelope.body.PullResponse.Items.ChildNodes[0].FirstChild.ChildNodes) {
            $ColNames += ("""" + $RetCol.Name.replace("p:","") + """,")
          }
          $ColNames = $ColNames.Substring(0,$ColNames.Length-1)
          $ColNames | Out-File -FilePath $fileCSV

          if ($xmlEvt.Envelope.body.PullResponse.Items.ChildNodes[0].FirstChild.ChildNodes[0].ReferenceParameters) {
            ForEach ($resrow in $xmlEvt.Envelope.body.PullResponse.Items.ChildNodes) {
              $rowval = ""
              ForEach ($colval in $resrow.FirstChild.ChildNodes) {
                $rowval += ("""" + $colval.ReferenceParameters.SelectorSet.FirstChild.'#text' + """,")
              }
              $rowval | Out-File -FilePath $fileCSV -Append
            }
          } else {
            ForEach ($resrow in $xmlEvt.Envelope.body.PullResponse.Items.ChildNodes) {
              $rowval = ""
              ForEach ($colval in $resrow.FirstChild.ChildNodes) {
                $rowval += ("""" + $colval.'#text' + """,")
              }
              $rowval | Out-File -FilePath $fileCSV -Append
            }
          }
        } 
      } elseif ($row.Message -eq "Release") {
        if ($xmlEvt.Envelope.Body.Release.EnumerationContext) {
          $row.EnumerationContext = $xmlEvt.Envelope.Body.Release.EnumerationContext.'#text'.Substring(5)
        }

      } elseif ($row.Message -eq "ReleaseResponse") {
        $row.EnumerationContext = $row.EnumerationContext  # we just want to leave EnumerationContext empty to up updated later from the RelatedTo

      } elseif ($row.Message -eq "CommandLine") {
        $row.Command = $xmlEvt.Envelope.body.CommandLine.Command
        if (($xmlEvt.Envelope.Body.CommandLine.Arguments) -and ($xmlEvt.Envelope.Body.CommandLine.Arguments -match "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$")) {
          $arg = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($xmlEvt.Envelope.Body.CommandLine.Arguments))
          $arg = $arg.Substring($arg.IndexOf("<Obj"))
        } else {
          $arg = $xmlEvt.Envelope.body.CommandLine.Command
        }
        $fileshell = $dirName + "\" + $FileName.Replace("xml","shell.xml")
        $arg | Out-File -FilePath $fileshell

      } elseif ($row.Message -eq "Unsubscribe") {
        $row.Command = $xmlEvt.Envelope.Header.OptionSet.FirstChild.'#text'

      } elseif ($row.Message -eq "Shell") {
        $ShellXML = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($xmlEvt.Envelope.Body.Shell.creationXml.'#text'))
        if ($ShellXML) {
          $ShellXML = $ShellXML.Substring($ShellXML.IndexOf("<Obj"))
          $XmlShell.LoadXml($ShellXML)
          $fileshell = $dirName + "\" + $FileName.Replace("xml","shell.xml")
          $XmlShell.OuterXml | Out-File -FilePath $fileshell
          $tz = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($xmlShell.Obj.MS.BA.'#text'))
          $filetz = $dirName + "\" + $FileName.Replace("xml","tz.bin")
          $tz | Out-File -FilePath $filetz
        }    
      } elseif ($row.Message -eq "ReceiveResponse") {
        foreach ($stdout in $xmlEvt.Envelope.Body.ReceiveResponse.Stream) {
          $out = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($stdout.'#text'))
        }

      } elseif ($row.Message -eq "Subscribe") {
        $row.Command = $xmlEvt.Envelope.Header.OptionSet.FirstChild.'#text'
        # maybe also add the subscription details here

      } elseif ($row.Message -eq "TestConfiguration_INPUT") {
        $ShellXML = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($xmlEvt.Envelope.Body.TestConfiguration_INPUT.ConfigurationData.'#text'))
        if ($ShellXML) {
          $fileshell = $dirName + "\" + $FileName.Replace("xml","DSCTest.txt")
          $ShellXML | Out-File -FilePath $fileshell -Encoding ascii
        }

      } elseif ($row.Message -eq "InteractiveEvent") {
        $row.RetObj = $xmlEvt.Envelope.Body.InteractiveEvent.Name
        $row.Items = $xmlEvt.Envelope.Body.InteractiveEvent.Value.ChildNodes.Count
        $row.Command = $xmlEvt.Envelope.Body.InteractiveEvent.EventType + " - " + $xmlEvt.Envelope.Body.InteractiveEvent.Description
        if ($row.Items -gt 0) {
          $fileCSV = $dirName + "\" + $FileName.Replace("xml", $row.RetObj + ".csv")
          $ColNames = ""
          ForEach ($RetCol in $xmlEvt.Envelope.Body.InteractiveEvent.Value.FirstChild.ChildNodes) {
            $ColNames += ("""" + $RetCol.Name.replace("p1:","") + """,")
          }
          $ColNames = $ColNames.Substring(0,$ColNames.Length-1)
          $ColNames | Out-File -FilePath $fileCSV

          ForEach ($resrow in $xmlEvt.Envelope.Body.InteractiveEvent.Value.ChildNodes) {
            $rowval = ""
            ForEach ($colval in $resrow.ChildNodes) {
              $rowval += ("""" + $colval.'#text' + """,")
            }
            $rowval | Out-File -FilePath $fileCSV -Append
          }
        } 

      } elseif ($row.Message -eq "ApplyConfiguration_INPUT") {
        $row.Message = $row.Message  # We just want to leave $row.Command Null

      } elseif ($xmlEvt.Envelope.Header.ResourceURI.'#text') {
        if ($xmlEvt.Envelope.Header.ResourceURI.'#text'.IndexOf("cim-schema") -gt 0) {
          $cmdWMI = ""
          foreach ($sel in $xmlEvt.Envelope.Header.SelectorSet.Selector) {
            $cmdWMI = $cmdWMI + $sel.'#text' + " "
          }
          $row.Command = $cmdWMI
        }
      }
    
    if ($xmlEvt.Envelope.Header.Action.HasAttributes) {
      $row.Action = $xmlEvt.Envelope.Header.Action.'#text'
    } else {
      $row.Action = $xmlEvt.Envelope.Header.Action
    }

    if ($xmlEvt.Envelope.Header.RelatesTo.HasAttributes) {
      $relTo = ($xmlEvt.Envelope.Header.RelatesTo.'#text').substring(5)
    } else {
      $relTo = $xmlEvt.Envelope.Header.RelatesTo
      if ($relTo) {
        $relTo = $relTo.substring(5)
      }
    }
      
    if ($xmlEvt.Envelope.Header.OperationID.HasAttributes) {
      $OpId = ($xmlEvt.Envelope.Header.OperationID.'#text').substring(5).Replace("uuid:","")  # Some lines contains "uuid:uuid:"
    } else {
      $OpId = $xmlEvt.Envelope.Header.OperationID
      if ($OpId) {
        $OpId = $OpId.substring(5).Replace("uuid:","")  # Some lines contains "uuid:uuid:"
      }
    }

    if ($xmlEvt.Envelope.Header.SessionID) {
      if ($xmlEvt.Envelope.Header.SessionID.HasAttributes) {
        $SessID = ($xmlEvt.Envelope.Header.SessionID.'#text').substring(5)
      } else {
        $SessID = ($xmlEvt.Envelope.Header.SessionID).substring(5)
      }
    } else {
      $SessID = ""
    }

    $ShlID = ""
    if ($xmlEvt.Envelope.Header.SelectorSet.Selector.Name) {
      if ($xmlEvt.Envelope.Header.SelectorSet.Selector.Name -eq "ShellID") {
        $ShlID = $xmlEvt.Envelope.Header.SelectorSet.Selector.'#text'
      }
    } elseif ($xmlEvt.Envelope.Body.Shell.ShellId) {
      $ShlID = $xmlEvt.Envelope.Body.Shell.ShellId
    }

    $cmdID = ""
    if ($ShlID) {
      if ($xmlEvt.Envelope.Body.Receive.DesiredStream.CommandId) {
        $cmdID = $xmlEvt.Envelope.Body.Receive.DesiredStream.CommandId
      } elseif ($xmlEvt.Envelope.Body.CommandLine.CommandId) {
        $cmdID = $xmlEvt.Envelope.Body.CommandLine.CommandId
      } elseif ($xmlEvt.Envelope.Body.Signal.CommandId) {
        $cmdID = $xmlEvt.Envelope.Body.Signal.CommandId
        $row.Command = ($xmlEvt.Envelope.Body.Signal.Code).Replace("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/","")
      }
    }

    if ($xmlEvt.Envelope.Header.ActivityID) {
      if ($xmlEvt.Envelope.Header.ActivityID.HasAttributes) {
        $ActID = ($xmlEvt.Envelope.Header.ActivityID.'#text').substring(5)
      } else {
        $ActID = ($xmlEvt.Envelope.Header.ActivityID).substring(5)
      }
    } else {
      $ActID = ""
    }

    $To = $xmlEvt.Envelope.Header.To

    if ($relTo) {  # Completing the response packet with information from the request packet
      $aRel = $tbEvt.Select("MessageID = '" + $relTo + "'")
      if ($aRel) {
        $To = $aRel[0].To
        $SessID = $aRel[0].SessionID
        $ShlID = $aRel[0].ShellID
        $cmdID = $aRel[0].CommandID
        $ActID = $aRel[0].ActivityID
        $OpId = $aRel[0].OperationID
        $computer = $aRel[0].Computer
        if (($aRel[0].Command.GetType()).Name -ne "DBNull") {
          $row.Command = $aRel[0].Command
        }

        if ($row.EnumerationContext.GetType().Name -eq "DBNull") {
          $row.EnumerationContext = $aRel[0].EnumerationContext
        }

        $duration = New-TimeSpan -Start (ToTime $aRel[0].Time) -End (ToTime $time)
        $row.OperationTimeout = $duration.TotalMilliseconds
        $aStats = $tbStats.Select("Server = '" + $Computer + "'")
        if ($aStats) {
          $aStats[0].PktPrc += $duration.TotalMilliseconds
        }
      }
    } else {
      $row.OperationTimeout = $xmlEvt.Envelope.Header.OperationTimeout
    }

    # 20220228 Tried to correlate the information in tbHTTP but it does not seem to work
    # if ($row.Type -eq "LR") {
    #   $aIP = $tbHTTP.select("AppPID = " + $row.PID + " and AppTID = " + $row.TID + "and URI = '" + $To + "'", "Time Desc")
    #   if ($aIP) {
    #     $ClientIP = $aIP[0].RemoteAddress
    #   } else {
    #     $ClientIP = $aIP[0].RemoteAddress
    #   }
    # } else {
    #   $ClientIP = $aIP[0].RemoteAddress
    # }

    $row.To = $To
    $row.Computer = $computer
    #$row.ClientIP = $ClientIP
    $row.MessageID = $msgId
    $row.RelatesTo = $relTo
    $row.SessionID = $SessId
    $row.ShellID = $ShlID
    $row.CommandID = $cmdID
    $row.ActivityID = $ActId
    $row.OperationID = $OpId
    $row.FileName = $FileName
    $tbEvt.Rows.Add($row)

    Write-Host $lines $thread $time $To $row.Action

    }
  } elseif ((($line -match  "Microsoft-Windows-CAPI2/Operational") -or ($line -match  "Microsoft_Windows_CAPI2/Operational") ) -and -not ($line -match "SOAP \[")) {
    $npos=$line.IndexOf("::")
    $time = ($line.Substring($nPos + 2 , 25))
    $timeFile = $time.Substring(9).Replace(":","").Replace(".","-")
    $xmlLineCAPI = $line.Substring($line.indexof("<"))
    $filename = "out-" + $timeFile + "-CAPI.xml"
    $xmlLineCAPI | Out-File -FilePath ($dirName + "\" + $FileName) 

    $xmlCAPI = New-Object -TypeName System.Xml.XmlDocument
    $xmlCAPI.LoadXml($xmlLineCAPI) 

    $rowCAPI = $tbCAPI.NewRow()
    $rowCAPI.Time = $time
    $rowCAPI.Operation = $xmlLineCAPI.Substring(1,$xmlLineCAPI.IndexOf(">")-1)
    $rowCAPI.ProcessName = $xmlCAPI.FirstChild.EventAuxInfo.ProcessName
    $rowCAPI.TaskID = $xmlCAPI.FirstChild.CorrelationAuxInfo.TaskId
    $rowCAPI.Seq = $xmlCAPI.FirstChild.CorrelationAuxInfo.SeqNumber
    $rowCAPI.FileName = $filename

    Write-Host $time $rowCAPI.Operation

    if ($xmlCAPI.FirstChild.Certificate) {
      if ($xmlCAPI.FirstChild.Certificate.Count -gt 1) {
        $rowCAPI.Subject = $xmlCAPI.FirstChild.Certificate[0].subjectName
        $rowCAPI.FileRef = $xmlCAPI.FirstChild.Certificate[0].fileRef
      } else {
        $rowCAPI.Subject = $xmlCAPI.FirstChild.Certificate.subjectName
        $rowCAPI.FileRef = $xmlCAPI.FirstChild.Certificate.fileRef
      }
    }

    if ($xmlCAPI.FirstChild.URL) {
      $rowCAPI.URL = $xmlCAPI.FirstChild.URL.'#text'
    }

    if ($xmlCAPI.FirstChild.Result) {
      $rowCAPI.Result = $xmlCAPI.FirstChild.Result.value
    }
    $tbCAPI.Rows.Add($rowCAPI)

    $line = $sr.ReadLine()
    $lines = $lines + 1
  } elseif (($line -match  "HTTPServiceChannel16 ") -or ($line -match  "HTTP Service Channel")-and -not ($line -match "SOAP \[")) {
    if ($line -match "Request received") {
      $LP = LineParam
      $rowHTTP = $tbHTTP.NewRow()
      $rowHTTP.Time = $LP.Time
      $rowHTTP.SysTID = $LP.TID
      $rowHTTP.RequestID = ":" + (FindSep -FindIn $line -Left "(request ID " -Right ")")
      $rowHTTP.ConnectionID = ":" + (FindSep -FindIn $line -Left "(connection ID " -Right ")")
      $rowHTTP.RemoteAddress = ConvertIP (FindSep -FindIn $line -Left "from remote address " -Right ". ")
      $tbHTTP.Rows.Add($rowHTTP)

    } elseif ($line -match "Delivered request to server application") {
      $reqID = ":" + (FindSep -FindIn $line -Left "request ID " -Right ",")
      $aHTTP = $tbHTTP.Select("RequestID = '" + $reqID + "'")        
      if ($aHTTP.Count -gt 0) { 
        $aHTTP[0].URI = FindSep -FindIn $line -Left "for URI " -Right " with"
      }
    } elseif ($line -match "Server application passed response") {
      $reqID = ":" + (FindSep -FindIn $line -Left "(request ID " -Right ",")
      $aHTTP = $tbHTTP.Select("RequestID = '" + $reqID + "'")        
      if ($aHTTP.Count -gt 0) { 
        Write-Host $line
        $LP = LineParam
        $aHTTP[0].AppPID = $LP.PID
        $aHTTP[0].AppTID = $LP.TID
        $aHTTP[0].Method = FindSep -FindIn $line -Left ", method " -Right ", "
        $aHTTP[0].Status = FindSep -FindIn $line -Left "status code " -Right "."
        $duration = New-TimeSpan -Start (ToTime $aHTTP[0].Time) -End (ToTime $LP.Time)
        $aHTTP[0].Duration = $duration.TotalMilliseconds
      }
    }

    $line = $sr.ReadLine()
    $lines = $lines + 1

  } elseif ($line -match  "CRequestContext::GetFaultXMLPrivate()") {
    $faultxml = FindSep $line -Left "fault string: "
    if ($faultxml) {
      $xmlFault = New-Object -TypeName System.Xml.XmlDocument
      $xmlFault.LoadXml($faultxml)
      $LP = LineParam

      $filename = "out-" + $LP.time.Substring(9).Replace(":","").Replace(".","-") + "-FT.xml" 
      $faultxml | Out-File -FilePath ($dirName + "\" + $FileName) 

      $row = $tbEvt.NewRow()
      $row.Time = $LP.Time
      $row.Pid = $LP.PID
      $row.Tid = $LP.TID
      $row.Type = "FT"
      $row.Action = $xmlFault.WSManFault.f
      $row.Computer = $xmlfault.WSManFault.Machine
      $row.FileName = $filename
      $row.FileSize = $faultxml.Length

      if ($xmlfault.WSManFault.Message.ProviderFault) {
        $row.Message = $xmlfault.WSManFault.Message.ProviderFault.WSManFault.Code + " - " + $xmlfault.WSManFault.Message.ProviderFault.provider + " - " + $xmlfault.WSManFault.Message.ProviderFault.WSManFault.Message
      } else {
        $row.Message = $xmlfault.WSManFault.Code + " - " + $xmlfault.WSManFault.Message
      }

      $tbEvt.Rows.Add($row)
    }

    $line = $sr.ReadLine()
    $lines = $lines + 1

  } else {
    $line = $sr.ReadLine()
    $lines = $lines + 1
  }

  if ($nErrors -gt $maxErrors) {
    if ($TrimStr -eq "  ") {
      Write-Host "Too many errors, trying again with one trailing space"
      $TrimStr = " "
      $nErrors = 0
      $sr.Close()
      $sr = new-object System.io.streamreader(get-item $InputFile)
      $line = $sr.ReadLine()
      $lines = 1
      Remove-Item $dirName -Recurse
      $dirName = $InputFile + "-" + $(get-date -f yyyyMMdd_HHmmss)
      New-Item -itemtype directory -path $dirname | Out-Null
    }
  }
}

$sr.Close()

$nRow = 0
foreach ($row in $tbStats.Rows) {
  $SpanPkt = New-TimeSpan -Start $row.FirstPacket -End $row.LastPacket
  $tbStats.Rows[$nRow].SpanPkt = $SpanPkt.ToString().Substring(0,8)
  $SpanEvt = New-TimeSpan -Start $row.EvtFirst -End $row.EvtLast
  $tbStats.Rows[$nRow].SpanEvt = $SpanEvt.ToString().Substring(0,8)
  $tbStats.Rows[$nRow].DelayStart = ("{0:g}" -f (New-TimeSpan -Start $row.EvtFirst -End $row.FirstPacket))
  $tbStats.Rows[$nRow].DelayEnd = ("{0:g}" -f (New-TimeSpan -Start $row.EvtLast -End $row.LastPacket))
  $tbStats.Rows[$nRow].EvtSecPkt = [math]::Round($row.Events / $SpanPkt.TotalSeconds)
  $tbStats.Rows[$nRow].EvtSecSrv = [math]::Round($row.Events / $SpanEvt.TotalSeconds)
  $tbStats.Rows[$nRow].AvgmsPkt = [math]::Round($row.PktPrc / $row.Pckts)
  $nRow++
}

Write-Host "Exporting WinRM events to tsv"
$tbEvt | Export-Csv ($dirName + "\events-" + (Get-Item $InputFile).BaseName +".tsv") -noType -Delimiter "`t"

Write-Host "Exporting CAPI events to tsv"
$tbCAPI | Export-Csv ($dirName + "\CAPI-" + (Get-Item $InputFile).BaseName +".tsv") -noType -Delimiter "`t"

Write-Host "Exporting event statistics to tsv"
$tbStats | Export-Csv ($dirName + "\EvtStats-" + (Get-Item $InputFile).BaseName +".tsv") -noType -Delimiter "`t"

Write-Host "Exporting HTTP events to tsv"
$tbHTTP | Export-Csv ($dirName + "\HTTP-" + (Get-Item $InputFile).BaseName +".tsv") -noType -Delimiter "`t"

$duration = New-TimeSpan -Start $dtStart -End (Get-Date)
Write-Host "Execution completed in" $duration
Write-host ("Trace parser performance: " + ($TotEvents / $duration.TotalSeconds) + " evt/sec, " + ($TotPkt / $duration.TotalSeconds) + " pkt/sec")