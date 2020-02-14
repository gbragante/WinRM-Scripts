# WinRM-TraceParse - by Gianni Bragante gbrag@microsoft.com
# Version 20200214

param (
  [string]$InputFile
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

Function ToTime{
  param( [string]$time)
  return Get-Date -Year $time.Substring(6,2) -Month $time.Substring(0,2) -Day $time.Substring(3,2) -Hour $time.Substring(9,2) -Minute $time.Substring(12,2) -Second $time.Substring(15,2) -Millisecond $time.Substring(18,3)
}

$inputFile = "C:\files\WinRM\WinRM-TraceParse\winrm-trace-devdcs1-20200208-!FMT.txt"
if ($InputFile -eq "") {
  Write-Host "Trace filename not specified"
  exit
}

$lines = 0
$xmlLine = @{}
$dirName = $InputFile + "-" + $(get-date -f yyyyMMdd_HHmmss)
Write-Host $dirname
New-Item -itemtype directory -path $dirname | Out-Null

$tbEvt = New-Object system.Data.DataTable
$col = New-Object system.Data.DataColumn Time,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn PID,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Type,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn To,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Action,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Message,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Command,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn RetObj,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Bookmarks,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Items,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Dates,([string]); $tbEvt.Columns.Add($col)
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

$tbStats = New-Object system.Data.DataTable
$col = New-Object system.Data.DataColumn Server,([string]); $tbCAPI.Columns.Add($col)
$col = New-Object system.Data.DataColumn FirstPacket,([string]); $tbCAPI.Columns.Add($col)
$col = New-Object system.Data.DataColumn LastPacket,([string]); $tbCAPI.Columns.Add($col)
$col = New-Object system.Data.DataColumn SpanPkt,([string]); $tbCAPI.Columns.Add($col)
$col = New-Object system.Data.DataColumn Events,([string]); $tbCAPI.Columns.Add($col)
$col = New-Object system.Data.DataColumn EvtMinPkt,([string]); $tbCAPI.Columns.Add($col)
$col = New-Object system.Data.DataColumn EvtFirst,([string]); $tbCAPI.Columns.Add($col)
$col = New-Object system.Data.DataColumn EvtLast,([string]); $tbCAPI.Columns.Add($col)
$col = New-Object system.Data.DataColumn SpanEvt,([string]); $tbCAPI.Columns.Add($col)
$col = New-Object system.Data.DataColumn EvtMinSrv,([string]); $tbCAPI.Columns.Add($col)
$col = New-Object system.Data.DataColumn DelayStart,([string]); $tbCAPI.Columns.Add($col)
$col = New-Object system.Data.DataColumn DelayEnd,([string]); $tbCAPI.Columns.Add($col)

$dtStart = Get-Date

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
    $xmlPart = $line.Substring($nPos+8, $line.Length - $nPos - 8).TrimEnd()
    if ($xmlPart.Length -gt 1) {
      if ($xmlPart.Substring($xmlPart.Length-1, 1) -eq " ") {
        $xmlPart = $xmlPart.Substring(0,$xmlPart.Length - 1)
      }
    }

    # This is one of the SOAP lines
    if ($line -match  "index 1 of") {
      if ($xmlLine[$thread]) {
        Write-Error ("Unclosed tag for thread " + $thread + " before " + $time)
        $xmlLine.Remove($thread)
      }
      $xmlLine.Add($thread,$xmlpart)
      
      $npos=$line.IndexOf("::")
      $time = ($line.Substring($nPos + 2 , 25))
      $timeFile = $time.Substring(9).Replace(":","").Replace(".","-")
    } else {
      $xmlLine[$thread] = $xmlLine[$thread] + $xmlPart
    }
    
    # Process extra content not included in the [SOAP] line
    $line = $sr.ReadLine().TrimEnd()
    $lines = $lines + 1

    while (-not $sr.EndOfStream) {
      if ($line.Length -gt 1) {
        if (($line.Length -gt 25) -and ($line.Substring(0,25) -match "[A-Fa-f0-9]{4,5}.[A-Fa-f0-9]{4,5}::\d\d/")) { break }
        if ($line.Substring($line.Length-1, 1) -eq " ") {
          $line=$line.Substring(0, $line.Length-1)
        }
      }
      $xmlLine[$thread] = $xmlLine[$thread] + $line
      $line = $sr.ReadLine().TrimEnd()
      $lines = $lines + 1
    }

    # Closing tag detection
    #if ($xmlLine[$thread].Substring($xmlLine[$thread].Length-13) -eq "</s:Envelope>") {
    if ($xmlLine[$thread].Substring($xmlLine[$thread].Length-20) -match "</s:Envelope>") {
      $filename = "out-" + $timeFile + "-" + $msgtype + ".xml"
      $xmlLine[$thread] | Out-File -FilePath ($dirName + "\" + $FileName) 
            
      $xmlEvt = New-Object -TypeName System.Xml.XmlDocument
      $xmlPL = New-Object -TypeName System.Xml.XmlDocument
      $xmlShell = New-Object -TypeName System.Xml.XmlDocument
      $xmlT = New-Object -TypeName System.Xml.XmlDocument

      # Fixing tags broken by trimming
      $xmlLine[$thread] = $xmlLine[$thread].Replace("w:EventAction=", "w:Event Action=")
      $xmlLine[$thread] = $xmlLine[$thread].Replace("<DataName=", "<Data Name=")

      try {
        $xmlEvt.LoadXml($xmlLine[$thread])
      }
      catch {
        Write-Error $PSItem.Exception 
        Write-Error $xmlLine.Values
      }
      $xmlLine.Remove($thread)

      $row = $tbEvt.NewRow()
      $row.Time = $time
      $row.Pid = [int32]("0x" + $thread.Substring(0,$thread.IndexOf(".")))
      $row.Type = $msgtype
      $row.FileSize = (Get-Item ($dirName + "\" + $FileName)).Length
      
      $row.Message = $xmlEvt.Envelope.Body.FirstChild.LocalName
      if ($row.Message -eq "Fault") {
        $row.Message = $xmlEvt.Envelope.Body.Fault.Reason.text.'#text'
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
        $row.Items = $xmlEvt.Envelope.body.Events.Event.count

        # Get lowest and highest events date for the packet
        if ($xmlEvt.Envelope.Body.Events.FirstChild.'#cdata-section') {
          try {
            $xmlPL.LoadXml($xmlEvt.Envelope.Body.Events.FirstChild.'#cdata-section')
          }
          catch {
            Write-Error $PSItem.Exception 
            Write-Error $xmlEvt.Envelope.Body.Events.FirstChild.'#cdata-section'
          }
          $row.dates = $xmlpl.Event.System.TimeCreated.SystemTime + " - "
          $xmlPL.LoadXml($xmlEvt.Envelope.Body.Events.LastChild.'#cdata-section')
          $row.dates = $row.dates + $xmlpl.Event.System.TimeCreated.SystemTime 
          $Computer = $xmlpl.Event.System.Computer 
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
        }
        if ($xmlEvt.Envelope.Body.EnumerateResponse.EnumerationContext) {
          $row.EnumerationContext = $xmlEvt.Envelope.Body.EnumerateResponse.EnumerationContext.substring(5) 
        }
      } elseif ($row.Message -eq "Enumerate") {
        $Computer = $xmlEvt.Envelope.Header.MachineID.'#text'
        $row.Command = $xmlevt.Envelope.Header.SelectorSet.Selector.'#text' + " " +  $xmlEvt.Envelope.Body.Enumerate.Filter.'#text'
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
      } elseif ($row.Message -eq "CommandLine") {
        $row.Command = $xmlEvt.Envelope.body.CommandLine.Command
        $arg = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($xmlEvt.Envelope.Body.CommandLine.Arguments))
        $arg = $arg.Substring($arg.IndexOf("<Obj"))
        $fileshell = $dirName + "\" + $FileName.Replace("xml","shell.xml")
        $arg | Out-File -FilePath $fileshell

      } elseif ($row.Message -eq "Unsubscribe") {
        $row.Command = $xmlEvt.Envelope.Header.OptionSet.FirstChild.'#text'

      } elseif ($row.Message -eq "Shell") {
        $ShellXML = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($xmlEvt.Envelope.Body.Shell.creationXml.'#text'))
        $ShellXML = $ShellXML.Substring($ShellXML.IndexOf("<Obj"))
        $XmlShell.LoadXml($ShellXML)
        $fileshell = $dirName + "\" + $FileName.Replace("xml","shell.xml")
        $XmlShell.OuterXml | Out-File -FilePath $fileshell
        $tz = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($xmlShell.Obj.MS.BA.'#text'))
        $filetz = $dirName + "\" + $FileName.Replace("xml","tz.bin")
        $tz | Out-File -FilePath $filetz
    
      } elseif ($row.Message -eq "ReceiveResponse") {
        foreach ($stdout in $xmlEvt.Envelope.Body.ReceiveResponse.Stream) {
          $out = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($stdout.'#text'))
        }

      } elseif ($row.Message -eq "Subscribe") {
        $row.Command = $xmlEvt.Envelope.Header.OptionSet.FirstChild.'#text'
        # maybe also add the subscription details here
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
      $OpId = ($xmlEvt.Envelope.Header.OperationID.'#text').substring(5)
    } else {
      $OpId = $xmlEvt.Envelope.Header.OperationID
      if ($OpId) {
        $OpId = $OpId.substring(5)
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

    if ($relTo) {
      $aRel = $tbEvt.Select("MessageID = '" + $relTo + "'")
      $To = $aRel[0].To
      $SessID = $aRel[0].SessionID
      $ShlID = $aRel[0].ShellID
      $cmdID = $aRel[0].CommandID
      $ActID = $aRel[0].ActivityID
      $OpId = $aRel[0].OperationID
      $computer = $aRel[0].Computer
      $row.Command = $aRel[0].Command
      if (-not $row.EnumerationContext) {
        $row.EnumerationContext = $aRel[0].EnumerationContext
      }
      if ($aRel) {
        $duration = New-TimeSpan -Start (ToTime $aRel[0].Time) -End (ToTime $time)
        $row.OperationTimeout = $duration.TotalMilliseconds
      }
    } else {
      $row.OperationTimeout = $xmlEvt.Envelope.Header.OperationTimeout
    }

    $row.To = $To
    $row.Computer = $computer
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
  } elseif (($line -match  "Microsoft-Windows-CAPI2/Operational") -and -not ($line -match "SOAP \[")) {
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

    if ($filename -eq "out-163547-1381473-CAPI.xml") {
      Write-Host ""
    }

    $line = $sr.ReadLine()
    $lines = $lines + 1
  } else {
    $line = $sr.ReadLine()
    $lines = $lines + 1
  }
}

$sr.Close()

Write-Host "Exporting WinRM events to tsv"
$tbEvt | Export-Csv ($dirName + "\events-" + (Get-Item $InputFile).BaseName +".tsv") -noType -Delimiter "`t"

Write-Host "Exporting CAPI events to tsv"
$tbCAPI | Export-Csv ($dirName + "\CAPI-" + (Get-Item $InputFile).BaseName +".tsv") -noType -Delimiter "`t"

$duration = New-TimeSpan -Start $dtStart -End (Get-Date)
Write-Host "Execution completed in" $duration