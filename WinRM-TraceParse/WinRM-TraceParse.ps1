# WinRM-TraceParse - 20180703

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
$col = New-Object system.Data.DataColumn Type,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn To,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Action,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Message,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Command,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Bookmarks,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Items,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Dates,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn SessionID,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn ShellID,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn CommandID,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn ActivityID,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn OperationID,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn OperationTimeout,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn MessageID,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn RelatesTo,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn FileName,([string]); $tbEvt.Columns.Add($col)

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
    $xmlPart = $line.Substring($nPos+8, $line.Length - $nPos - 8)
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
    $line = $sr.ReadLine()
    $lines = $lines + 1

    while (1 -eq 1) {
      if ($line.Length -gt 1) {
        if ($line.Substring(0,1) -eq "[") { break }
        if ($line.Substring($line.Length-1, 1) -eq " ") {
          $line=$line.Substring(0, $line.Length-1)
        }
      }
      $xmlLine[$thread] = $xmlLine[$thread] + $line
      $line = $sr.ReadLine()
      $lines = $lines + 1
    }

    # Closing tag detection
    if ($xmlLine[$thread].Substring($xmlLine[$thread].Length-13) -eq "</s:Envelope>") {
      $filename = "out-" + $timeFile + "-" + $msgtype + ".xml"
      $xmlLine[$thread] | Out-File -FilePath ($dirName + "\" + $FileName) 
      
      $xmlEvt = New-Object -TypeName System.Xml.XmlDocument
      $xmlPL = New-Object -TypeName System.Xml.XmlDocument

      $xmlEvt.LoadXml($xmlLine[$thread]) 
      $xmlLine.Remove($thread)

      $row = $tbEvt.NewRow()
      $row.Time = $time
      $row.Type = $msgtype
      
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

      if ($row.Message -eq "Events") {
        $blist = ""
        foreach ($bookmark in $xmlEvt.Envelope.Header.Bookmark.BookmarkList.Bookmark) {
          $blist += $bookmark.Channel + " = " + $bookmark.RecordId + " "
        }
        $row.Bookmarks = $blist
        $row.Items = $xmlEvt.Envelope.body.Events.Event.count

        # Get lowest and highest events date for the packet
        if ($xmlEvt.Envelope.Body.Events.FirstChild.'#cdata-section') {
          $xmlPL.LoadXml($xmlEvt.Envelope.Body.Events.FirstChild.'#cdata-section')
          $row.dates = $xmlpl.Event.System.TimeCreated.SystemTime + " - "
          $xmlPL.LoadXml($xmlEvt.Envelope.Body.Events.LastChild.'#cdata-section')
          $row.dates = $row.dates + $xmlpl.Event.System.TimeCreated.SystemTime  
        }
      } elseif ($row.Message -eq "EnumerateResponse") {
        if ($xmlEvt.Envelope.body.EnumerateResponse.Items.FirstChild.Name -eq "m:Subscription") {
          $row.Items = $xmlEvt.Envelope.body.EnumerateResponse.Items.ChildNodes.Count
          $filesub = $dirName + "\" + $FileName.Replace("xml","subscriptions.txt")
          foreach ($sub in $xmlEvt.Envelope.body.EnumerateResponse.Items) {
            $sub.Subscription.Envelope.Header.OptionSet.Option[0].'#text' | Out-File $filesub
            $sub.Subscription.Envelope.Body.Subscribe.EndTo.Address | Out-File $filesub -Append
  
            foreach ($qry in $sub.Subscription.Envelope.Body.Subscribe.filter.QueryList) {
              $qry.Query.InnerXml | Out-File $filesub -Append
            }
  
            foreach ($bm in $sub.Subscription.Envelope.Body.Subscribe.Bookmark.BookmarkList.Bookmark) {
              $bm.Channel + " = " + $bm.RecordId | Out-File $filesub -Append
            }
            "" | Out-File $filesub -Append
          }
        } elseif ($xmlEvt.Envelope.body.EnumerateResponse.Items.FirstChild.Name -eq "w:Item") {
          $row.Items = $xmlEvt.Envelope.body.EnumerateResponse.Items.ChildNodes.Count
        }
      } elseif ($row.Message -eq "CommandLine") {
        $row.Command = $xmlEvt.Envelope.body.CommandLine.Command
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
      }

      $row.To = $To
      $row.MessageID = $msgId
      $row.RelatesTo = $relTo
      $row.SessionID = $SessId
      $row.ShellID = $ShlID
      $row.CommandID = $cmdID
      $row.ActivityID = $ActId
      $row.OperationID = $OpId
      $row.OperationTimeout = $xmlEvt.Envelope.Header.OperationTimeout
      $row.FileName = $FileName

      $tbEvt.Rows.Add($row)
      Write-Host $lines $thread $time $To $row.Action

      }
    } else {
      $line = $sr.ReadLine()
      $lines = $lines + 1
    }
  }

$sr.Close()

$tbEvt | Export-Csv ($dirName + "\events-" + (Get-Item $InputFile).BaseName +".tsv") -noType -Delimiter "`t"

$duration = New-TimeSpan -Start $dtStart -End (Get-Date)
Write-Host "Execution completed in" $duration