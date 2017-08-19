# WinRM-TraceParse - 20170704

param (
  [string]$FileName
)

Function ReadLine {
  $line = ""
  while ($line.Length -le 0) {
   $line = $sr.ReadLine()
  }
  return $line
}

if ($FileName -eq "") {
  Write-Host "Trace filename not specified"
  exit
}

$lines = 0
$xmlLine = @{}
$dirName = $filename + "-" + $(get-date -f yyyyMMdd_HHmmss)
Write-Host $dirname
New-Item -itemtype directory -path $dirname | Out-Null

$tbEvt = New-Object system.Data.DataTable “evt”
$col = New-Object system.Data.DataColumn Time,([string])
$tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Type,([string])
$tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn To,([string])
$tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Action,([string])
$tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Message,([string])
$tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn OperationID,([string])
$tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn OperationTimeout,([string])
$tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn FileName,([string])
$tbEvt.Columns.Add($col)

$dtStart = Get-Date

$sr = new-object System.io.streamreader(get-item $FileName)
$line = $sr.ReadLine()
$lines = $lines + 1
while (-not $sr.EndOfStream) {
  if ($line -match  "\] SOAP \[") {
    $thread = $line.Substring(4,8)
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

      $xmlEvt.LoadXml($xmlLine[$thread])
      $xmlLine.Remove($thread)

      $row = $tbEvt.NewRow()
      $row.Time = $time
      $row.Type = $msgtype
      
      $row.Message = $xmlEvt.Envelope.Body.FirstChild.LocalName
      if ($row.Message -eq "Fault") {
        $row.Message = $xmlEvt.Envelope.Body.Fault.Reason.text.'#text'
      }

      if ($xmlEvt.Envelope.Header.Action.HasAttributes) {
        $row.Action = $xmlEvt.Envelope.Header.Action.'#text'
      } else {
        $row.Action = $xmlEvt.Envelope.Header.Action
      }

      if ($xmlEvt.Envelope.Header.OperationID.HasAttributes) {
        $OpId = $xmlEvt.Envelope.Header.OperationID.'#text'
      } else {
        $OpId = $xmlEvt.Envelope.Header.OperationID
      }

      $To = $xmlEvt.Envelope.Header.To
      if ($OpId -ne "") {
        if ($To -eq "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous" -and $OpId -ne "") {
          $aOpId = $tbEvt.Select("OperationID = '" + $OpId + "'")
          if ($aOpId.Count -gt 0) { $To = $aOpId[0].To }
        }
      }
      $row.To = $To
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

$tbEvt | Export-Csv ($dirName + "\Events.csv") -noType

$duration = New-TimeSpan -Start $dtStart -End (Get-Date)
Write-Host "Execution completed in" $duration