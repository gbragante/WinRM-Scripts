# AddEventAnalysis - by Gianni Bragante gbrag@microsoft.com
# Version 20210209

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

Function ToTime{
  param( [string]$time)
  return (Get-Date -Year (2000 + $time.Substring(6,2)) -Month $time.Substring(0,2) -Day $time.Substring(3,2) -Hour $time.Substring(9,2) -Minute $time.Substring(12,2) -Second $time.Substring(15,2))
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

if ($InputFile -eq "") {
  Write-Host "Trace filename not specified"
  exit
}

$tbEvt = New-Object system.Data.DataTable
$col = New-Object system.Data.DataColumn Time,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn PID,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn TID,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Size,([decimal]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Diff,([decimal]); $tbEvt.Columns.Add($col)

$dtStart = Get-Date
$TZName = (Get-WmiObject win32_timezone).StandardName
$TZ = [System.TimeZoneInfo]::FindSystemTimeZoneById($TZName)
$prevTime = $null
$prevmSec = 0

$sr = new-object System.io.streamreader(get-item $InputFile)
$line = $sr.ReadLine()
$lines = $lines + 1
while (-not $sr.EndOfStream) {
  if ($line -match  "CWSManEnumerator::AddEvent - adding event with size") {
    Write-Host $line
    $LP = LineParam
    $currTime = ToTime $LP.Time
    $currmSec = $lp.time.Substring($lp.time.IndexOf(".")+1) / 10000

    if ($prevTime) {
      $diff = New-TimeSpan -Start $prevTime -End $currTime
      $diffSec = [math]::Round($diff.TotalSeconds)
      if ($diffSec -gt 10) {
        $diffmSec = 9999
      } else {
        if ($prevmSec -gt $currmSec) {
          $diffmSec = $currmSec + 1000 - $prevmSec
        } else {
          $diffmSec = $currmSec - $prevmSec
        }
        $diffmSec = [math]::Round($diffmSec,3)
      }
      Write-Host $diffmSec
    } else {
      $diff = 0
    }
    $prevTime = $currTime
    $prevmSec = $currmSec

    $row = $tbEvt.NewRow()
    $row.Time = $LP.time
    $row.Pid = $LP.PID
    $row.Tid = $LP.TID
    $row.Size = FindSep -FindIn $line -Left "with size: "
    $row.Diff = $diffmSec
    $tbEvt.Rows.Add($row)
  }
  $line = $sr.ReadLine()
  $lines = $lines + 1
}

$sr.Close()

Write-Host "Exporting data to tsv"
$tbEvt | Export-Csv (".\AddEvent-" + (Get-Item $InputFile).BaseName +".tsv") -noType -Delimiter "`t"