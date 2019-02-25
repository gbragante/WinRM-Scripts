# Version 20190225
# by Gianni Bragante - gbrag@microsoft.com

param( [string]$Subscription = "*", [Int]$PurgeDays = 0 )

$tbSts = New-Object system.Data.DataTable “Status”
$col = New-Object system.Data.DataColumn Subscription,([string]); $tbSts.Columns.Add($col)
$col = New-Object system.Data.DataColumn Source,([string]); $tbSts.Columns.Add($col)
$col = New-Object system.Data.DataColumn LastHeartbeatTime,([string]); $tbSts.Columns.Add($col)
$col = New-Object system.Data.DataColumn Bookmark,([string]); $tbSts.Columns.Add($col)
$col = New-Object system.Data.DataColumn Result,([string]); $tbSts.Columns.Add($col)

$Subscriptions = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions
foreach ($sub in $Subscriptions) {
  if ($Subscription -eq "*" -or $Subscription -eq $sub.PSChildName) {
    Write-Host $sub.PSChildName

    $sources = Get-ChildItem -Path (($sub.Name).replace("HKEY_LOCAL_MACHINE\","HKLM:\") + "\EventSources")
  
    foreach ($src in $sources) {
      $dtSub = ([DateTime][Convert]::ToInt64(($src | Get-ItemProperty).LastHeartbeatTime)).AddYears(1600)
      $dtDiff = New-TimeSpan -Start $dtSub -End (Get-Date)

      $row = $tbSts.NewRow()
      $row.Subscription = $sub.PSChildName
      $row.Source = $src.PSChildName
      $row.LastHeartbeatTime = $dtSub.ToString("yyyyMMdd HH:mm:ss")
      $row.Bookmark = ($src | Get-ItemProperty).Bookmark
      $row.Result = $dtDiff.Days.ToString() + " days old"

      if ($PurgeDays -gt 0) {
        if ($dtDiff.Days -ge $PurgeDays) {
          $row.Result = $row.Result + ", removed"
          Remove-Item -Path $src.name.replace("HKEY_LOCAL_MACHINE\","HKLM:\") 
        }
      }

      Write-Host ($sub.PSChildName + " " + $src.PSChildName + " " + $row.LastHeartbeatTime + " " + $row.Result)
      $tbSts.Rows.Add($row)
    }
  }
}

$Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path
$tbSts | Export-Csv ($root + "\Status-" + (Get-Date).ToString("yyyyMMddHHmmss") + ".csv") -noType