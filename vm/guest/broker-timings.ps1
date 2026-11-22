<#
  Purge rig, M3 gate G12 (docs\M3_DESIGN.md 9.1 and 12; docs\m3-notes\broker-core.md "Timing records"). Guest or
  host side, Windows PowerShell 5.1; reading the Application log needs no elevation.

    & C:\cr\guest\broker-timings.ps1 -Out <file.jsonl> [-Since <datetime>]

  Writes every timing line of purge-broker (Application log, source "Purge", event id 100, information) to -Out,
  one JSON object per line, oldest first. Each line is one mark (purge_rpc::timing::TimingLine): pid and creation
  time of the broker process, request id and method for a request mark, the mark, ms since the process creation
  and the wall clock. -Since keeps the events written at or after that local time (the start of a run). No event
  is an empty file, not an error. The host turns the file into gate numbers with
  `cargo xtask broker-timings <file.jsonl> --out <file.json>`.
#>
param(
    [Parameter(Mandatory)]
    [string] $Out,
    [datetime] $Since
)
$ErrorActionPreference = 'Stop'

# FilterXPath, not -ProviderName: the source "Purge" is not a registered provider, and the provider lookup of
# -FilterHashtable/-ProviderName refuses an unregistered one. The line is the event's one insertion string.
$xpath = "*[System[Provider[@Name='Purge'] and EventID=100"
if ($PSBoundParameters.ContainsKey('Since')) {
    $utc = $Since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $xpath += " and TimeCreated[@SystemTime>='$utc']"
}
$xpath += ']]'

$events = @()
try {
    $events = @(Get-WinEvent -LogName Application -FilterXPath $xpath -ErrorAction Stop | Sort-Object RecordId)
} catch [System.Exception] {
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
}
$lines = [string[]]@($events | ForEach-Object { [string]$_.Properties[0].Value })
$dir = Split-Path -Parent ([IO.Path]::GetFullPath($Out))
if ($dir) { New-Item -ItemType Directory -Force $dir | Out-Null }
[IO.File]::WriteAllLines([IO.Path]::GetFullPath($Out), $lines, (New-Object System.Text.UTF8Encoding($false)))
Write-Output ("broker-timings: {0} line(s) -> {1}" -f $lines.Count, $Out)
