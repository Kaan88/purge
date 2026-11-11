# BCU leg for one installed app: snapshot -> BCU-console uninstall /Q /U /J=Good -> snapshot.
# Everything that disappeared beyond what the vendor uninstaller alone removes is BCU's junk cleanup.
$Id = "__ID__"
. C:\cr\guest\lib.ps1
. C:\cr\guest\apps.ps1
$a = $Apps | Where-Object id -eq $Id
$console = Get-ChildItem 'C:\Program Files*\BCUninstaller*' -Recurse -Filter 'BCU-console.exe' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
$main = UninstallEntries | Where-Object { $_.name -match $a.match -and -not $_.sys } | Select-Object -First 1
if (-not $main) { $main = UninstallEntries | Where-Object { $_.name -match $a.match } | Select-Object -First 1 }
if (-not $main) { "NO MAIN ENTRY for $Id"; exit 3 }
"== bcu $Id : $($main.name)"
$esc = [Security.SecurityElement]::Escape($main.name)
$bcul = @"
<?xml version="1.0" encoding="utf-8"?>
<UninstallList>
  <Filters>
    <Filter>
      <Name>$esc</Name>
      <Exclude>false</Exclude>
      <ComparisonEntries>
        <FilterCondition>
          <InvertResults>false</InvertResults>
          <ComparisonMethod>Equals</ComparisonMethod>
          <FilterText>$esc</FilterText>
          <TargetPropertyId>DisplayName</TargetPropertyId>
          <Enabled>true</Enabled>
        </FilterCondition>
      </ComparisonEntries>
      <Enabled>true</Enabled>
    </Filter>
  </Filters>
  <Enabled>true</Enabled>
</UninstallList>
"@
$listFile = "$Out\$Id.bcul"
[IO.File]::WriteAllText($listFile, $bcul, [Text.UTF8Encoding]::new($false))

# Dry run first: what BCU would remove while the app is still installed (shows its junk finders' reach).
& $console uninstall $listFile /Q /U /N /J=Good /V *> "$Out\$Id-bcu-dryrun.txt"
"dry-run exit=$LASTEXITCODE"
$b0 = Snap "$Id-b0"
$t = Get-Date
& $console uninstall $listFile /Q /U /J=Good /V *> "$Out\$Id-bcu-run.txt"
"bcu exit=$LASTEXITCODE  $([int]((Get-Date)-$t).TotalSeconds)s"
Start-Sleep 5
$b1 = Snap "$Id-b1"
$after = [Collections.Generic.HashSet[string]]::new([string[]](@($b1.fs) + @($b1.reg)), [StringComparer]::OrdinalIgnoreCase)
$gone = @(@($b0.fs) + @($b0.reg) | Where-Object { -not $after.Contains($_) -and $_ -notmatch $Noise })
$gone = @(TopMost $gone)
$gone | ConvertTo-Json | Out-File "$Out\$Id-bcu-removed.json" -Encoding utf8
"removed (top-most): $($gone.Count)"
Get-Content "$Out\$Id-bcu-run.txt" -Tail 25
