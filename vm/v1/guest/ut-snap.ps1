# Original's leg, snapshot half: "pre" before driving its Uninstall Wizard for one app, "post" after
# the wizard's Finish. post writes <id>-ut-removed.json (what disappeared in between).
$Id = "__ID__"; $Phase = "__PHASE__"
. C:\cr\guest\lib.ps1
if ($Phase -eq "pre") { $null = Snap "$Id-u0"; "pre snapshot done"; exit }
$u0 = Get-Content "$Out\snap-$Id-u0.json" -Raw | ConvertFrom-Json
$u1 = Snap "$Id-u1"
$after = [Collections.Generic.HashSet[string]]::new([string[]](@($u1.fs) + @($u1.reg)), [StringComparer]::OrdinalIgnoreCase)
$gone = @(TopMost @(@($u0.fs) + @($u0.reg) | Where-Object { -not $after.Contains($_) -and $_ -notmatch $Noise }))
$gone | ConvertTo-Json | Out-File "$Out\$Id-ut-removed.json" -Encoding utf8
"removed (top-most): $($gone.Count)"
