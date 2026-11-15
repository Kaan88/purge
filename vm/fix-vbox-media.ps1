# Repairs a rig VM that VirtualBox lists as <inaccessible> after the other host (Windows / Linux) used it.
#
# Cause: VirtualBox keeps the VM's disk tree in the host's own global VirtualBox.xml, not in the .vbox. Each
# snapshot restore makes a new current-state disk, so after one host ran a campaign the other host's registry
# names a disk that is gone, and the .vbox names one it has never seen.
#
# Fix: read every VDI header in the VM folder, and write the tree of the disks the .vbox uses (with their
# parents) into the .vbox as <MediaRegistry>. VirtualBox takes it from there on the next access and moves it to
# its global file when it next saves the VM. Disks no snapshot uses are left out. A copy of the .vbox is kept.
#
#   pwsh -NoProfile -File vm/fix-vbox-media.ps1 -Vbox E:\inbound-vm\Inbound-Win11-Test\Inbound-Win11-Test.vbox
#   ... -Print   shows the block and changes nothing
#   ... -ExtraDisk E:\purge-vm\inbound-m2-data.vdi   a disk the VM uses that lies outside its folder
#
# Run it with the VM powered off. VirtualBox may stay open as long as the VM shows as inaccessible.
param(
    [Parameter(Mandatory)] [string] $Vbox,
    [string[]] $ExtraDisk = @(),
    [switch] $Print
)
$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent (Resolve-Path $Vbox)
$utf8 = [Text.UTF8Encoding]::new($false)
$text = $utf8.GetString([IO.File]::ReadAllBytes($Vbox))

# uuid -> parent and relative location, from the VDI headers (v1.1: uuid at 392, parent at 424)
$disks = @{}
$files = @(Get-ChildItem -LiteralPath $dir -Filter *.vdi) + @(Get-ChildItem -LiteralPath (Join-Path $dir 'Snapshots') -Filter *.vdi)
$files += @($ExtraDisk | ForEach-Object { Get-Item -LiteralPath $_ })
foreach ($file in $files) {
    $stream = [IO.File]::Open($file.FullName, 'Open', 'Read', 'ReadWrite')
    try { $head = New-Object byte[] 512; [void]$stream.Read($head, 0, 512) } finally { $stream.Close() }
    if ([BitConverter]::ToString($head, 64, 4) -ne '7F-10-DA-BE') { throw "$($file.Name) is not a VDI" }
    $uuid = [guid]::new([byte[]]$head[392..407]).ToString()
    $parent = [guid]::new([byte[]]$head[424..439])
    $location = if ($file.DirectoryName -eq $dir) { $file.Name }
    elseif ($file.DirectoryName -eq (Join-Path $dir 'Snapshots')) { "Snapshots/$($file.Name)" }
    else { $file.FullName }
    $disks[$uuid] = @{
        Parent   = if ($parent -eq [guid]::Empty) { $null } else { $parent.ToString() }
        Location = $location
    }
}

# the disks the .vbox attaches, and all their parents
$used = @{}
foreach ($m in [regex]::Matches($text, '<Image uuid="\{([0-9a-fA-F-]+)\}"')) {
    $uuid = $m.Groups[1].Value.ToLower()
    while ($uuid) {
        if (-not $disks.ContainsKey($uuid)) { throw "disk {$uuid} is used by the .vbox or by a child disk, but no VDI in $dir has it" }
        $used[$uuid] = $true
        $uuid = $disks[$uuid].Parent
    }
}
if ($used.Count -eq 0) { throw 'the .vbox attaches no disk image' }

$nl = if ($text.Contains("`r`n")) { "`r`n" } else { "`n" }
function Node([string] $uuid, [string] $indent) {
    $kids = @($used.Keys | Where-Object { $disks[$_].Parent -eq $uuid } | Sort-Object)
    $type = if ($disks[$uuid].Parent) { '' } else { ' type="Normal"' }
    $open = "$indent<HardDisk uuid=`"{$uuid}`" location=`"$($disks[$uuid].Location)`" format=`"VDI`"$type"
    if ($kids.Count -eq 0) { return "$open/>" }
    return (@("$open>") + @($kids | ForEach-Object { Node $_ "$indent  " }) + @("$indent</HardDisk>")) -join $nl
}
$roots = @($used.Keys | Where-Object { -not $disks[$_].Parent } | Sort-Object)
$block = (@('    <MediaRegistry>', '      <HardDisks>') + @($roots | ForEach-Object { Node $_ '        ' }) +
    @('      </HardDisks>', '    </MediaRegistry>')) -join $nl

if ($Print) { $block; return }
if ($text.Contains('<MediaRegistry>')) { throw "$Vbox already has a <MediaRegistry>; nothing done (remove that block by hand if it is the stale one)" }

$machine = [regex]::Match($text, '<Machine [^>]*>')
if (-not $machine.Success) { throw 'no <Machine> element' }
$at = $machine.Index + $machine.Length
$fixed = $text.Substring(0, $at) + $nl + $block + $text.Substring($at)
[xml]$null = $fixed
$copy = "$Vbox.before-media-fix-$(Get-Date -Format yyyyMMdd-HHmmss)"
Copy-Item -LiteralPath $Vbox -Destination $copy
[IO.File]::WriteAllBytes($Vbox, $utf8.GetBytes($fixed))
"wrote the disk tree of $($used.Count) disks into $Vbox (copy: $copy)"
"check with: VBoxManage list vms; VBoxManage snapshot <vm> list"
