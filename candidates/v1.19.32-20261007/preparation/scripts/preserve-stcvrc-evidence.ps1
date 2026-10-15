param(
    [Parameter(Mandatory=$true)][string]$Destination,
    [string]$AppDirectory = (Join-Path $env:APPDATA 'io.github.clash-verge-rev.clash-verge-rev'),
    [string]$ServiceOwnerDirectory,
    [ValidateRange(1,30)][int]$Days = 14,
    [ValidateRange(1,536870912)][long]$MaxLogBytes = 268435456,
    [switch]$SkipEvents,
    [switch]$RequireComplete
)
$ErrorActionPreference = 'Stop'
$env:PSModulePath=(Join-Path $PSHOME 'Modules')+';'+(Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')
function Assert-NoReparseAncestors([string]$Path) {
    $p=[IO.Path]::GetFullPath($Path)
    while($p) {
        if(Test-Path -LiteralPath $p) {
            if((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refuse reparse ancestor' }
        }
        $p=Split-Path -Parent $p
    }
}
$dest = [IO.Path]::GetFullPath($Destination)
Assert-NoReparseAncestors $dest
if (Test-Path -LiteralPath $dest) { throw 'Evidence destination must be new' }
Assert-NoReparseAncestors $AppDirectory
$app = (Resolve-Path -LiteralPath $AppDirectory).Path
$sources=@(@{label='app';root=(Join-Path $app 'logs');prefix='logs'})
if($ServiceOwnerDirectory) {
    $owner=[IO.Path]::GetFullPath($ServiceOwnerDirectory).TrimEnd('\')
    $allowed=[IO.Path]::GetFullPath((Join-Path $env:ProgramData 'clash-verge-service\users')).TrimEnd('\')+'\'
    if(-not $owner.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase) -or $owner.Substring($allowed.Length) -cnotmatch '^[0-9a-f]{64}$') { throw 'Exact service-owner directory required' }
    Assert-NoReparseAncestors $owner
    $sources+=@{label='service-owner';root=(Join-Path $owner 'logs');prefix='service-logs'}
    $serviceLogs=Join-Path $env:ProgramData 'clash-verge-service\logs'
    Assert-NoReparseAncestors $serviceLogs
    if(Test-Path -LiteralPath $serviceLogs -PathType Container) {
        $sources+=@{label='service-process';root=$serviceLogs;prefix='service-process-logs'}
    }
}
foreach($source in $sources) {
    $parent=Split-Path -Parent $source.root
    if($dest -ieq $parent -or $dest.StartsWith($parent.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Evidence must live outside source roots' }
}
$null = New-Item -ItemType Directory -Path $dest
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
foreach($principal in @($sid, [Security.Principal.SecurityIdentifier]'S-1-5-18', [Security.Principal.SecurityIdentifier]'S-1-5-32-544')) {
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($principal,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $dest -AclObject $acl
$manifest = [ordered]@{schemaVersion=2;host=$env:COMPUTERNAME;startedUtc=[DateTime]::UtcNow.ToString('o');files=@();sources=@();events=@();status='partial';maxLogBytes=$MaxLogBytes}
$errors = @()
$reserved=0L
foreach($source in $sources) {
    $logs=$source.root
    Assert-NoReparseAncestors $logs
    if(-not(Test-Path -LiteralPath $logs -PathType Container)) {
        $manifest.sources+=@{name=$source.label;status='missing'}
        continue
    }
    $manifest.sources+=@{name=$source.label;status='present'}
    $pending=New-Object 'Collections.Generic.Queue[string]'
    $pending.Enqueue($logs)
    $files=@()
    while($pending.Count) {
        $directory=$pending.Dequeue()
        foreach($item in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction SilentlyContinue -ErrorVariable +errors)) {
            if($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refuse log reparse tree' }
            if($item.PSIsContainer) { $pending.Enqueue($item.FullName) }
            elseif($item.Extension -ieq '.log') { $files+= $item }
        }
    }
    foreach($file in ($files|Sort-Object FullName)) {
    if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refuse log reparse point' }
    $relative = $file.FullName.Substring($logs.Length).TrimStart('\')
    $relativeTarget=$source.prefix+'/'+$relative.Replace('\','/')
    $target = Join-Path (Join-Path $dest $source.prefix) $relative
    $null = New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force
    $inputStream=$null; $outputStream=$null
    try {
        $inputStream = [IO.File]::Open($file.FullName,'Open','Read',([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        $remaining = $inputStream.Length
        if($remaining -gt ($MaxLogBytes-$reserved)) {
            $manifest.files+=@{path=$relativeTarget;status='budget-exceeded';sourceBytes=$remaining}
            continue
        }
        $reserved+=$remaining
        $outputStream = [IO.File]::Open($target,'CreateNew','Write','None')
        $buffer = New-Object byte[] 65536
        while($remaining -gt 0) {
            $read = $inputStream.Read($buffer,0,[int][Math]::Min($remaining,$buffer.Length))
            if($read -eq 0){break}
            $outputStream.Write($buffer,0,$read); $remaining -= $read
        }
        $outputStream.Close(); $outputStream=$null
        $manifest.files += @{path=$relativeTarget;bytes=(Get-Item -LiteralPath $target).Length;sha256=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash;sourceLastWriteUtc=$file.LastWriteTimeUtc.ToString('o');status= $(if($remaining -eq 0){'copied'}else{'source-truncated'})}
    } catch {
        $manifest.files += @{path=$relativeTarget;status='unreadable';errorClass=$_.Exception.GetType().Name}
    } finally {
        if($inputStream){$inputStream.Dispose()}; if($outputStream){$outputStream.Dispose()}
    }
    }
}
$manifest.enumerationErrors = $errors.Count
if(-not $SkipEvents) {
    $eventRoot = Join-Path $dest 'events'
    $null = New-Item -ItemType Directory -Path $eventRoot
    $channels = @('System','Application','Microsoft-Windows-NetworkProfile/Operational','Microsoft-Windows-WLAN-AutoConfig/Operational','Microsoft-Windows-TerminalServices-RDPClient/Operational','Microsoft-Windows-TerminalServices-LocalSessionManager/Operational')
    $query = '*[System[TimeCreated[timediff(@SystemTime) <= '+([long]$Days*86400000)+']]]'
    foreach($channel in $channels) {
        $name=$channel.Replace('/','-')+'.evtx'
        $target=Join-Path $eventRoot $name
        $null = & "$env:SystemRoot\System32\wevtutil.exe" epl $channel $target "/q:$query" 2>&1
        $code=$LASTEXITCODE
        $entry=@{channel=$channel;exitCode=$code;status='unavailable'}
        if($code -eq 0 -and (Test-Path -LiteralPath $target)) {
            $entry.status='exported';$entry.bytes=(Get-Item -LiteralPath $target).Length
            $entry.sha256=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
        }
        $manifest.events += $entry
    }
}
$manifest.finishedUtc=[DateTime]::UtcNow.ToString('o')
if($manifest.enumerationErrors -eq 0 -and @($manifest.sources | Where-Object {$_.status -ne 'present'}).Count -eq 0 -and @($manifest.files | Where-Object {$_.status -ne 'copied'}).Count -eq 0 -and @($manifest.events | Where-Object {$_.status -ne 'exported'}).Count -eq 0) {$manifest.status='preserved'}
[IO.File]::WriteAllText((Join-Path $dest 'manifest.json'),($manifest|ConvertTo-Json -Depth 6),(New-Object Text.UTF8Encoding($false)))
$totalBytes=0L
foreach($entry in $manifest.files){if($entry.ContainsKey('bytes')){$totalBytes += $entry.bytes}}
@{status=$manifest.status;logFiles=$manifest.files.Count;logBytes=$totalBytes;eventsExported=@($manifest.events|Where-Object {$_.status -eq 'exported'}).Count;enumerationErrors=$manifest.enumerationErrors;destination=$dest}|ConvertTo-Json -Compress
if($RequireComplete -and $manifest.status -cne 'preserved') { throw 'Evidence preservation incomplete; inspect manifest before any rollout' }
