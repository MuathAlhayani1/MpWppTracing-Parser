#Requires -Version 5.1
<#
.SYNOPSIS
    Forensic extractor for MpWppTracing binary (.bin) files from Windows Defender.

.DESCRIPTION
    Parses binary WPP trace files from:
        C:\ProgramData\Microsoft\Windows Defender\Support\
        MpWppTracing-YYYYMMDD-HHMMSS-00000003-fffffffeffffffff.bin

    Performs two levels of extraction:
    1. STRING EXTRACTION: ASCII and UTF-16LE printable strings, classified into
       PowerShell, ExecutablePath, NetworkIndicator, and RegistryKey categories.
       Base64-encoded PowerShell payloads are decoded automatically.
    2. BINARY PARSING: Walks the ETW/WPP buffer structure to extract record
       timestamps (FILETIME), PIDs, TIDs, Message GUIDs, and payload hex --
       data invisible to string extraction alone.

.PARAMETER Path
    Path to one or more .bin files. Accepts wildcards.
    Default: C:\ProgramData\Microsoft\Windows Defender\Support\MpWppTracing*.bin

.PARAMETER MinStringLength
    Minimum printable string length to extract. Default: 8.

.PARAMETER ExportCsv
    CSV output path. Defaults to .\MpWppTracing-Findings-<timestamp>.csv

.PARAMETER NoExport
    Skip CSV export, console output only.

.PARAMETER SuspiciousOnly
    Return only CRITICAL and HIGH severity findings.

.PARAMETER IncludeRaw
    Include all extracted strings as additional output rows.

.PARAMETER SkipBinaryParsing
    Skip structured ETW/WPP binary record parsing, do string extraction only.

.EXAMPLE
    .\Parse-MpWppTracingBin.ps1

.EXAMPLE
    .\Parse-MpWppTracingBin.ps1 -Path C:\Cases\*.bin -SuspiciousOnly -ExportCsv C:\Cases\out.csv

.EXAMPLE
    $hits = .\Parse-MpWppTracingBin.ps1 -Path .\trace.bin
    $hits | Where-Object { $_.Category -eq 'WppRecord' } | Format-Table Timestamp, PID, TID, MatchedValue
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string[]]$Path = @('C:\ProgramData\Microsoft\Windows Defender\Support\MpWppTracing*.bin'),

    [Parameter(Position = 1)]
    [ValidateRange(4, 512)]
    [int]$MinStringLength = 8,

    [Parameter()]
    [string]$ExportCsv,

    [Parameter()]
    [switch]$NoExport,

    [Parameter()]
    [switch]$SuspiciousOnly,

    [Parameter()]
    [switch]$IncludeRaw,

    [Parameter()]
    [switch]$SkipBinaryParsing
)

# StrictMode disabled - script processes arbitrary binary data where property absence is expected
Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

#region -- Classification Patterns --------------------------------------------

$script:Patterns = [ordered]@{
    'PS_ENCODED_CMD'      = @{ Cat='PowerShell';       Sev='CRITICAL'; Desc='PowerShell encoded command (-enc / -EncodedCommand)';             Re='(?i)-[Ee]nc\S*\s+[A-Za-z0-9+/]{20,}={0,2}' }
    'PS_DOWNLOAD_CRADLE'  = @{ Cat='PowerShell';       Sev='CRITICAL'; Desc='Download cradle or remote execution (IEX, WebClient, BITS)';      Re='(?i)(IEX|Invoke-Expression|DownloadString|DownloadFile|Net\.WebClient|Start-BitsTransfer)' }
    'PS_AMSI_BYPASS'      = @{ Cat='PowerShell';       Sev='CRITICAL'; Desc='AMSI bypass attempt';                                             Re='(?i)(amsiInitFailed|AmsiScanBuffer|amsi\.dll|AmsiUtils)' }
    'NET_DIRECT_IP_URL'   = @{ Cat='NetworkIndicator'; Sev='CRITICAL'; Desc='HTTP URL with raw IP address - strong C2 indicator';              Re='https?://((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)' }
    'PS_EXEC_BYPASS'      = @{ Cat='PowerShell';       Sev='HIGH';     Desc='ExecutionPolicy Bypass';                                          Re='(?i)-[Ee]xecution[Pp]olicy\s+[Bb]ypass|-[Ee][Pp]\s+[Bb]ypass' }
    'PS_REFLECTION'       = @{ Cat='PowerShell';       Sev='HIGH';     Desc='In-memory assembly load via reflection';                          Re='(?i)(\[Reflection\.Assembly\]|Assembly\.Load|LoadWithPartialName)' }
    'NET_SUSPICIOUS_TLD'  = @{ Cat='NetworkIndicator'; Sev='HIGH';     Desc='Domain with commonly abused TLD (.top .xyz .tk .onion etc.)';     Re='(?i)[a-z0-9][a-z0-9\-]{1,62}\.(top|xyz|pw|cc|tk|ml|ga|cf|gq|bit|onion|ru|su|cn|ws)\b' }
    'PATH_LOLBAS'         = @{ Cat='ExecutablePath';   Sev='HIGH';     Desc='Living-off-the-land binary (LOLBAS)';                             Re='(?i)\b(regsvr32|rundll32|mshta|certutil|wmic|msiexec|installutil|regasm|regsvcs|cmstp|msdt|csc|vbc|msbuild|xwizard|dnscmd|bitsadmin|odbcconf)(\.exe)?\b' }
    'PATH_SUSPICIOUS_LOC' = @{ Cat='ExecutablePath';   Sev='HIGH';     Desc='Executable in writable or suspicious directory';                  Re='(?i)[a-zA-Z]:\\(temp|windows\\temp|users\\[^\\]+\\(appdata|downloads|desktop)|programdata|public)\\[^\s"]{4,}\.(exe|dll|ps1|bat|cmd|vbs|js|hta|scr|pif|com|lnk|msi)' }
    'PATH_UNC'            = @{ Cat='ExecutablePath';   Sev='HIGH';     Desc='UNC path - possible lateral movement or remote execution';        Re='\\\\[a-zA-Z0-9\-\.]{2,}\\[a-zA-Z$][^\s"]{3,}' }
    'REG_RUN_KEY'         = @{ Cat='RegistryKey';      Sev='HIGH';     Desc='Registry Run key - persistence mechanism';                        Re='(?i)(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s"]{0,150}\\(Run|RunOnce|RunOnceEx|RunServices)\b' }
    'REG_PERSISTENCE'     = @{ Cat='RegistryKey';      Sev='HIGH';     Desc='Registry persistence or hijack location';                         Re='(?i)(HKLM|HKCU)\\[^\s"]{0,150}\\(Winlogon|AppInit_DLLs|Image File Execution Options|SecurityProviders|BootExecute|ServiceDll|Userinit)\b' }
    'REG_DEFENDER_TAMPER' = @{ Cat='RegistryKey';      Sev='HIGH';     Desc='Defender config key - possible exclusion or tamper';              Re='(?i)SOFTWARE\\(Microsoft\\)?Windows Defender\\(Exclusions|Real-Time Protection|Features|Signature Updates)[^\s"]{0,100}' }
    'PS_INVOCATION'       = @{ Cat='PowerShell';       Sev='MEDIUM';   Desc='PowerShell invocation with arguments';                            Re='(?i)powershell(\.exe)?\s+-.{4,}' }
    'NET_URL'             = @{ Cat='NetworkIndicator'; Sev='MEDIUM';   Desc='HTTP/HTTPS URL';                                                  Re='https?://[a-zA-Z0-9\-\.]{4,}[^\s"<>]{4,}' }
    'NET_IP_ADDRESS'      = @{ Cat='NetworkIndicator'; Sev='MEDIUM';   Desc='IP address with optional port';                                   Re='\b((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)(:\d{2,5})?\b' }
    'PATH_EXE_DLL'        = @{ Cat='ExecutablePath';   Sev='INFO';     Desc='Executable or DLL path';                                          Re='(?i)[a-zA-Z]:\\[^\s"<>|*?]{5,}\.(exe|dll|sys|drv)' }
    'REG_GENERAL'         = @{ Cat='RegistryKey';      Sev='INFO';     Desc='Registry key path';                                               Re='(?i)(HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\[^\s"]{5,}' }
}

$script:SevOrder = @{ CRITICAL = 0; HIGH = 1; MEDIUM = 2; INFO = 3 }
$script:SevColor = @{ CRITICAL = 'Red'; HIGH = 'Yellow'; MEDIUM = 'Cyan'; INFO = 'DarkGray' }

#endregion

#region -- String Extraction --------------------------------------------------

function Extract-Strings {
    param([byte[]]$Bytes, [int]$Min)

    $seen = [System.Collections.Generic.HashSet[string]]::new()

    # ASCII pass
    $asciiText = [System.Text.Encoding]::ASCII.GetString($Bytes)
    $asciiRx   = [regex]('[\x20-\x7E]{' + $Min + ',}')
    foreach ($m in $asciiRx.Matches($asciiText)) {
        [void]$seen.Add($m.Value)
    }

    # UTF-16LE pass - walk byte pairs
    $buf = [System.Text.StringBuilder]::new(256)
    $i = 0
    while ($i -lt ($Bytes.Length - 1)) {
        $lo = $Bytes[$i]
        $hi = $Bytes[$i + 1]
        if ($lo -ge 0x20 -and $lo -le 0x7E -and $hi -eq 0x00) {
            [void]$buf.Append([char]$lo)
            $i += 2
        }
        else {
            if ($buf.Length -ge $Min) {
                [void]$seen.Add($buf.ToString())
            }
            [void]$buf.Clear()
            $i++
        }
    }
    if ($buf.Length -ge $Min) {
        [void]$seen.Add($buf.ToString())
    }

    return ,[System.Collections.Generic.HashSet[string]]$seen
}

function Decode-Base64PS {
    param([string]$Str)
    if ($Str -match '(?i)-[Ee]nc\S*\s+([A-Za-z0-9+/]{20,}={0,2})') {
        try {
            $decoded = [System.Text.Encoding]::Unicode.GetString(
                [Convert]::FromBase64String($Matches[1])
            )
            if ($decoded -match '[\x20-\x7E]{10,}') {
                return $decoded
            }
        }
        catch { }
    }
    return $null
}

function Classify-Strings {
    param(
        [System.Collections.Generic.HashSet[string]]$Strings,
        [string]$File
    )

    $out = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($s in $Strings) {
        foreach ($name in $script:Patterns.Keys) {
            $p = $script:Patterns[$name]
            if ($s -match $p.Re) {
                $decoded = $null
                if ($name -eq 'PS_ENCODED_CMD') {
                    $decoded = Decode-Base64PS -Str $s
                }
                $row = [PSCustomObject]@{
                    SourceFile   = $File
                    Category     = $p.Cat
                    PatternName  = $name
                    Severity     = $p.Sev
                    Description  = $p.Desc
                    MatchedValue = $s.Trim()
                    DecodedB64   = $decoded
                    RecordType   = 'StringMatch'
                    RecordOffset = $null
                    Timestamp    = $null
                    PID          = $null
                    TID          = $null
                    MessageGUID  = $null
                    Flags        = $null
                    PayloadHex   = $null
                    PayloadSize  = $null
                }
                $out.Add($row)
            }
        }
    }

    return ,[System.Collections.Generic.List[PSCustomObject]]$out
}

#endregion

#region -- Structured Binary Parser -------------------------------------------
#
#  ETW/WPP buffer structure (simplified):
#
#  Buffer header (variable size, typically 0x48 to 0x80 bytes):
#    +0x00  Signature/Version   ULONG
#    +0x04  BufferSize          ULONG
#    +0x08  SavedOffset         ULONG
#    +0x0C  CurrentOffset       ULONG
#    +0x10  ReferenceCount      LONG
#    +0x14  TimeStamp           LARGE_INTEGER (FILETIME)
#    +0x1C  SequenceNumber      LARGE_INTEGER
#
#  WPP message record header:
#    +0x00  Marker    BYTE   0xFF = user-mode, 0xC0 = kernel-mode
#    +0x01  Size      USHORT total record size including header
#    +0x03  HookId    USHORT
#    +0x05  TypeGroup BYTE
#    +0x06  Reserved  BYTE
#    +0x07  ThreadId  ULONG
#    +0x0B  ProcessId ULONG
#    +0x0F  SystemTime LARGE_INTEGER (FILETIME, 100ns ticks since 1601-01-01)
#    +0x17  MessageGUID GUID (16 bytes)
#    +0x27  Payload   variable length bytes

function Read-U16LE {
    param([byte[]]$b, [int]$o)
    return [uint16]($b[$o] -bor ($b[$o + 1] -shl 8))
}

function Read-U32LE {
    param([byte[]]$b, [int]$o)
    return [uint32]($b[$o] -bor ($b[$o + 1] -shl 8) -bor ($b[$o + 2] -shl 16) -bor ($b[$o + 3] -shl 24))
}

function Read-U64LE {
    param([byte[]]$b, [int]$o)
    $lo = [uint64](Read-U32LE -b $b -o $o)
    $hi = [uint64](Read-U32LE -b $b -o ($o + 4))
    return $lo -bor ($hi -shl 32)
}

function Read-GUID {
    param([byte[]]$b, [int]$o)
    $p1  = (Read-U32LE -b $b -o $o).ToString('X8')
    $p2  = (Read-U16LE -b $b -o ($o + 4)).ToString('X4')
    $p3  = (Read-U16LE -b $b -o ($o + 6)).ToString('X4')
    $p4  = $b[$o + 8].ToString('X2') + $b[$o + 9].ToString('X2')
    $p5  = $b[$o + 10].ToString('X2') + $b[$o + 11].ToString('X2') +
           $b[$o + 12].ToString('X2') + $b[$o + 13].ToString('X2') +
           $b[$o + 14].ToString('X2') + $b[$o + 15].ToString('X2')
    return '{' + $p1 + '-' + $p2 + '-' + $p3 + '-' + $p4 + '-' + $p5 + '}'
}

function FileTime-ToDateTime {
    param([uint64]$ft)
    try {
        return [datetime]::FromFileTimeUtc([int64]$ft)
    }
    catch {
        return $null
    }
}

function Bytes-ToHex {
    param([byte[]]$b, [int]$offset, [int]$len)
    $end = [Math]::Min($offset + $len, $b.Length)
    $sb  = [System.Text.StringBuilder]::new(($end - $offset) * 2)
    for ($i = $offset; $i -lt $end; $i++) {
        [void]$sb.Append($b[$i].ToString('X2'))
    }
    return $sb.ToString()
}

function Parse-WppRecords {
    param([byte[]]$Bytes, [string]$File)

    $records    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $MIN_RECORD = 39
    $MAX_RECORD = 65535

    $i = 0
    while ($i -lt ($Bytes.Length - $MIN_RECORD)) {
        # Wrap each record in its own try/catch so one bad record never aborts the whole file
        try {
            $marker = $Bytes[$i]

            if ($marker -ne 0xFF -and $marker -ne 0xC0) {
                $i++
                continue
            }

            if (($i + 2) -ge $Bytes.Length) { break }

            $recSize = [int](Read-U16LE -b $Bytes -o ($i + 1))

            if ($recSize -lt $MIN_RECORD -or $recSize -gt $MAX_RECORD) {
                $i++
                continue
            }
            if (($i + $recSize) -gt $Bytes.Length) {
                $i++
                continue
            }

            $recTid   = Read-U32LE -b $Bytes -o ($i + 7)
            $recPid   = Read-U32LE -b $Bytes -o ($i + 11)
            $filetime = Read-U64LE -b $Bytes -o ($i + 15)

            # Safe timestamp conversion - discard record if conversion fails or value is nonsensical
            $dt = $null
            try { $dt = FileTime-ToDateTime -ft $filetime } catch { }
            if ($null -eq $dt -or $dt.Year -lt 2010 -or $dt.Year -gt 2040) {
                $i++
                continue
            }

            $guid       = Read-GUID   -b $Bytes -o ($i + 23)
            $hookFlags  = (Read-U16LE -b $Bytes -o ($i + 3)).ToString('X4')
            $payloadOff = $i + 39
            $payloadLen = $recSize - 39

            $payHex  = ''
            $payText = ''
            if ($payloadLen -gt 0) {
                $capLen  = [Math]::Min($payloadLen, 128)
                $payHex  = Bytes-ToHex -b $Bytes -offset $payloadOff -len $capLen
                $payBuf  = $Bytes[$payloadOff..($payloadOff + $payloadLen - 1)]
                $asAscii = [System.Text.Encoding]::ASCII.GetString($payBuf) -replace '[^\x20-\x7E]', '.'
                $asWide  = [System.Text.Encoding]::Unicode.GetString($payBuf) -replace '[^\x20-\x7E]', ''
                $payText = if ($asWide.Length -gt ($asAscii -replace '\.','').Length) {
                    $asWide.Trim()
                } else {
                    $asAscii.Trim()
                }
                $payText = $payText -replace '\.{3,}', '...'
                if ($payText.Length -gt 300) { $payText = $payText.Substring(0, 300) + '...' }
            }

            $patName = if ($marker -eq 0xC0) { 'WPP_KERNEL_MODE' } else { 'WPP_USER_MODE' }

            $records.Add([PSCustomObject]@{
                SourceFile   = $File
                Category     = 'WppRecord'
                PatternName  = $patName
                Severity     = 'INFO'
                Description  = 'Parsed WPP/ETW binary record'
                MatchedValue = $payText
                DecodedB64   = $null
                RecordType   = 'BinaryRecord'
                RecordOffset = $i
                Timestamp    = $dt
                PID          = $recPid
                TID          = $recTid
                MessageGUID  = $guid
                Flags        = '0x' + $hookFlags
                PayloadHex   = $payHex
                PayloadSize  = $payloadLen
            })

            $i += $recSize
        }
        catch {
            # Bad record - skip one byte and keep going
            $i++
        }
    }

    # Return as array-wrapped list so .Count always works on the caller side
    return ,$records
}

#endregion

#region -- Main ---------------------------------------------------------------

$allFindings    = [System.Collections.Generic.List[PSCustomObject]]::new()
$processedFiles = 0
$totalBytes     = 0

# Resolve file paths
$resolvedFiles = [System.Collections.Generic.List[string]]::new()
foreach ($p in $Path) {
    $hits = Resolve-Path -Path $p -ErrorAction SilentlyContinue
    if ($hits) {
        foreach ($h in $hits) {
            $resolvedFiles.Add($h.Path)
        }
    }
    else {
        Write-Warning "No files matched: $p"
    }
}

if ($resolvedFiles.Count -eq 0) {
    Write-Error 'No .bin files found. Use -Path to specify location, or run as Administrator.'
    exit 1
}

Write-Host ''
Write-Host '+==============================================================+' -ForegroundColor Cyan
Write-Host '|   MpWppTracing Full-Spectrum Forensic Extractor              |' -ForegroundColor Cyan
Write-Host '|   Strings + WPP/ETW Binary Structure Parser                  |' -ForegroundColor Cyan
Write-Host '+==============================================================+' -ForegroundColor Cyan
Write-Host ''
Write-Host "  Files found     : $($resolvedFiles.Count)" -ForegroundColor White
Write-Host "  String min len  : $MinStringLength" -ForegroundColor DarkGray

$binLabel = 'ENABLED'
if ($SkipBinaryParsing) { $binLabel = 'SKIPPED' }
Write-Host "  Binary parsing  : $binLabel" -ForegroundColor DarkGray
Write-Host ''

foreach ($file in $resolvedFiles) {
    $leaf   = Split-Path $file -Leaf
    $fileTs = $null

    if ($leaf -match 'MpWppTracing-(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})-') {
        $dtStr = $Matches[1] + '-' + $Matches[2] + '-' + $Matches[3] + ' ' +
                 $Matches[4] + ':' + $Matches[5] + ':' + $Matches[6]
        try { $fileTs = [datetime]$dtStr } catch { }
    }

    $tsLabel = 'unknown time'
    if ($null -ne $fileTs) { $tsLabel = $fileTs.ToString('yyyy-MM-dd HH:mm:ss') }

    Write-Host "  [*] $leaf" -ForegroundColor White
    Write-Host "      Trace time : $tsLabel" -ForegroundColor DarkGray

    try {
        # Open with FileShare.ReadWrite so we can read files locked by the Defender service
        $fs    = [System.IO.FileStream]::new(
                     $file,
                     [System.IO.FileMode]::Open,
                     [System.IO.FileAccess]::Read,
                     [System.IO.FileShare]::ReadWrite)
        $bytes = [byte[]]::new($fs.Length)
        [void]$fs.Read($bytes, 0, $bytes.Length)
        $fs.Close()
        $fs.Dispose()
        $totalBytes += $bytes.Length
        $processedFiles++

        $fileSizeKB = [math]::Round($bytes.Length / 1024, 1)
        Write-Host "      File size  : $fileSizeKB KB" -ForegroundColor DarkGray

        # 1. String extraction and classification
        # Do NOT wrap in @() - Extract-Strings returns a HashSet; @() would make a 1-element array containing it
        $strings     = Extract-Strings -Bytes $bytes -Min $MinStringLength
        $strFindings = Classify-Strings -Strings $strings -File $leaf
        $strCount    = if ($null -ne $strings)     { $strings.Count     } else { 0 }
        $clsCount    = if ($null -ne $strFindings) { $strFindings.Count } else { 0 }
        Write-Host "      Strings    : $strCount extracted, $clsCount classified" -ForegroundColor DarkGray
        if ($null -ne $strFindings) {
            foreach ($f in $strFindings) { $allFindings.Add($f) }
        }

        # 2. Structured binary parsing
        if (-not $SkipBinaryParsing) {
            $binRecords = Parse-WppRecords -Bytes $bytes -File $leaf
            $wppCount = if ($null -ne $binRecords) { $binRecords.Count } else { 0 }
            Write-Host "      WPP records: $wppCount parsed" -ForegroundColor DarkGray
            if ($null -ne $binRecords) { foreach ($r in $binRecords) { $allFindings.Add($r) } }
        }

        # 3. Optional raw strings
        if ($IncludeRaw) {
            foreach ($s in $strings) {
                $raw = [PSCustomObject]@{
                    SourceFile   = $leaf
                    Category     = 'RawString'
                    PatternName  = 'RAW'
                    Severity     = 'INFO'
                    Description  = 'Unclassified extracted string'
                    MatchedValue = $s
                    DecodedB64   = $null
                    RecordType   = 'RawString'
                    RecordOffset = $null
                    Timestamp    = $null
                    PID          = $null
                    TID          = $null
                    MessageGUID  = $null
                    Flags        = $null
                    PayloadHex   = $null
                    PayloadSize  = $null
                }
                $allFindings.Add($raw)
            }
        }
    }
    catch {
        Write-Warning "    Error reading $file : $_"
    }

    Write-Host ''
}

# Deduplicate - use PSObject.Properties.Match for safe property access under any StrictMode
$seen    = [System.Collections.Generic.HashSet[string]]::new()
$deduped = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($f in $allFindings) {
    # Skip anything that is not a PSCustomObject (e.g. raw strings leaked from pipeline)
    if ($f -isnot [System.Management.Automation.PSObject] -and
        $f -isnot [PSCustomObject]) { continue }

    $recType = if ($f.PSObject.Properties.Match('RecordType').Count -gt 0) { $f.RecordType } else { '' }
    $src     = if ($f.PSObject.Properties.Match('SourceFile').Count  -gt 0) { $f.SourceFile } else { '' }

    if ($recType -eq 'BinaryRecord') {
        $off = if ($f.PSObject.Properties.Match('RecordOffset').Count -gt 0) { $f.RecordOffset } else { '0' }
        $key = 'BIN|' + $src + '|' + $off
    }
    else {
        $pat = if ($f.PSObject.Properties.Match('PatternName').Count  -gt 0) { $f.PatternName  } else { '' }
        $val = if ($f.PSObject.Properties.Match('MatchedValue').Count -gt 0) { $f.MatchedValue } else { '' }
        $key = $pat + '|' + $src + '|' + $val
    }
    if ($seen.Add($key)) { $deduped.Add($f) }
}

$allFindings = $deduped

if ($SuspiciousOnly) {
    $filtered = $allFindings | Where-Object {
        $sev = if ($_.PSObject.Properties.Match('Severity').Count -gt 0) { $_.Severity } else { '' }
        $sev -eq 'CRITICAL' -or $sev -eq 'HIGH'
    }
    $allFindings = [System.Collections.Generic.List[PSCustomObject]]$filtered
}

$sorted = $allFindings | Sort-Object @{
    Expression = {
        $sev = if ($_.PSObject.Properties.Match('Severity').Count -gt 0) { $_.Severity } else { 'INFO' }
        $script:SevOrder[$sev]
    }
}, @{
    Expression = {
        if ($_.PSObject.Properties.Match('Category').Count -gt 0) { $_.Category } else { '' }
    }
}

#endregion

#region -- Console Report -----------------------------------------------------

Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host '  FINDINGS REPORT' -ForegroundColor Cyan
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host ''

# String-based findings grouped by category
$strRows = $sorted | Where-Object { $_.PSObject.Properties.Match('RecordType').Count -eq 0 -or $_.RecordType -ne 'BinaryRecord' }
$catGroups = $strRows | Group-Object Category | Sort-Object Name

foreach ($catGroup in $catGroups) {
    $label = $catGroup.Name.ToUpper()
    switch ($catGroup.Name) {
        'PowerShell'       { $label = 'POWERSHELL' }
        'ExecutablePath'   { $label = 'EXECUTABLE / DLL PATHS' }
        'NetworkIndicator' { $label = 'NETWORK INDICATORS' }
        'RegistryKey'      { $label = 'REGISTRY KEYS' }
        'RawString'        { $label = 'RAW STRINGS (unclassified)' }
    }

    Write-Host "  -- $label  ($($catGroup.Count) findings) --" -ForegroundColor Magenta
    Write-Host ''

    $bySev = $catGroup.Group | Sort-Object @{ Expression = { $sev = if ($_.PSObject.Properties.Match('Severity').Count -gt 0) { $_.Severity } else { 'INFO' }; $script:SevOrder[$sev] } }
    foreach ($f in $bySev) {
        $col = $script:SevColor[$f.Severity]
        Write-Host ('  [{0,-8}]  {1}' -f $f.Severity, $f.Description) -ForegroundColor $col
        Write-Host "  Source   : $($f.SourceFile)" -ForegroundColor DarkGray

        $disp = $f.MatchedValue
        if ($disp.Length -gt 220) { $disp = $disp.Substring(0, 220) + '...' }
        Write-Host "  Match    : $disp" -ForegroundColor White

        if ($null -ne $f.DecodedB64 -and $f.DecodedB64 -ne '') {
            $dec = $f.DecodedB64
            if ($dec.Length -gt 350) { $dec = $dec.Substring(0, 350) + '...' }
            Write-Host "  Decoded  : $dec" -ForegroundColor Green
        }
        Write-Host ''
    }
}

# Binary WPP records
$binRows = @($sorted | Where-Object { $_.PSObject.Properties.Match('RecordType').Count -gt 0 -and $_.RecordType -eq 'BinaryRecord' })
if ($binRows.Count -gt 0) {
    Write-Host "  -- WPP/ETW BINARY RECORDS  ($($binRows.Count) total) --" -ForegroundColor Magenta
    Write-Host ''

    $displayRows = $binRows | Select-Object -First 100
    foreach ($r in $displayRows) {
        $tsStr = '(no timestamp)'
        if ($null -ne $r.Timestamp) { $tsStr = $r.Timestamp.ToString('yyyy-MM-dd HH:mm:ss.fff') }

        Write-Host "  [$tsStr]  PID=$($r.PID)  TID=$($r.TID)  $($r.PatternName)" -ForegroundColor DarkGray
        Write-Host "  GUID  : $($r.MessageGUID)" -ForegroundColor DarkGray

        if ($null -ne $r.MatchedValue -and $r.MatchedValue -ne '') {
            Write-Host "  Text  : $($r.MatchedValue)" -ForegroundColor White
        }

        $hexStr    = $r.PayloadHex
        $hexPreview = ''
        $hexSuffix  = ''
        if ($null -ne $hexStr -and $hexStr.Length -gt 0) {
            if ($hexStr.Length -gt 64) {
                $hexPreview = $hexStr.Substring(0, 64)
                $hexSuffix  = '...'
            }
            else {
                $hexPreview = $hexStr
            }
            Write-Host "  Hex   : $hexPreview$hexSuffix" -ForegroundColor DarkGray
        }
        Write-Host ''
    }

    if ($binRows.Count -gt 100) {
        $remaining = $binRows.Count - 100
        Write-Host "  ... $remaining additional records in CSV output" -ForegroundColor DarkGray
        Write-Host ''
    }
}

# Summary counts
$critC = @($allFindings | Where-Object { $_.PSObject.Properties.Match('Severity').Count -gt 0 -and $_.Severity -eq 'CRITICAL' }).Count
$highC = @($allFindings | Where-Object { $_.PSObject.Properties.Match('Severity').Count -gt 0 -and $_.Severity -eq 'HIGH'     }).Count
$medC  = @($allFindings | Where-Object { $_.PSObject.Properties.Match('Severity').Count -gt 0 -and $_.Severity -eq 'MEDIUM'   }).Count
$infoC = @($allFindings | Where-Object { $_.PSObject.Properties.Match('Severity').Count -gt 0 -and $_.Severity -eq 'INFO'     }).Count
$binC  = $binRows.Count

$totalKB = [math]::Round($totalBytes / 1024, 1)

Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host '  SUMMARY' -ForegroundColor Cyan
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host "  Files processed  : $processedFiles  ($totalKB KB)"

$critColor = 'Green'
if ($critC -gt 0) { $critColor = 'Red' }
$highColor = 'Green'
if ($highC -gt 0) { $highColor = 'Yellow' }
$medColor = 'Green'
if ($medC -gt 0) { $medColor = 'Cyan' }

Write-Host "  Total findings   : $($allFindings.Count)"
Write-Host "  [CRITICAL]       : $critC" -ForegroundColor $critColor
Write-Host "  [HIGH]           : $highC" -ForegroundColor $highColor
Write-Host "  [MEDIUM]         : $medC"  -ForegroundColor $medColor
Write-Host "  [INFO / WPP]     : $infoC (includes $binC binary records)" -ForegroundColor DarkGray
Write-Host ''

#endregion

#region -- CSV Export ---------------------------------------------------------

if (-not $NoExport) {
    if (-not $ExportCsv) {
        $ts        = Get-Date -Format 'yyyyMMdd-HHmmss'
        $ExportCsv = '.\MpWppTracing-Findings-' + $ts + '.csv'
    }

    $allFindings |
        Select-Object SourceFile, Severity, Category, PatternName, Description,
                      Timestamp, PID, TID, MessageGUID, Flags, PayloadSize,
                      MatchedValue, DecodedB64, PayloadHex, RecordOffset |
        Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8

    Write-Host "  CSV exported     : $ExportCsv" -ForegroundColor Green
    Write-Host ''
}

#endregion

return $allFindings
