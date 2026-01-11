#!/usr/bin/env pwsh
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("baseline", "verify")]
    [string]$Mode,

    [Parameter(Mandatory = $true)]
    [string]$Path,

    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,

    [ValidateSet("SHA256", "SHA1", "MD5")]
    [string]$Algorithm = "SHA256",

    [switch]$Recurse,

    [string[]]$ExcludeExtensions = @(".tmp", ".log"),

    [string[]]$ExcludePaths = @(),

    # If set, verification will fail if the signature file is missing.
    [switch]$RequireManifestSignature
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-FullPath {
    param([string]$P)
    try {
        return (Resolve-Path -Path $P).Path
    } catch {
        $parent = Split-Path -Parent $P
        if ($parent -and (Test-Path $parent)) {
            $leaf = Split-Path -Leaf $P
            return (Join-Path (Resolve-Path $parent).Path $leaf)
        }
        return $P
    }
}

function Get-FilteredFiles {
    param(
        [string]$Root,
        [switch]$DoRecurse,
        [string[]]$ExcludeExtensions,
        [string[]]$ExcludePaths
    )

    if (!(Test-Path -Path $Root)) {
        throw "Target path not found: $Root"
    }

    $items = Get-ChildItem -Path $Root -File -Force -Recurse:$DoRecurse

    $excludeExtLower = $ExcludeExtensions | ForEach-Object { $_.ToLower() }

    $filtered = $items | Where-Object {
        $extOk = ($excludeExtLower -notcontains $_.Extension.ToLower())
        $pathOk = $true

        foreach ($p in $ExcludePaths) {
            if ($_.FullName -like "$p*") {
                $pathOk = $false
                break
            }
        }

        $extOk -and $pathOk
    }

    return $filtered
}

function Write-ManifestJson {
    param(
        [object]$ManifestObject,
        [string]$OutPath
    )

    $outDir = Split-Path -Parent $OutPath
    if ($outDir -and !(Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }

    $ManifestObject |
        ConvertTo-Json -Depth 8 |
        Out-File -FilePath $OutPath -Encoding utf8 -Force
}

function Get-ManifestSignaturePath {
    param([string]$ManifestFilePath)
    return "$ManifestFilePath.sha256"
}

function Write-ManifestSignature {
    param([string]$ManifestFilePath)

    if (!(Test-Path $ManifestFilePath)) {
        throw "Cannot write signature. Manifest not found: $ManifestFilePath"
    }

    $sigPath = Get-ManifestSignaturePath -ManifestFilePath $ManifestFilePath
    $hash = Get-FileHash -Path $ManifestFilePath -Algorithm SHA256

    # Store only the hash in the file
    $hash.Hash | Out-File -FilePath $sigPath -Encoding ascii -Force
}

function Assert-ManifestNotTampered {
    param(
        [string]$ManifestFilePath,
        [switch]$RequireSignature
    )

    if (!(Test-Path $ManifestFilePath)) {
        throw "Manifest not found: $ManifestFilePath"
    }

    $sigPath = Get-ManifestSignaturePath -ManifestFilePath $ManifestFilePath

    if (!(Test-Path $sigPath)) {
        if ($RequireSignature) {
            throw "Manifest signature file is required but missing: $sigPath"
        } else {
            Write-Warning "Manifest signature file missing: $sigPath. Tamper detection is not enforced."
            return
        }
    }

    $expected = (Get-Content -Path $sigPath -Raw).Trim()
    if ([string]::IsNullOrWhiteSpace($expected)) {
        throw "Manifest signature file is empty: $sigPath"
    }

    $actual = (Get-FileHash -Path $ManifestFilePath -Algorithm SHA256).Hash

    if ($actual -ne $expected) {
        throw "Manifest tamper detected. Manifest hash does not match signature file."
    }
}

function New-Baseline {
    param(
        [string]$Root,
        [string]$OutManifest,
        [string]$Algorithm,
        [switch]$DoRecurse,
        [string[]]$ExcludeExtensions,
        [string[]]$ExcludePaths
    )

    $files = Get-FilteredFiles -Root $Root -DoRecurse:$DoRecurse `
        -ExcludeExtensions $ExcludeExtensions `
        -ExcludePaths $ExcludePaths

    $records = foreach ($f in $files) {
        $hash = Get-FileHash -Path $f.FullName -Algorithm $Algorithm
        [PSCustomObject]@{
            Path = $f.FullName
            Hash = $hash.Hash
            Algorithm = $Algorithm
            SizeBytes = $f.Length
            LastWriteTimeUtc = $f.LastWriteTimeUtc.ToString("o")
        }
    }

    $manifest = [PSCustomObject]@{
        GeneratedAtUtc    = (Get-Date).ToUniversalTime().ToString("o")
        RootPath          = (Resolve-FullPath $Root)
        Algorithm         = $Algorithm
        Recurse           = [bool]$DoRecurse
        ExcludeExtensions = $ExcludeExtensions
        ExcludePaths      = $ExcludePaths
        FileCount         = $records.Count
        Files             = $records
    }

    Write-ManifestJson -ManifestObject $manifest -OutPath $OutManifest
    Write-ManifestSignature -ManifestFilePath $OutManifest

    Write-Host ""
    Write-Host "Baseline created"
    Write-Host "Root:      $Root"
    Write-Host "Manifest:  $OutManifest"
    Write-Host "Signature: $(Get-ManifestSignaturePath -ManifestFilePath $OutManifest)"
    Write-Host "Algorithm: $Algorithm"
    Write-Host "Files:     $($records.Count)"
    Write-Host ""
}

function Compare-Integrity {
    param(
        [string]$Root,
        [string]$ManifestFile
    )

    Assert-ManifestNotTampered -ManifestFilePath $ManifestFile -RequireSignature:$RequireManifestSignature

    $manifest = Get-Content -Path $ManifestFile -Raw | ConvertFrom-Json
    $algo = $manifest.Algorithm

    $baselineMap = @{}
    foreach ($f in $manifest.Files) {
        $baselineMap[$f.Path] = $f.Hash
    }

    $currentFiles = Get-FilteredFiles -Root $Root `
        -DoRecurse:([bool]$manifest.Recurse) `
        -ExcludeExtensions $manifest.ExcludeExtensions `
        -ExcludePaths $manifest.ExcludePaths

    $currentMap = @{}
    foreach ($f in $currentFiles) {
        $hash = Get-FileHash -Path $f.FullName -Algorithm $algo
        $currentMap[$f.FullName] = $hash.Hash
    }

    $modified = @()
    $missing  = @()
    $new      = @()

    foreach ($path in $baselineMap.Keys) {
        if ($currentMap.ContainsKey($path)) {
            if ($currentMap[$path] -ne $baselineMap[$path]) {
                $modified += $path
            }
        } else {
            $missing += $path
        }
    }

    foreach ($path in $currentMap.Keys) {
        if (-not $baselineMap.ContainsKey($path)) {
            $new += $path
        }
    }

    return [PSCustomObject]@{
        RootPath = $manifest.RootPath
        Manifest = $ManifestFile
        Algorithm = $algo
        BaselineGeneratedAtUtc = $manifest.GeneratedAtUtc
        Summary = [PSCustomObject]@{
            ModifiedCount = $modified.Count
            MissingCount  = $missing.Count
            NewCount      = $new.Count
        }
        Modified = $modified
        Missing  = $missing
        New      = $new
    }
}

try {
    if (!(Test-Path $Path)) {
        throw "Target path not found: $Path"
    }

    if ($Mode -eq "baseline") {
        New-Baseline -Root $Path -OutManifest $ManifestPath `
            -Algorithm $Algorithm -DoRecurse:$Recurse `
            -ExcludeExtensions $ExcludeExtensions `
            -ExcludePaths $ExcludePaths
        exit 0
    }

    if ($Mode -eq "verify") {
        $result = Compare-Integrity -Root $Path -ManifestFile $ManifestPath

        Write-Host ""
        Write-Host "Integrity Check Results"
        Write-Host "Modified: $($result.Summary.ModifiedCount)"
        Write-Host "Missing : $($result.Summary.MissingCount)"
        Write-Host "New     : $($result.Summary.NewCount)"
        Write-Host ""

        $delta = $result.Summary.ModifiedCount +
                 $result.Summary.MissingCount +
                 $result.Summary.NewCount

        if ($delta -gt 0) { exit 2 } else { exit 0 }
    }

    throw "Invalid mode specified"
}
catch {
    Write-Error $_
    exit 1
}
