[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateRange(8,128)]
    [int]$Length = 16,

    [switch]$IncludeSymbols,
    [switch]$NoAmbiguous
)

# Character sets
$Lower   = "abcdefghijklmnopqrstuvwxyz"
$Upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
$Digits  = "0123456789"
$Symbols = "!@#$%^&*()-_=+[]{};:,.?/"

$Ambiguous = "O0Il1"

# Build allowed character set
$Allowed = $Lower + $Upper + $Digits
if ($IncludeSymbols) {
    $Allowed += $Symbols
}

if ($NoAmbiguous) {
    $Allowed = ($Allowed.ToCharArray() | Where-Object { $Ambiguous -notcontains $_ }) -join ""
}

if ($Allowed.Length -eq 0) {
    Write-Error "No valid characters available."
    exit 1
}

# Cryptographically secure RNG
$Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$Bytes = New-Object byte[] ($Length)
$Rng.GetBytes($Bytes)

$PasswordChars = for ($i = 0; $i -lt $Length; $i++) {
    $Allowed[ $Bytes[$i] % $Allowed.Length ]
}

$Password = -join $PasswordChars

# Entropy estimation
$EntropyBits = [Math]::Round($Length * [Math]::Log2($Allowed.Length), 2)

# Strength label
switch ($EntropyBits) {
    {$_ -lt 35} { $Strength = "Weak"; break }
    {$_ -lt 60} { $Strength = "Okay"; break }
    {$_ -lt 80} { $Strength = "Strong"; break }
    default     { $Strength = "Very Strong" }
}

Write-Host ""
Write-Host "Generated password:`n"
Write-Host $Password
Write-Host ""
Write-Host "Stats:"
Write-Host "- Length: $Length"
Write-Host "- Character set size: $($Allowed.Length)"
Write-Host "- Estimated entropy: $EntropyBits bits"
Write-Host "- Strength: $Strength"
Write-Host ""
