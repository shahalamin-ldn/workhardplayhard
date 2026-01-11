File Integrity Checker (PowerShell)
==================================

A cross-platform PowerShell tool for detecting unauthorized or unexpected file changes by comparing cryptographic hashes against a trusted baseline. Designed for security monitoring, incident response, audits, and automation workflows.

------------------------------------------------------------
Overview
------------------------------------------------------------

File integrity monitoring (FIM) helps identify changes to files that may indicate:

- Unauthorized modification
- Misconfiguration
- Malware activity
- Accidental deletion or configuration drift

This tool operates in two phases:

1) Baseline – Create a trusted snapshot of files and their cryptographic hashes
2) Verify   – Recalculate hashes later and report changes

The tool is written in PowerShell Core and runs on Windows, macOS, and Linux.

------------------------------------------------------------
Key Features
------------------------------------------------------------

- Cryptographic hashing (default: SHA-256)
- Baseline creation and integrity verification
- Detection of:
  - Modified files
  - Missing files
  - New files
- Manifest tamper detection:
  - SHA-256 signature
  - Optional certificate-based signing (CMS / PKCS#7)
- Structured output:
  - JSON (for SIEM / automation)
  - CSV (for reporting)
- Quiet mode for scheduled jobs
- Automation-friendly exit codes
- Cross-platform PowerShell support

------------------------------------------------------------
Requirements
------------------------------------------------------------

- PowerShell Core 7.x or later
- Uses built-in .NET cryptography libraries

------------------------------------------------------------
How It Works
------------------------------------------------------------

Baseline Phase
--------------

During baseline creation, the tool:

- Walks the target directory
- Calculates a cryptographic hash for each file
- Records metadata (path, size, timestamp)
- Writes the results to a JSON manifest
- Generates a tamper-detection signature for the manifest

This baseline represents a known-good state.

Verify Phase
------------

During verification, the tool:

- Validates the integrity of the manifest itself
- Re-hashes current files
- Compares current hashes to the baseline
- Reports:
  - Modified files (hash mismatch)
  - Missing files (baseline file not found)
  - New files (present now, not in baseline)

------------------------------------------------------------
Manifest File Explained
------------------------------------------------------------

The manifest (manifest.json) is a structured record of the baseline.

Example (simplified):

{
  "GeneratedAtUtc": "2026-01-11T12:00:00Z",
  "RootPath": "/path/to/testdata",
  "Algorithm": "SHA256",
  "Recurse": true,
  "ExcludeExtensions": [".tmp", ".log"],
  "FileCount": 3,
  "Files": [
    {
      "Path": "/path/to/testdata/file1.txt",
      "Hash": "A94A8FE5...",
      "Algorithm": "SHA256",
      "SizeBytes": 11,
      "LastWriteTimeUtc": "2026-01-11T12:00:00Z"
    }
  ]
}

What the hash represents
------------------------

A cryptographic hash is a one-way fingerprint of file contents.

- Any change to a file produces a completely different hash
- Hashes cannot be reversed to recover file contents
- SHA-256 provides strong collision resistance

Hash comparison is the primary integrity signal.

------------------------------------------------------------
Manifest Tamper Detection
------------------------------------------------------------

Because the manifest itself is security-critical, the tool supports tamper detection.

SHA-256 Signature (Default)
---------------------------

During baseline:
- A SHA-256 hash of manifest.json is written to manifest.json.sha256

During verify:
- The manifest hash is recomputed and compared
- A mismatch indicates the manifest was modified

This provides tamper evidence.

Certificate-Based Signing (Optional)
------------------------------------

For stronger protection, the manifest can be signed using a certificate:

- Detached CMS signature (manifest.json.p7s)
- Uses a private key from a PFX file
- Verification validates the cryptographic signature

This better reflects enterprise-grade integrity protection.

------------------------------------------------------------
Usage
------------------------------------------------------------

Create a baseline
-----------------

./Invoke-FileIntegrityCheck.ps1 -Mode baseline -Path ./testdata -ManifestPath ./baseline/manifest.json -Recurse

Creates:
- baseline/manifest.json
- baseline/manifest.json.sha256

Verify integrity
----------------

./Invoke-FileIntegrityCheck.ps1 -Mode verify -Path ./testdata -ManifestPath ./baseline/manifest.json

Strict tamper enforcement (SHA-256)
-----------------------------------

Fails verification if the signature file is missing or invalid:

./Invoke-FileIntegrityCheck.ps1 -Mode verify -Path ./testdata -ManifestPath ./baseline/manifest.json -RequireManifestSignature

Certificate-signed baseline
---------------------------

$pw = Read-Host -AsSecureString "Enter PFX password"

./Invoke-FileIntegrityCheck.ps1 -Mode baseline -Path ./testdata -ManifestPath ./baseline/manifest.json -Recurse -SignManifest -PfxPath ./certs/manifest-signing.pfx -PfxPassword $pw

Require signed manifest during verify
-------------------------------------

./Invoke-FileIntegrityCheck.ps1 -Mode verify -Path ./testdata -ManifestPath ./baseline/manifest.json -RequireSignedManifest

------------------------------------------------------------
Structured Output (SIEM / Automation)
------------------------------------------------------------

JSON output:

./Invoke-FileIntegrityCheck.ps1 -Mode verify -Path ./testdata -ManifestPath ./baseline/manifest.json -OutJson ./output/verify.json

CSV output:

./Invoke-FileIntegrityCheck.ps1 -Mode verify -Path ./testdata -ManifestPath ./baseline/manifest.json -OutCsv ./output/verify.csv

These formats are suitable for ingestion into SIEM platforms, log pipelines, or scheduled monitoring jobs.

------------------------------------------------------------
Quiet Mode (Automation)
------------------------------------------------------------

Suppresses console output and relies on exit codes:

./Invoke-FileIntegrityCheck.ps1 -Mode verify -Path ./testdata -ManifestPath ./baseline/manifest.json -Quiet

------------------------------------------------------------
Exit Codes
------------------------------------------------------------

0 = No changes detected
2 = Modified, missing, or new files detected
1 = Error (including tamper detection failure)

------------------------------------------------------------
Enterprise Context
------------------------------------------------------------

In an enterprise environment, this tool can support:

- Incident response investigations
- Configuration drift detection
- Post-deployment validation
- Compliance and audit workflows
- Scheduled integrity checks with alerting

Baselines should be created after systems are hardened and stored securely.
Manifests and signing keys should be access-controlled.

------------------------------------------------------------
Limitations
------------------------------------------------------------

- Hash-based detection identifies changes but not intent
- Does not replace EDR or host-based intrusion detection
- Manifest protection is only as strong as filesystem access controls

------------------------------------------------------------
Future Enhancements
------------------------------------------------------------

- Windows Event Log output
- Scheduled mode
- Manifest encryption
- Remote baseline storage
- Native SIEM connectors

------------------------------------------------------------
License
------------------------------------------------------------

MIT License
