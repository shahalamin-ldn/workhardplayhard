# Secure Password Generator (PowerShell)

A cross-platform PowerShell CLI tool that generates cryptographically secure passwords 
with configurable policy options and entropy-based strength estimation. 

Designed for security-conscious environments and operational use cases such as onboarding, 
incident response, and privileged access workflows.

---

## Overview

This tool generates strong passwords using a cryptographically secure random number generator provided 
by the operating system. It allows users to customize password length and character composition while 
providing an estimated entropy score to indicate password strength.

The script is implemented in PowerShell Core, making it compatible with Windows, macOS, and Linux.

---

## Security Principles
The tool is designed around the following security principles:

- **Cryptographically Secure Randomness**  
  Uses `System.Security.Cryptography.RandomNumberGenerator` to ensure passwords are generated using 
  OS-backed entropy sources rather than predictable pseudo-random functions.

- **Sufficient Keyspace and Entropy**  
  Password strength is derived from configurable length and character set size, with entropy estimated 
  using standard cryptographic calculations.

- **Policy-Aware Customization**  
  Supports optional symbol inclusion and removal of ambiguous characters to balance security requirements with usability.

---

## Features

Cryptographically secure password generation
Configurable password length
Optional symbol inclusion
Optional removal of ambiguous characters (e.g. O, 0, I, l, 1)
Entropy estimation (bits)
Human-readable strength classification
Cross-platform compatibility (PowerShell Core)


### Requirements
- PowerShell Core (`pwsh`) 7.x or later

### Basic usage
Generate a secure password using default settings (16 characters):

Powershell
./Generate-SecurePassword.ps1
