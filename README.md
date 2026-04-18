# frostsnap-thaw

Emergency recovery tool for FROST backups.

## Overview

Reconstructs Bitcoin wallet extended private key (`xpriv`) from Frostsnap backups if the original software is unavailable. Implements Shamir secret sharing reconstruction with full checksum verification.

## Usage

```bash
pip install -r requirements.txt
python3 reconstruct_frost_backups.py
```

The tool will prompt for your shares and output an xpriv and descriptor for wallet import.

**Security:** Run only on a fresh, offline, secure machine. Private keys are displayed on screen.

## Testing

```bash
python3 test.py
```

29 tests validate against Frostsnap test vectors.

## Implementation

The tool implements:

- Lagrange interpolation for threshold secret recovery
- Words checksum validation (detects transcription errors)
- Polynomial checksum verification (detects mismatched shares)
- BIP32 xpriv generation
- Taproot descriptor output

Uses `secp256k1` Python bindings for elliptic curve operations.

## Checksums

Two checksums are verified per the FROST backup specification v0:

**Words checksum (11-bit):** SHA256-based validation of individual share integrity. Catches transcription errors.

**Polynomial checksum (8-bit):** Validates that all shares belong to the same wallet by reconstructing the polynomial commitment and verifying each share's embedded checksum.

Note: Fingerprint grinding verification is not implemented. It protects against public key substitution by malicious coordinators during FROST signing sessions. Since this tool reconstructs the full secret offline, that attack vector doesn't apply.
