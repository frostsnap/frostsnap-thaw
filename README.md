# frostsnap-thaw

Emergency recovery tool for FROST backups.

Note: this tool should only be considered in emergency situations on a fresh, offline, secure machine. Private keys are displayed on screen. The entire purpose of FROST is to avoid this situation of the secret key existing on a single device!

## Overview

Reconstructs Bitcoin wallet extended private key (`xpriv`) from FROST backups if the original software is unavailable. Implements Shamir secret sharing reconstruction with full checksum verification. The reconstituted `xpriv` can be loaded into another wallet such as Bitcoin Core or Sparrow.

## Usage

```bash
pip install -r requirements.txt
python3 reconstruct_frost_backups.py
```

The tool will prompt for your shares and output an xpriv and descriptor for wallet import.

## Importing into a wallet

The descriptor is the complete recovery artifact: it encodes the key, the Taproot script type, and the derivation path, and carries its own checksum. Import it into any descriptor-aware wallet to access your funds. Two things to get right:

- **Bitcoin Core must be v28.0 or newer.** Earlier versions reject the `<0;1>` multipath descriptor with a parse error. Multipath descriptor support ([BIP 389](https://github.com/bitcoin/bips/blob/master/bip-0389.mediawiki)) landed in Core 28.0.
- **Rescan from before the wallet was created.** When importing, set the rescan start time to the wallet's creation date — or `0` to scan from genesis (slower, but always complete). A `now` timestamp scans nothing prior and silently finds no existing coins. No Frostsnap wallet existed before mid-2025, so a `timestamp` of `1735689600` (2025-01-01 UTC) or `0` is always a safe floor.

Once imported and rescanned, checking your balance and spending are standard descriptor-wallet operations; follow your wallet's normal documentation for those steps.

## Testing

```bash
python3 test.py
```

32 tests cover share parsing, secret recovery, and descriptor generation (including a golden-vector test pinning the exact xpriv/descriptor output to the Rust reference).

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
