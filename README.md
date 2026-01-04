# frostsnap-thaw

Emergency recovery tool for FROST backup shares.

## What this does

Reconstructs Bitcoin wallet from Frostsnap backup shares (recovery cards) when Frostsnap is unavailable.

## Usage

```bash
python3 reconstruct_frost_backups.py
```

Outputs xpriv and descriptor for import into Bitcoin Core or Sparrow Wallet.

## Requirements

```bash
pip install -r requirements.txt
```

## Testing

```bash
python3 test.py
```

## Limitations

Minimal implementation for emergency recovery. Does not include:
- Polynomial checksum verification
- Fingerprint grinding verification
- Fuzzy recovery (auto-finding valid share subsets)

You must provide the correct threshold of backups that belong together.

## Security

**Run on a fresh, offline, secure machine only.** Private keys will be displayed.
