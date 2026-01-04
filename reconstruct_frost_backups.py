#!/usr/bin/env python3
"""
FROST Backup Emergency Recovery Tool

This tool recovers Bitcoin wallets from FROST backup shares.
It is designed for emergency recovery if Frostsnap ceases operations.

WARNING: Only run this on a secure offline machine!

Reference implementation: https://github.com/frostsnap/frostsnap
Based on frost_backup specification v0
"""

import sys
import hashlib
import re
from typing import List
from mnemonic import Mnemonic

# secp256k1 curve order (for Shamir secret sharing field arithmetic)
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Constants from FROST backup specification
NUM_WORDS = 25
BITS_PER_WORD = 11
TOTAL_BITS = NUM_WORDS * BITS_PER_WORD  # 275 bits
SCALAR_BITS = 256
POLY_CHECKSUM_BITS = 8
WORDS_CHECKSUM_BITS = 11
POLY_CHECKSUM_START = SCALAR_BITS  # 256
WORDS_CHECKSUM_START = POLY_CHECKSUM_START + POLY_CHECKSUM_BITS  # 264


class ShareBackupError(Exception):
    """Errors during share parsing and validation"""
    pass


class ShareBackup:
    """
    Represents a parsed FROST backup share.

    Format: #<index> <25 BIP39 words>

    Bit layout (275 bits):
    - Bits 0-255: Secret share scalar (32 bytes)
    - Bits 256-263: Polynomial checksum (8 bits)
    - Bits 264-274: Words checksum (11 bits)
    """

    def __init__(self, index: int, scalar_bytes: bytes, poly_checksum: int):
        if index == 0:
            raise ShareBackupError("Share index cannot be 0")
        if len(scalar_bytes) != 32:
            raise ShareBackupError(f"Scalar must be 32 bytes, got {len(scalar_bytes)}")

        self.index = index
        self.scalar_bytes = scalar_bytes
        self.poly_checksum = poly_checksum

    @classmethod
    def from_string(cls, share_string: str) -> 'ShareBackup':
        """Parse a share string into a ShareBackup object."""
        share_string = share_string.strip()
        match = re.match(r'#(\d+)\s+(.+)', share_string)
        if not match:
            raise ShareBackupError("Invalid format. Expected: #<index> <25 words>")

        index = int(match.group(1))
        words = match.group(2).upper().split()

        if len(words) != NUM_WORDS:
            raise ShareBackupError(f"Expected {NUM_WORDS} words, got {len(words)}")

        # Convert words to 11-bit indices using BIP39 wordlist
        mnem = Mnemonic("english")
        wordlist = mnem.wordlist
        word_indices = []

        for i, word in enumerate(words):
            word_lower = word.lower()
            if word_lower not in wordlist:
                raise ShareBackupError(f"Word #{i+1} '{word}' not in BIP39 wordlist")
            word_indices.append(wordlist.index(word_lower))

        # Unpack 275 bits into components
        scalar_bytes = bytearray(32)
        poly_checksum = 0
        words_checksum = 0
        total_bits_processed = 0

        for word_idx in word_indices:
            for bit_offset in range(BITS_PER_WORD - 1, -1, -1):
                bit = (word_idx >> bit_offset) & 1
                if bit != 0:
                    if total_bits_processed < SCALAR_BITS:
                        byte_index = total_bits_processed // 8
                        bit_in_byte = total_bits_processed % 8
                        scalar_bytes[byte_index] |= (1 << (7 - bit_in_byte))
                    elif total_bits_processed < WORDS_CHECKSUM_START:
                        checksum_bit = total_bits_processed - POLY_CHECKSUM_START
                        poly_checksum |= (1 << (POLY_CHECKSUM_BITS - 1 - checksum_bit))
                    elif total_bits_processed < TOTAL_BITS:
                        checksum_bit = total_bits_processed - WORDS_CHECKSUM_START
                        words_checksum |= (1 << (WORDS_CHECKSUM_BITS - 1 - checksum_bit))
                total_bits_processed += 1

        # Validate words checksum
        expected_checksum = compute_words_checksum(index, bytes(scalar_bytes), poly_checksum)
        if expected_checksum != words_checksum:
            raise ShareBackupError(
                f"Words checksum failed (expected {expected_checksum}, got {words_checksum}). "
                "Likely transcription error."
            )

        return cls(index, bytes(scalar_bytes), poly_checksum)


def compute_words_checksum(index: int, scalar_bytes: bytes, poly_checksum: int) -> int:
    """Compute the words checksum for validation."""
    h = hashlib.sha256()
    h.update(index.to_bytes(4, 'big'))
    h.update(scalar_bytes)
    h.update(poly_checksum.to_bytes(2, 'big'))
    digest = h.digest()
    return ((digest[0] << 3) | (digest[1] >> 5)) & 0x7FF


def lagrange_coefficient(x_i: int, x_values: List[int]) -> int:
    """Compute Lagrange coefficient L_i(0) in secp256k1 field."""
    numerator = 1
    denominator = 1

    for x_j in x_values:
        if x_j != x_i:
            numerator = (numerator * ((-x_j) % SECP256K1_ORDER)) % SECP256K1_ORDER
            denominator = (denominator * ((x_i - x_j) % SECP256K1_ORDER)) % SECP256K1_ORDER

    denominator_inv = pow(denominator, SECP256K1_ORDER - 2, SECP256K1_ORDER)
    return (numerator * denominator_inv) % SECP256K1_ORDER


def recover_secret(shares: List[ShareBackup]) -> bytes:
    """Recover secret from threshold shares using Lagrange interpolation."""
    if not shares:
        raise ValueError("No shares provided")

    indices = [share.index for share in shares]
    scalars = [int.from_bytes(share.scalar_bytes, 'big') for share in shares]

    if len(indices) != len(set(indices)):
        raise ValueError("Duplicate share indices detected")

    secret = 0
    for x_i, y_i in zip(indices, scalars):
        coeff = lagrange_coefficient(x_i, indices)
        secret = (secret + (coeff * y_i)) % SECP256K1_ORDER

    return secret.to_bytes(32, 'big')


def generate_xpriv(secret_bytes: bytes, network: str = 'mainnet') -> str:
    """Generate BIP32 extended private key from the recovered secret."""
    import base58

    version = bytes.fromhex('0488ADE4' if network == 'mainnet' else '04358394')
    depth = bytes([0])
    parent_fingerprint = bytes(4)
    child_number = bytes(4)
    chain_code = bytes(32)
    key_data = bytes([0]) + secret_bytes

    serialized = version + depth + parent_fingerprint + child_number + chain_code + key_data
    checksum = hashlib.sha256(hashlib.sha256(serialized).digest()).digest()[:4]

    return base58.b58encode(serialized + checksum).decode('ascii')


def generate_descriptor(xpriv: str) -> str:
    """Generate Bitcoin descriptor for the wallet (Taproot)."""
    return f"tr({xpriv}/0/0/0/0/<0;1>/*)"


def interactive_recovery():
    """Run interactive recovery session."""
    print("\nFROST Backup Emergency Recovery Tool")
    print("=" * 70)
    print("WARNING: Run on air-gapped machine only. Private keys will be displayed.")
    print("=" * 70)

    input("\nPress ENTER to continue...")

    # Get threshold
    threshold_str = input("\nHow many shares are required (threshold)? ")
    try:
        threshold = int(threshold_str)
        if threshold < 1:
            raise ValueError()
    except ValueError:
        print("Error: Invalid threshold")
        sys.exit(1)

    # Collect shares
    shares = []
    print(f"\nEnter {threshold} shares (format: #<number> <25 BIP39 words>)\n")

    for i in range(threshold):
        while True:
            share_str = input(f"Share {i+1}/{threshold}: ").strip()
            if not share_str:
                print("  Error: Empty input")
                continue

            try:
                share = ShareBackup.from_string(share_str)
                shares.append(share)
                print(f"  OK: Share #{share.index} validated")
                break
            except ShareBackupError as e:
                print(f"  Error: {e}")
                if input("  Try again? (y/n): ").lower() != 'y':
                    sys.exit(1)

    # Verify unique shares
    if len(set(s.index for s in shares)) < threshold:
        print("\nError: Duplicate share indices")
        sys.exit(1)

    # Recover secret
    print("\nRecovering secret...")
    try:
        secret = recover_secret(shares)
    except Exception as e:
        print(f"Error: Recovery failed - {e}")
        sys.exit(1)

    # Get network
    network_input = input("Network (mainnet/testnet) [mainnet]: ").strip().lower()
    network = 'testnet' if network_input == 'testnet' else 'mainnet'

    # Generate outputs
    try:
        xpriv = generate_xpriv(secret, network)
        descriptor = generate_descriptor(xpriv)
    except Exception as e:
        print(f"Error: Key generation failed - {e}")
        sys.exit(1)

    # Display results
    print("\n" + "=" * 70)
    print("RECOVERY SUCCESSFUL")
    print("=" * 70)
    print(f"\nSecret:     {secret.hex()}")
    print(f"Shares:     {', '.join(f'#{s.index}' for s in shares)}")
    print(f"\nxpriv:      {xpriv}")
    print(f"Descriptor: {descriptor}")

    print("\n" + "=" * 70)
    print("IMPORT TO WALLET")
    print("=" * 70)
    print("\nBitcoin Core (v22.0+):")
    print("  importdescriptors '[{\"desc\": \"<descriptor>\", \"timestamp\": \"now\"}]'")
    print("\nSparrow Wallet:")
    print("  File > Import Wallet > Descriptor")
    print("\nIMPORTANT: Verify addresses match before using!")
    print("=" * 70 + "\n")


def main():
    """Main entry point."""
    if len(sys.argv) > 1 and sys.argv[1] in ['--help', '-h']:
        print(__doc__)
        print("\nUsage: python3 reconstruct_frost_backups.py")
        print("\nReconstructs Bitcoin wallet from FROST backup shares.")
        print("Outputs xpriv and descriptor for import into Bitcoin Core or Sparrow.\n")
        sys.exit(0)

    try:
        interactive_recovery()
    except KeyboardInterrupt:
        print("\n\nAborted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nFatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
