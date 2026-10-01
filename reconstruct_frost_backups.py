#!/usr/bin/env python3
"""
FROST Backup Emergency Recovery Tool

This tool recombines FROST backup shares into xprivs.
It is designed for emergency recovery if Frostsnap is unavailable or ceases operations.

WARNING: Only run this on a secure offline machine! 
This script will reconstruct and display your secret.

Reference implementation: https://github.com/frostsnap/frostsnap
Based on frost_backup specification v0
"""

import sys
import hashlib
import itertools
import re
from typing import List, Optional, Tuple
from mnemonic import Mnemonic
import secp256k1

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

# frost-v0 fingerprint parameters
FINGERPRINT_TAG = b"frost-v0"
FINGERPRINT_BITS_PER_COEFF = 18
FINGERPRINT_MAX_BITS_TOTAL = 36


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
        # Index 0 is a bare secret: the backup carries the secret itself.
        if index > 0xFFFFFFFF:
            raise ShareBackupError("Share index must fit in 32 bits")
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
        if index > 0xFFFFFFFF:
            raise ShareBackupError("Share index must fit in 32 bits")
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

        # Unpack 275 bits into components: 256 (scalar) + 8 (poly) + 11 (words checksum)
        scalar_bytes = bytearray(32)
        poly_checksum = 0
        words_checksum = 0
        total_bits_processed = 0

        # Process bits MSB-first (as specified in FROST backup format)
        for word_idx in word_indices:
            for bit_offset in range(BITS_PER_WORD - 1, -1, -1):  # 10, 9, 8, ..., 0
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

        # The scalar must be less than the group order; it is rejected, never reduced
        if int.from_bytes(scalar_bytes, 'big') >= SECP256K1_ORDER:
            raise ShareBackupError("Scalar is not less than the secp256k1 group order")

        # Validate words checksum
        expected_checksum = compute_words_checksum(index, bytes(scalar_bytes), poly_checksum)
        if expected_checksum != words_checksum:
            raise ShareBackupError(
                f"Words checksum failed (expected {expected_checksum}, got {words_checksum}). "
                "Likely transcription error."
            )

        return cls(index, bytes(scalar_bytes), poly_checksum)


def compute_words_checksum(index: int, scalar_bytes: bytes, poly_checksum: int) -> int:
    """
    Compute 11-bit words checksum.

    Returns the first 11 bits of SHA256(index || scalar || poly_checksum).
    """
    h = hashlib.sha256()
    h.update(index.to_bytes(4, 'big'))
    h.update(scalar_bytes)
    h.update(poly_checksum.to_bytes(2, 'big'))
    digest = h.digest()

    # Read first 16 bits as big-endian int, then take top 11 bits
    two_bytes = int.from_bytes(digest[0:2], 'big')
    return two_bytes >> 5


def compute_share_image(index: int, scalar_bytes: bytes) -> Tuple[int, bytes]:
    """
    Compute public share image from secret share.

    A share image is the public version of a share: share_scalar * G
    where G is the secp256k1 generator point.

    Args:
        index: Share index
        scalar_bytes: 32-byte secret share scalar

    Returns:
        Tuple of (index, 33-byte compressed secp256k1 point)
    """
    privkey = secp256k1.PrivateKey(scalar_bytes)
    pubkey = privkey.pubkey
    point_bytes = pubkey.serialize(compressed=True)
    return (index, point_bytes)


def compute_poly_checksum(index: int, scalar_bytes: bytes, poly_commitment: bytes) -> int:
    """
    Compute polynomial checksum.

    Note: Uses index as 32-byte scalar (different from words checksum which uses 4-byte u32)

    Args:
        index: Share index
        scalar_bytes: 32-byte secret share
        poly_commitment: Concatenated polynomial points (threshold * 33 bytes)

    Returns:
        8-bit checksum (0-255)
    """
    h = hashlib.sha256()
    h.update(index.to_bytes(32, 'big'))  # 32-byte scalar (different from words checksum!)
    h.update(scalar_bytes)
    h.update(poly_commitment)
    digest = h.digest()
    return digest[0]  # First 8 bits


def verify_polynomial_checksum(share: ShareBackup, poly_commitment: bytes) -> bool:
    """Verify share's polynomial checksum against reconstructed commitment."""
    expected = compute_poly_checksum(share.index, share.scalar_bytes, poly_commitment)
    return expected == share.poly_checksum


def lagrange_coefficient_for_degree(degree: int, share_index: int, all_indices: List[int]) -> int:
    """
    Compute Lagrange coefficient for extracting polynomial coefficient at given degree.

    Lagrange coefficients are scalars, but we work in the secp256k1 scalar field,
    so all arithmetic is modulo SECP256K1_ORDER.

    This builds the Lagrange basis polynomial L_i(x) = product_{j != i} ((x - x_j) / (x_i - x_j))
    and extracts the coefficient of x^degree.

    Args:
        degree: Which polynomial coefficient to extract (0 to threshold-1)
        share_index: The share's x-coordinate (x_i)
        all_indices: All share x-coordinates being used

    Returns:
        Scalar coefficient in secp256k1 field (integer mod SECP256K1_ORDER)
    """
    # Start with constant polynomial p(x) = 1
    poly = [1]

    # Build L_i(x) by multiplying (x - x_j) / (x_i - x_j) for each j != i
    for x_j in all_indices:
        if x_j == share_index:
            continue

        # Compute 1 / (x_i - x_j) in the field using modular inverse
        denom = (share_index - x_j) % SECP256K1_ORDER
        denom_inv = pow(denom, SECP256K1_ORDER - 2, SECP256K1_ORDER)  # Fermat's little theorem

        # Multiply current polynomial by (x - x_j) / denominator
        # Expanding: poly(x) * (x - x_j) = poly(x) * x - poly(x) * x_j
        new_poly = [0] * (len(poly) + 1)
        for i, coeff in enumerate(poly):
            new_poly[i + 1] = (new_poly[i + 1] + coeff) % SECP256K1_ORDER      # poly[i] * x term
            new_poly[i] = (new_poly[i] - coeff * x_j) % SECP256K1_ORDER        # -poly[i] * x_j term

        # Divide all coefficients by (x_i - x_j)
        poly = [(c * denom_inv) % SECP256K1_ORDER for c in new_poly]

    return poly[degree] if degree < len(poly) else 0


def reconstruct_polynomial_commitment(share_images: List[Tuple[int, bytes]], threshold: int) -> bytes:
    """
    Reconstruct polynomial commitment from share images.

    Uses Lagrange interpolation on elliptic curve points to recover
    the polynomial coefficients as public keys.

    Args:
        share_images: List of (index, 33-byte point) tuples
        threshold: Polynomial degree + 1

    Returns:
        Concatenated polynomial commitment bytes (threshold * 33 bytes)
    """
    indices = [idx for idx, _ in share_images]

    poly_points = []

    for degree in range(threshold):
        # Reconstruct coefficient at this degree using Lagrange interpolation
        # Collect all weighted points
        weighted_points = []

        for i, (x_i, point_bytes) in enumerate(share_images):
            # Compute Lagrange coefficient for this degree
            weight = lagrange_coefficient_for_degree(degree, x_i, indices)

            # Scalar multiply: weight * point
            pubkey = secp256k1.PublicKey(point_bytes, raw=True)
            weighted_point = pubkey.tweak_mul(weight.to_bytes(32, 'big'))
            weighted_points.append(weighted_point)

        # Combine all weighted points
        if len(weighted_points) == 1:
            # Only one point, no need to combine
            result_point = weighted_points[0]
        else:
            # Combine all points: combine() adds ALL keys in the list (doesn't add to the calling object)
            try:
                combined_cdata = weighted_points[0].combine([wp.public_key for wp in weighted_points])
            except Exception:
                # The sum is the point at infinity, i.e. a zero coefficient. That
                # happens when more shares than the true threshold are
                # interpolated. Serialize it as 33 zero bytes (as the reference
                # implementation does) so the checksum comparison reports it.
                poly_points.append(bytes(33))
                continue
            # Wrap the cdata result back into a PublicKey for serialization
            result_point = secp256k1.PublicKey(combined_cdata)

        # Serialize the coefficient point
        poly_points.append(result_point.serialize(compressed=True))

    return b''.join(poly_points)


def check_fingerprint(poly_commitment: bytes) -> Optional[int]:
    """
    Check that a polynomial commitment carries the frost-v0 fingerprint.

    A running SHA256 hash absorbs byte(len(tag)) || tag || ser(A_0). Then each
    non-constant coefficient A_j in turn must give the hash at least `needed`
    leading zero bits, until FINGERPRINT_MAX_BITS_TOTAL bits have been checked,
    so only A_1 and A_2 carry fingerprint bits. A threshold-1 polynomial has no
    non-constant coefficients and passes with 0 bits.

    Args:
        poly_commitment: Concatenated polynomial points (threshold * 33 bytes)

    Returns:
        The number of fingerprint bits verified, or None if the check fails
    """
    coeffs = [poly_commitment[i:i + 33] for i in range(0, len(poly_commitment), 33)]
    state = hashlib.sha256(bytes([len(FINGERPRINT_TAG)]) + FINGERPRINT_TAG + coeffs[0])
    bits = 0
    for coeff in coeffs[1:]:
        needed = min(FINGERPRINT_BITS_PER_COEFF, FINGERPRINT_MAX_BITS_TOTAL - bits)
        if needed == 0:
            break
        # digest_with(state, coeff): the digest after absorbing coeff, leaving state unchanged
        with_coeff = state.copy()
        with_coeff.update(coeff)
        digest = with_coeff.digest()
        # Leading zero bits of the 32-byte digest, most significant bit first
        if 256 - int.from_bytes(digest, 'big').bit_length() < needed:
            return None
        state.update(coeff)
        bits += needed
    return bits


def lagrange_coefficient(x_i: int, x_values: List[int], x: int = 0) -> int:
    """Compute Lagrange coefficient L_i(x) in secp256k1 field (L_i(0) by default)."""
    numerator = 1
    denominator = 1

    for x_j in x_values:
        if x_j != x_i:
            numerator = (numerator * ((x - x_j) % SECP256K1_ORDER)) % SECP256K1_ORDER
            denominator = (denominator * ((x_i - x_j) % SECP256K1_ORDER)) % SECP256K1_ORDER

    denominator_inv = pow(denominator, SECP256K1_ORDER - 2, SECP256K1_ORDER)
    return (numerator * denominator_inv) % SECP256K1_ORDER


def recover_secret(shares: List[ShareBackup], threshold: int = None) -> bytes:
    """
    Recover secret from threshold shares using Lagrange interpolation.

    The shares are verified together first: the public polynomial F
    interpolated from `threshold` of them must carry the frost-v0 fingerprint,
    every share must lie on F, and every share's polynomial checksum must
    verify against F.

    Args:
        shares: List of ShareBackup objects
        threshold: Polynomial threshold. If omitted it is discovered by trying
            subsets of 2, 3, ... shares and keeping the first F with the
            most fingerprint bits. A lone share needs threshold 1 stated.

    Returns:
        32-byte secret

    Raises:
        ValueError: If the shares do not verify together
    """
    if not shares:
        raise ValueError("No shares provided")

    # A #0 backup is not a share: it is recovered on its own
    if any(share.index == 0 for share in shares):
        return recover_bare_secret(shares)

    # Interpolation needs distinct indices, so a subset takes one share per
    # index; different shares at one index (shares of different keys usually
    # both start at #1) are tried in turn
    shares_by_index = {}
    for share in shares:
        shares_by_index.setdefault(share.index, []).append(share)
    indices = sorted(shares_by_index)

    # Without a threshold, subset sizes start at 2 since a single share has no
    # fingerprint to check. A lone share is recovered as a threshold-1 key only
    # when threshold 1 is stated: a share of a larger key would pass its 8-bit
    # polynomial checksum 1 time in 256 and give a wrong secret.
    if threshold is not None:
        if threshold < 1:
            raise ValueError("Threshold must be at least 1")
        min_size = threshold
    elif len(shares) == 1:
        raise ValueError(
            "One share is not enough to recover the key. Enter more shares. If the "
            "wallet needs only one share (threshold 1), state threshold 1."
        )
    else:
        min_size = 2
    if len(indices) < min_size:
        raise ValueError(f"Need at least {min_size} shares with different indices, got {len(indices)}")
    sizes = [threshold] if threshold is not None else range(min_size, len(indices) + 1)

    # Interpolate F from each subset and check its fingerprint. As in the Rust
    # reference (frost_backup's find_valid_subset), keep the first F with the
    # most fingerprint bits: a threshold-2 key carries only 18, so the search
    # goes on to larger subsets and stops early only at the full 36.
    subsets = (
        subset
        for size in sizes
        for index_combo in itertools.combinations(indices, size)
        for subset in itertools.product(*(shares_by_index[i] for i in index_combo))
    )
    best = None
    for subset in subsets:
        share_images = [compute_share_image(s.index, s.scalar_bytes) for s in subset]
        poly_commitment = reconstruct_polynomial_commitment(share_images, len(subset))
        # A zero top coefficient means the subset fits a smaller threshold: a
        # smaller subset finds that F, and a stated threshold rules it out
        if poly_commitment[-33:] == bytes(33):
            continue
        bits = check_fingerprint(poly_commitment)
        if bits is not None and (best is None or bits > best[0]):
            best = (bits, subset, poly_commitment)
            if bits == FINGERPRINT_MAX_BITS_TOTAL:
                break

    if best is None:
        if threshold is not None:
            raise ValueError(
                f"Fingerprint check failed: no {threshold} of these shares form a key with "
                f"threshold {threshold}. The threshold may be wrong, or a share is from a "
                "different key or was mistranscribed."
            )
        raise ValueError(
            "Fingerprint check failed: no group of these shares forms a key. Fewer shares "
            "than the threshold may have been given, or a share is from a different key "
            "or was mistranscribed."
        )
    _, subset, poly_commitment = best
    subset_indices = [s.index for s in subset]
    subset_scalars = [int.from_bytes(s.scalar_bytes, 'big') for s in subset]

    # Every share must lie on F: F(x) = y*G. Since G has prime order this holds
    # exactly when y = f(x), for the secret polynomial f through the subset.
    strays = []
    for position, share in enumerate(shares):
        f_x = 0
        for x_i, y_i in zip(subset_indices, subset_scalars):
            coeff = lagrange_coefficient(x_i, subset_indices, share.index)
            f_x = (f_x + (coeff * y_i)) % SECP256K1_ORDER
        if f_x != int.from_bytes(share.scalar_bytes, 'big'):
            strays.append(f"#{share.index} (entry {position + 1})")
    if strays:
        raise ValueError(
            f"These shares do not belong with the others: {', '.join(strays)}. Each is from "
            "a different key or was mistranscribed. Remove them and try again."
        )

    # Every share's polynomial checksum must verify against F
    failed = [f"#{s.index}" for s in shares if not verify_polynomial_checksum(s, poly_commitment)]
    if failed:
        raise ValueError(
            f"Polynomial checksum failed for share {', '.join(failed)}. A share may be from a "
            "different key or mistranscribed, or fewer shares than the threshold were given."
        )

    # Reconstruct secret using Lagrange interpolation
    secret = 0
    for x_i, y_i in zip(subset_indices, subset_scalars):
        coeff = lagrange_coefficient(x_i, subset_indices)
        secret = (secret + (coeff * y_i)) % SECP256K1_ORDER

    return secret.to_bytes(32, 'big')


def recover_bare_secret(shares: List[ShareBackup]) -> bytes:
    """
    Recover from #0 backups, which carry the secret itself.

    They need no interpolation: each polynomial checksum is verified against
    the backup's own degree-0 commitment (secret * G). They must not be
    combined with shares, and if there are several they must agree.
    """
    if any(share.index != 0 for share in shares):
        raise ValueError("A #0 backup must not be combined with shares")

    secret = None
    for share in shares:
        _, commitment = compute_share_image(0, share.scalar_bytes)
        if not verify_polynomial_checksum(share, commitment):
            raise ValueError(
                "Polynomial checksum failed for backup #0: it was mistranscribed or is corrupted"
            )
        if secret is None:
            secret = share.scalar_bytes
        elif secret != share.scalar_bytes:
            raise ValueError("The #0 backups encode different secrets")

    return secret


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


# BIP-380 descriptor checksum. Reference implementation transcribed verbatim
# from the BIP so it matches Bitcoin Core's getdescriptorinfo output exactly.
# Without this suffix, importdescriptors rejects the descriptor with
# "Missing checksum" (src/wallet/rpc/backup.cpp passes require_checksum=true).
INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GENERATOR = [0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd]


def descsum_polymod(symbols):
    chk = 1
    for value in symbols:
        top = chk >> 35
        chk = (chk & 0x7ffffffff) << 5 ^ value
        for i in range(5):
            chk ^= GENERATOR[i] if ((top >> i) & 1) else 0
    return chk


def descsum_expand(s):
    groups = []
    symbols = []
    for c in s:
        if c not in INPUT_CHARSET:
            return None
        v = INPUT_CHARSET.find(c)
        symbols.append(v & 31)
        groups.append(v >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
            groups = []
    if len(groups) == 1:
        symbols.append(groups[0])
    elif len(groups) == 2:
        symbols.append(groups[0] * 3 + groups[1])
    return symbols


def descsum_create(s):
    symbols = descsum_expand(s) + [0, 0, 0, 0, 0, 0, 0, 0]
    checksum = descsum_polymod(symbols) ^ 1
    return s + '#' + ''.join(CHECKSUM_CHARSET[(checksum >> (5 * (7 - i))) & 31] for i in range(8))


def generate_descriptor(xpriv: str) -> str:
    """Generate Bitcoin descriptor for the wallet (Taproot) with BIP-380 checksum."""
    return descsum_create(f"tr({xpriv}/0/0/0/0/<0;1>/*)")


def interactive_recovery():
    """Run interactive recovery session."""
    print("\nFROST Backup Emergency Recovery Tool (frost_backup spec v0)")
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
        secret = recover_secret(shares, threshold)
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
    print("\nImport the descriptor above into any descriptor-aware wallet (Bitcoin")
    print("Core v28.0+; older versions reject the <0;1> multipath descriptor).")
    print("See the README for rescan/timestamp caveats.")
    print("=" * 70 + "\n")


def main():
    """Main entry point."""
    if len(sys.argv) > 1 and sys.argv[1] in ['--help', '-h']:
        print(__doc__)
        print("\nUsage: python3 reconstruct_frost_backups.py")
        print("\nReconstructs Bitcoin wallet from FROST backups.")
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
