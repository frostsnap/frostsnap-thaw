#!/usr/bin/env python3
"""
Test suite for FROST Backup Emergency Recovery Tool

Uses test vectors from the Rust implementation to ensure correctness.
Reference: frost_backup/tests/common/mod.rs
"""

import sys
import pytest
from reconstruct_frost_backups import (
    ShareBackup,
    ShareBackupError,
    compute_words_checksum,
    recover_secret,
    generate_xpriv,
    generate_descriptor,
    SECP256K1_ORDER,
)


# Test vectors from frost_backup/tests/common/mod.rs
# All generated with fingerprint: 18-bit "frost-v0"

# 1-of-1 scheme
# Secret: 0x0101010101010101010101010101010101010101010101010101010101010101
TEST_SHARES_1_OF_1 = [
    "#1 ABSURD AMOUNT DOCTOR ACOUSTIC AVOID LETTER ADVICE CAGE ABSURD AMOUNT DOCTOR ACOUSTIC AVOID LETTER ADVICE CAGE ABSURD AMOUNT DOCTOR ACOUSTIC AVOID LETTER ADVICE CURTAIN SOON",
]
EXPECTED_SECRET_1_OF_1 = "0101010101010101010101010101010101010101010101010101010101010101"

# 2-of-3 scheme
# Secret: 0x0101010101010101010101010101010101010101010101010101010101010101
TEST_SHARES_2_OF_3 = [
    "#1 MUTUAL JEANS SNAP STING BLESS JOURNEY MORAL BREAD ROOM LIMIT DOSE GRAVITY SORT DELIVER OUTDOOR RIPPLE DONKEY BLOUSE PLAY CART CENTURY MAXIMUM MAKE LOCAL MOBILE",
    "#2 CASH TRASH FOIL PREFER BUTTER IDEA BRAVE BITTER ITEM WINK DRIFT SMILE TOMATO LUNCH OPTION HERO THREE ENGINE BLESS MANAGE HORSE JAR ADVICE SHERIFF BUSINESS",
    "#3 REGION FINISH TRAVEL LAUNDRY CHEAP HAIR PLUNGE BANANA CRACK INTEREST DURING COTTON PHONE DISAGREE CRUNCH AIRPORT CANCEL FOLD LAUNDRY PONY LOBSTER LENS MAMMAL CLOTH FINGER",
]
EXPECTED_SECRET_2_OF_3 = "0101010101010101010101010101010101010101010101010101010101010101"

# 3-of-5 scheme
# Secret: 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
TEST_SHARES_3_OF_5 = [
    "#1 DUTCH GLAD TORCH EXACT PROGRAM GRASS CLUB SCRAP MUSCLE TUITION TISSUE CLERK SEA SUMMER SHIP VERY FREQUENT DIAL SYRUP MAMMAL SIMILAR MISERY PLAY RING ARM",
    "#2 SUGAR GENERAL PARK VOYAGE CREEK FLY MOTOR ALWAYS WAVE SUNNY WARRIOR DIAMOND WAVE SUNSET ANY LEFT LIGHT FLOAT VAULT GENUINE ELBOW TENNIS BECOME TABLE CLAIM",
    "#3 ORANGE HAMMER UNFOLD REFUSE IMMUNE FAVORITE POET MEDIA CARRY SEGMENT PULL BRUSH DAMAGE ADDRESS FILE PORTION UNFOLD BLAST ACCOUNT NATION TELL BELT DENY ABILITY FOOD",
    "#4 MIRACLE KETCHUP SLIM MAZE GUESS FEBRUARY IDLE ENDORSE BARELY POLAR AGAIN SIBLING CLARIFY SHELL EAGER FISCAL DISTANCE FEW ABOVE SURE FRAME ENFORCE BUTTER MORNING ZOO",
    "#5 PUMPKIN NEUTRAL DESTROY INSTALL BEHAVE FOLD UNDER EAST SHORT MAGNET WORLD DEVICE SPECIAL BUYER STONE MILLION JUNIOR BEAN UPON CRYSTAL SCENE LEARN SEARCH GALAXY SUMMER",
]
EXPECTED_SECRET_3_OF_5 = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

# Invalid share for testing checksum validation
# This is TEST_SHARES_2_OF_3[0] with the last word changed from "MOBILE" to "ABANDON"
INVALID_SHARE_CHECKSUM = "#1 MUTUAL JEANS SNAP STING BLESS JOURNEY MORAL BREAD ROOM LIMIT DOSE GRAVITY SORT DELIVER OUTDOOR RIPPLE DONKEY BLOUSE PLAY CART CENTURY MAXIMUM MAKE LOCAL ABANDON"


class TestShareParsing:
    """Test share parsing and validation."""

    def test_parse_valid_share_1_of_1(self):
        """Test parsing the 1-of-1 share."""
        share = ShareBackup.from_string(TEST_SHARES_1_OF_1[0])
        assert share.index == 1
        assert len(share.scalar_bytes) == 32

    def test_parse_valid_shares_2_of_3(self):
        """Test parsing all shares from 2-of-3 scheme."""
        for i, share_str in enumerate(TEST_SHARES_2_OF_3):
            share = ShareBackup.from_string(share_str)
            assert share.index == i + 1
            assert len(share.scalar_bytes) == 32

    def test_parse_valid_shares_3_of_5(self):
        """Test parsing all shares from 3-of-5 scheme."""
        for i, share_str in enumerate(TEST_SHARES_3_OF_5):
            share = ShareBackup.from_string(share_str)
            assert share.index == i + 1
            assert len(share.scalar_bytes) == 32

    def test_invalid_checksum_rejected(self):
        """Test that invalid checksum is detected."""
        with pytest.raises(ShareBackupError, match="Words checksum failed"):
            ShareBackup.from_string(INVALID_SHARE_CHECKSUM)

    def test_invalid_format_no_hash(self):
        """Test that shares without # are rejected."""
        with pytest.raises(ShareBackupError, match="Invalid format"):
            ShareBackup.from_string("1 WORD WORD WORD")

    def test_invalid_format_wrong_word_count(self):
        """Test that shares with wrong number of words are rejected."""
        with pytest.raises(ShareBackupError, match="Expected 25 words"):
            ShareBackup.from_string("#1 WORD WORD WORD")

    def test_invalid_word_not_in_bip39(self):
        """Test that non-BIP39 words are rejected."""
        # Create a share with an invalid word
        invalid_share = "#1 " + " ".join(["INVALID"] * 25)
        with pytest.raises(ShareBackupError, match="not in BIP39 wordlist"):
            ShareBackup.from_string(invalid_share)

    def test_share_index_zero_rejected(self):
        """Test that share index 0 is rejected."""
        # Note: This would need to pass checksum validation first
        # For now we just test the ShareBackup constructor
        with pytest.raises(ShareBackupError, match="index cannot be 0"):
            ShareBackup(0, bytes(32), 0)


class TestSecretRecovery:
    """Test secret recovery from shares."""

    def test_recover_1_of_1(self):
        """Test recovering secret from 1-of-1 scheme."""
        shares = [ShareBackup.from_string(s) for s in TEST_SHARES_1_OF_1]
        secret = recover_secret(shares)
        assert secret.hex() == EXPECTED_SECRET_1_OF_1

    def test_recover_2_of_3_first_two_shares(self):
        """Test recovering secret from first 2 shares of 2-of-3."""
        shares = [ShareBackup.from_string(s) for s in TEST_SHARES_2_OF_3[:2]]
        secret = recover_secret(shares)
        assert secret.hex() == EXPECTED_SECRET_2_OF_3

    def test_recover_2_of_3_first_and_last(self):
        """Test recovering secret from shares 1 and 3 of 2-of-3."""
        share_strs = [TEST_SHARES_2_OF_3[0], TEST_SHARES_2_OF_3[2]]
        shares = [ShareBackup.from_string(s) for s in share_strs]
        secret = recover_secret(shares)
        assert secret.hex() == EXPECTED_SECRET_2_OF_3

    def test_recover_2_of_3_last_two_shares(self):
        """Test recovering secret from last 2 shares of 2-of-3."""
        shares = [ShareBackup.from_string(s) for s in TEST_SHARES_2_OF_3[1:]]
        secret = recover_secret(shares)
        assert secret.hex() == EXPECTED_SECRET_2_OF_3

    def test_recover_3_of_5_first_three(self):
        """Test recovering secret from first 3 shares of 3-of-5."""
        shares = [ShareBackup.from_string(s) for s in TEST_SHARES_3_OF_5[:3]]
        secret = recover_secret(shares)
        assert secret.hex() == EXPECTED_SECRET_3_OF_5

    def test_recover_3_of_5_last_three(self):
        """Test recovering secret from last 3 shares of 3-of-5."""
        shares = [ShareBackup.from_string(s) for s in TEST_SHARES_3_OF_5[2:]]
        secret = recover_secret(shares)
        assert secret.hex() == EXPECTED_SECRET_3_OF_5

    def test_recover_3_of_5_shares_1_3_5(self):
        """Test recovering secret from shares 1, 3, 5 of 3-of-5."""
        share_strs = [TEST_SHARES_3_OF_5[0], TEST_SHARES_3_OF_5[2], TEST_SHARES_3_OF_5[4]]
        shares = [ShareBackup.from_string(s) for s in share_strs]
        secret = recover_secret(shares)
        assert secret.hex() == EXPECTED_SECRET_3_OF_5

    def test_recover_empty_shares_fails(self):
        """Test that recovery with no shares fails."""
        with pytest.raises(ValueError, match="No shares provided"):
            recover_secret([])

    def test_recover_duplicate_indices_fails(self):
        """Test that duplicate share indices are detected."""
        # Use the same share twice
        shares = [
            ShareBackup.from_string(TEST_SHARES_2_OF_3[0]),
            ShareBackup.from_string(TEST_SHARES_2_OF_3[0]),
        ]
        with pytest.raises(ValueError, match="Duplicate share indices"):
            recover_secret(shares)


class TestBitcoinOutputs:
    """Test Bitcoin xpriv and descriptor generation."""

    def test_xpriv_generation_mainnet(self):
        """Test generating xpriv for mainnet."""
        secret = bytes.fromhex(EXPECTED_SECRET_1_OF_1)
        xpriv = generate_xpriv(secret, 'mainnet')

        # Basic validation
        assert xpriv.startswith('xprv')
        assert len(xpriv) > 100  # Base58 encoded should be ~110 chars

    def test_xpriv_generation_testnet(self):
        """Test generating xpriv for testnet."""
        secret = bytes.fromhex(EXPECTED_SECRET_1_OF_1)
        xpriv = generate_xpriv(secret, 'testnet')

        # Basic validation
        assert xpriv.startswith('tprv')
        assert len(xpriv) > 100

    def test_xpriv_deterministic(self):
        """Test that xpriv generation is deterministic."""
        secret = bytes.fromhex(EXPECTED_SECRET_1_OF_1)
        xpriv1 = generate_xpriv(secret, 'mainnet')
        xpriv2 = generate_xpriv(secret, 'mainnet')
        assert xpriv1 == xpriv2

    def test_descriptor_format(self):
        """Test that descriptor has correct format."""
        secret = bytes.fromhex(EXPECTED_SECRET_1_OF_1)
        xpriv = generate_xpriv(secret, 'mainnet')
        descriptor = generate_descriptor(xpriv)

        # Check format: tr(xpriv/0/0/0/0/<0;1>/*)
        assert descriptor.startswith('tr(')
        assert descriptor.endswith(')')
        assert '/0/0/0/0/<0;1>/*' in descriptor
        assert xpriv in descriptor

    def test_descriptor_deterministic(self):
        """Test that descriptor generation is deterministic."""
        secret = bytes.fromhex(EXPECTED_SECRET_1_OF_1)
        xpriv = generate_xpriv(secret, 'mainnet')
        descriptor1 = generate_descriptor(xpriv)
        descriptor2 = generate_descriptor(xpriv)
        assert descriptor1 == descriptor2


class TestEndToEnd:
    """End-to-end integration tests."""

    def test_full_recovery_1_of_1(self):
        """Test complete recovery flow for 1-of-1."""
        # Parse shares
        shares = [ShareBackup.from_string(s) for s in TEST_SHARES_1_OF_1]

        # Recover secret
        secret = recover_secret(shares)
        assert secret.hex() == EXPECTED_SECRET_1_OF_1

        # Generate Bitcoin outputs
        xpriv = generate_xpriv(secret, 'mainnet')
        descriptor = generate_descriptor(xpriv)

        # Validate outputs
        assert xpriv.startswith('xprv')
        assert 'tr(' in descriptor

    def test_full_recovery_2_of_3(self):
        """Test complete recovery flow for 2-of-3."""
        # Parse shares (use first 2)
        shares = [ShareBackup.from_string(s) for s in TEST_SHARES_2_OF_3[:2]]

        # Recover secret
        secret = recover_secret(shares)
        assert secret.hex() == EXPECTED_SECRET_2_OF_3

        # Generate Bitcoin outputs
        xpriv = generate_xpriv(secret, 'mainnet')
        descriptor = generate_descriptor(xpriv)

        # Validate outputs
        assert xpriv.startswith('xprv')
        assert 'tr(' in descriptor

    def test_full_recovery_3_of_5(self):
        """Test complete recovery flow for 3-of-5."""
        # Parse shares (use first 3)
        shares = [ShareBackup.from_string(s) for s in TEST_SHARES_3_OF_5[:3]]

        # Recover secret
        secret = recover_secret(shares)
        assert secret.hex() == EXPECTED_SECRET_3_OF_5

        # Generate Bitcoin outputs
        xpriv = generate_xpriv(secret, 'mainnet')
        descriptor = generate_descriptor(xpriv)

        # Validate outputs
        assert xpriv.startswith('xprv')
        assert 'tr(' in descriptor

    def test_same_secret_from_different_share_combinations(self):
        """Test that different valid combinations yield the same secret."""
        # Test all 3 combinations of 2-of-3
        combo1 = [ShareBackup.from_string(s) for s in TEST_SHARES_2_OF_3[:2]]
        combo2 = [ShareBackup.from_string(TEST_SHARES_2_OF_3[0]),
                  ShareBackup.from_string(TEST_SHARES_2_OF_3[2])]
        combo3 = [ShareBackup.from_string(s) for s in TEST_SHARES_2_OF_3[1:]]

        secret1 = recover_secret(combo1)
        secret2 = recover_secret(combo2)
        secret3 = recover_secret(combo3)

        assert secret1 == secret2 == secret3
        assert secret1.hex() == EXPECTED_SECRET_2_OF_3


class TestWordsChecksum:
    """Test words checksum computation."""

    def test_checksum_computation(self):
        """Test that words checksum computation works."""
        # This is tested indirectly through share parsing,
        # but we can also test it directly
        index = 1
        scalar_bytes = bytes(32)  # All zeros
        poly_checksum = 0

        checksum = compute_words_checksum(index, scalar_bytes, poly_checksum)

        # Checksum should be 11 bits (0-2047)
        assert 0 <= checksum < 2048

    def test_checksum_different_for_different_inputs(self):
        """Test that different inputs produce different checksums."""
        index = 1
        scalar1 = bytes(32)  # All zeros
        scalar2 = bytes([1] + [0] * 31)  # One byte different

        checksum1 = compute_words_checksum(index, scalar1, 0)
        checksum2 = compute_words_checksum(index, scalar2, 0)

        # Different scalars should (very likely) produce different checksums
        assert checksum1 != checksum2


def run_tests():
    """Run all tests and display results."""
    print("=" * 70)
    print(" FROST BACKUP RECOVERY TOOL - TEST SUITE")
    print("=" * 70)
    print()
    print("Running tests against official test vectors...")
    print()

    # Run pytest
    exit_code = pytest.main([
        __file__,
        '-v',
        '--tb=short',
        '--color=yes',
    ])

    print()
    if exit_code == 0:
        print("=" * 70)
        print(" ALL TESTS PASSED ✓")
        print("=" * 70)
    else:
        print("=" * 70)
        print(" TESTS FAILED ✗")
        print("=" * 70)
        print()
        print("DO NOT use this tool for recovery until all tests pass!")

    return exit_code


if __name__ == '__main__':
    sys.exit(run_tests())
