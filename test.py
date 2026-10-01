#!/usr/bin/env python3
"""
Test suite for FROST Backup Emergency Recovery Tool

Uses test vectors from the Rust implementation to ensure correctness.
Reference: frost_backup/tests/common/mod.rs
Also covers every vector in the BIP's Test vectors section (bip-frost-backup.md).
"""

import sys
import hashlib
import pytest
from reconstruct_frost_backups import (
    ShareBackup,
    ShareBackupError,
    compute_words_checksum,
    compute_share_image,
    reconstruct_polynomial_commitment,
    verify_polynomial_checksum,
    check_fingerprint,
    recover_secret,
    generate_xpriv,
    generate_descriptor,
    descsum_create,
    CHECKSUM_CHARSET,
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

# The same secret as a #0 bare-secret backup (frost_backup/tests/common/mod.rs TEST_BARE_SECRET)
TEST_BARE_SECRET = "#0 ABSURD AMOUNT DOCTOR ACOUSTIC AVOID LETTER ADVICE CAGE ABSURD AMOUNT DOCTOR ACOUSTIC AVOID LETTER ADVICE CAGE ABSURD AMOUNT DOCTOR ACOUSTIC AVOID LETTER ADVICE CHECK WIDTH"

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

# 4-of-4 scheme (BIP): only A_1 and A_2 are ground, so A_3 carries no fingerprint bits
# Secret: 0x0202020202020202020202020202020202020202020202020202020202020202
TEST_SHARES_4_OF_4 = [
    "#1 CAT WITNESS MARINE SAVE SHOCK DEVELOP CHAOS DEVELOP SMOOTH SELECT RUG FATIGUE CITIZEN OBSCURE DINOSAUR ROOF ACTOR ALCOHOL SCREEN DEMAND PATH DOLPHIN FATIGUE INSECT FORCE",
    "#2 ARTWORK REUNION SECOND TURKEY COMMON CONNECT EQUIP HOTEL AFFORD CLOCK SHRIMP OCTOBER OBJECT SHIELD JEALOUS OBVIOUS ARMOR BURDEN HABIT SHIP EYE WORTH TOP OBJECT BEGIN",
    "#3 TRULY REPAIR WHEAT BRIDGE CANYON STUMBLE DRAMA EDGE GORILLA GROUP MANAGE ORANGE RACCOON VOICE BITTER MARKET ISSUE JOURNEY DELIVER TURN MEDAL MAN SPIRIT WEIRD REFORM",
    "#4 TOMATO HELP WEAR TUNNEL HEAD CRUISE SPAWN CUSTOM PRETTY NEITHER TONE CLOG RELIEF ELSE QUARTER LEND ROBOT OBVIOUS BUS REGION DILEMMA SUCCESS CARRY INJECT BOARD",
]
EXPECTED_SECRET_4_OF_4 = "0202020202020202020202020202020202020202020202020202020202020202"

# Polynomial commitments listed in the BIP, one 33-byte coefficient per line
POLY_COMMITMENT_1_OF_1 = [
    "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
]
POLY_COMMITMENT_2_OF_3 = [
    "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
    "0214ec06c944abcb9245902e82e37a23896a4069fd86ad7ae2f9cb91c59109109a",
]
POLY_COMMITMENT_3_OF_5 = [
    "02c6b754b20826eb925e052ee2c25285b162b51fdca732bcf67e39d647fb6830ae",
    "020edcb4850d4cd9a57009e9900bf54acdb240a2087e6071a3616808d73c8424f1",
    "029cf188eac4090ee194ca695133762e1ad22e709cf2a7e16d5494bfcfd245e25d",
]
POLY_COMMITMENT_4_OF_4 = [
    "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766",
    "020313fcdea366087be6d6e3f6dda8e94206ab2ecf4bc9c0579fabe53a8be6133a",
    "02a1870d54e1745899c36a2b5ad8d0d3954d7fe8a596bf5c1c2b6f8d5f66b1e179",
    "03ffa2679439054ac606a004ca7a304f0870d6d2e76a2be48f9c033046e96c39b6",
]

# Root xprv of the secret 0x0101...01 (BIP wallet derivation vector)
EXPECTED_XPRV = "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93yjHmmfwkTW7jWmaf7X9aF3GP9D3mXSChQcm2zAZG6kerWdMw"

# Invalid share for testing checksum validation
# This is TEST_SHARES_2_OF_3[0] with the last word changed from "MOBILE" to "ABANDON"
INVALID_SHARE_CHECKSUM = "#1 MUTUAL JEANS SNAP STING BLESS JOURNEY MORAL BREAD ROOM LIMIT DOSE GRAVITY SORT DELIVER OUTDOOR RIPPLE DONKEY BLOUSE PLAY CART CENTURY MAXIMUM MAKE LOCAL ABANDON"

# Invalid share (BIP): encodes the scalar N itself, with a polynomial checksum of 0
# and a valid words checksum
INVALID_SHARE_SCALAR_OUT_OF_RANGE = "#1 ZOO ZOO ZOO ZOO ZOO ZOO ZOO ZOO ZOO ZOO ZOO WORD PRIORITY HOVER ONE TROUBLE PARENT TARGET VIRUS RUG SNACK BRASS AGREE CACTUS MIRACLE"

# Invalid share (BIP): TEST_SHARES_2_OF_3[0] with every bit of its polynomial
# checksum flipped and word 25 recomputed, so the words checksum still passes
INVALID_SHARE_POLY_CHECKSUM = "#1 MUTUAL JEANS SNAP STING BLESS JOURNEY MORAL BREAD ROOM LIMIT DOSE GRAVITY SORT DELIVER OUTDOOR RIPPLE DONKEY BLOUSE PLAY CART CENTURY MAXIMUM MAKE ORIGINAL IMPULSE"

# Invalid #0 backup (BIP): TEST_BARE_SECRET with every bit of its polynomial
# checksum flipped and word 25 recomputed
INVALID_BARE_SECRET_POLY_CHECKSUM = "#0 ABSURD AMOUNT DOCTOR ACOUSTIC AVOID LETTER ADVICE CAGE ABSURD AMOUNT DOCTOR ACOUSTIC AVOID LETTER ADVICE CAGE ABSURD AMOUNT DOCTOR ACOUSTIC AVOID LETTER ADVICE DECLINE SILK"

# Invalid set (BIP): a 2-of-2 whose polynomial was never ground, so every checksum
# passes against the commitment below but the fingerprint does not
INVALID_SET_NO_FINGERPRINT = [
    "#1 ALPHA DEAL SCRUB ASTHMA IDEA LOGIC BRIGHT THOUGHT ALPHA DEAL SCRUB ASTHMA IDEA LOGIC BRIGHT THOUGHT ALPHA DEAL SCRUB ASTHMA IDEA LOGIC BRIGHT WINDOW BARELY",
    "#2 ARCH FLAME SECURITY BID RADAR MACHINE CLUB GESTURE ARCH FLAME SECURITY BID RADAR MACHINE CLUB GESTURE ARCH FLAME SECURITY BID RADAR MACHINE CLUB GLOOM INFORM",
]
POLY_COMMITMENT_INVALID_SET = [
    "02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337",
    "03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b",
]


def interpolate_commitment(share_strs, threshold):
    """Interpolate the polynomial commitment from the public images of the first threshold shares."""
    shares = [ShareBackup.from_string(s) for s in share_strs[:threshold]]
    images = [compute_share_image(s.index, s.scalar_bytes) for s in shares]
    return reconstruct_polynomial_commitment(images, threshold)


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

    def test_parse_valid_shares_4_of_4(self):
        """Test parsing all shares from 4-of-4 scheme."""
        for i, share_str in enumerate(TEST_SHARES_4_OF_4):
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
        with pytest.raises(ShareBackupError, match="Expected 25 words, got 26"):
            ShareBackup.from_string(TEST_SHARES_2_OF_3[0] + " ABANDON")

    def test_invalid_word_not_in_bip39(self):
        """Test that non-BIP39 words are rejected."""
        # Create a share with an invalid word
        invalid_share = "#1 " + " ".join(["INVALID"] * 25)
        with pytest.raises(ShareBackupError, match="not in BIP39 wordlist"):
            ShareBackup.from_string(invalid_share)

    def test_bare_secret_index_zero_accepted(self):
        """A #0 backup (bare secret) parses like any other backup."""
        share = ShareBackup.from_string(TEST_BARE_SECRET)
        assert share.index == 0
        assert share.scalar_bytes.hex() == EXPECTED_SECRET_1_OF_1

    def test_share_index_must_fit_in_32_bits(self):
        """Indices above 2^32 - 1 are rejected with a ShareBackupError, not an OverflowError."""
        with pytest.raises(ShareBackupError, match="fit in 32 bits"):
            ShareBackup.from_string("#4294967296 " + " ".join(["ABANDON"] * 25))
        ShareBackup(0xFFFFFFFF, bytes(32), 0)  # the largest valid index constructs fine

    def test_scalar_at_or_above_group_order_rejected(self):
        """The 256-bit scalar must be below the secp256k1 order; it is rejected, not reduced."""
        # Every word ZOO (index 2047) makes the scalar all ones, which is >= n
        with pytest.raises(ShareBackupError, match="group order"):
            ShareBackup.from_string("#1 " + " ".join(["ZOO"] * 25))
        # The BIP vector encodes n itself, with a valid words checksum
        with pytest.raises(ShareBackupError, match="group order"):
            ShareBackup.from_string(INVALID_SHARE_SCALAR_OUT_OF_RANGE)


class TestSecretRecovery:
    """Test secret recovery from shares."""

    def test_lone_share_without_threshold_rejected(self):
        """A lone share is not tried as a threshold-1 key unless threshold 1 is stated."""
        for share_str in [TEST_SHARES_1_OF_1[0], TEST_SHARES_2_OF_3[0]]:
            with pytest.raises(ValueError, match="One share is not enough.*state threshold 1"):
                recover_secret([ShareBackup.from_string(share_str)])

    def test_recover_1_of_1_lone_share_with_threshold_one(self):
        """A lone #1 share of a threshold-1 key (as shipped before #0) recovers when the threshold is given as 1."""
        shares = [ShareBackup.from_string(s) for s in TEST_SHARES_1_OF_1]
        secret = recover_secret(shares, 1)
        assert secret.hex() == EXPECTED_SECRET_1_OF_1
        # Its polynomial checksum is verified against its own public image
        corrupted = ShareBackup(1, shares[0].scalar_bytes, shares[0].poly_checksum ^ 0xFF)
        with pytest.raises(ValueError, match="Polynomial checksum failed for share #1"):
            recover_secret([corrupted], 1)

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

    def test_recover_4_of_4(self):
        """The 4-of-4 vector recovers, with and without the threshold given.

        A_3 carries no fingerprint bits, so this only passes if the fingerprint
        check stops at its 36-bit cap.
        """
        shares = [ShareBackup.from_string(s) for s in TEST_SHARES_4_OF_4]
        assert recover_secret(shares).hex() == EXPECTED_SECRET_4_OF_4
        assert recover_secret(shares, 4).hex() == EXPECTED_SECRET_4_OF_4
        with pytest.raises(ValueError, match="Fingerprint check failed"):
            recover_secret(shares[:3])

    def test_recover_with_more_shares_than_threshold(self):
        """All three 2-of-3 shares, with and without the threshold given, recover the secret."""
        shares = [ShareBackup.from_string(s) for s in TEST_SHARES_2_OF_3]
        assert recover_secret(shares).hex() == EXPECTED_SECRET_2_OF_3
        assert recover_secret(shares, 2).hex() == EXPECTED_SECRET_2_OF_3
        # All five 3-of-5 shares likewise
        shares = [ShareBackup.from_string(s) for s in TEST_SHARES_3_OF_5]
        assert recover_secret(shares).hex() == EXPECTED_SECRET_3_OF_5

    def test_recover_with_wrong_threshold_fails(self):
        """A stated threshold that does not match the shares is detected."""
        shares = [ShareBackup.from_string(s) for s in TEST_SHARES_2_OF_3]
        with pytest.raises(ValueError, match="Fingerprint check failed.*threshold may be wrong"):
            recover_secret(shares, 3)
        # Four 3-of-5 shares fit a zero A_3, which carries no fingerprint bits, so
        # a threshold of 4 must be ruled out by the degree, not left to the checksums
        shares = [ShareBackup.from_string(s) for s in TEST_SHARES_3_OF_5[:4]]
        with pytest.raises(ValueError, match="Fingerprint check failed.*threshold may be wrong"):
            recover_secret(shares, 4)
        with pytest.raises(ValueError, match="Need at least 3 shares"):
            recover_secret(shares[:2], 3)
        with pytest.raises(ValueError, match="Threshold must be at least 1"):
            recover_secret(shares, 0)

    def test_recover_empty_shares_fails(self):
        """Test that recovery with no shares fails."""
        with pytest.raises(ValueError, match="No shares provided"):
            recover_secret([])

    def test_recover_duplicate_indices_fails(self):
        """Interpolation needs different indices, so one share entered twice is not enough."""
        # Use the same share twice
        shares = [
            ShareBackup.from_string(TEST_SHARES_2_OF_3[0]),
            ShareBackup.from_string(TEST_SHARES_2_OF_3[0]),
        ]
        with pytest.raises(ValueError, match="Need at least 2 shares with different indices, got 1"):
            recover_secret(shares)
        # With another share the repeat is harmless: it lies on F and its checksum verifies
        shares.append(ShareBackup.from_string(TEST_SHARES_2_OF_3[1]))
        assert recover_secret(shares).hex() == EXPECTED_SECRET_2_OF_3

    def test_share_from_another_key_at_same_index_is_named(self):
        """A subset never takes two shares at one index; a #1 from another key is found and named."""
        shares = [ShareBackup.from_string(s) for s in TEST_SHARES_2_OF_3]
        shares.append(ShareBackup.from_string(TEST_SHARES_3_OF_5[0]))
        with pytest.raises(ValueError, match=r"do not belong with the others: #1 \(entry 4\)\."):
            recover_secret(shares)
        # A share beyond the first t must lie on F, whatever its checksum does
        shares = [ShareBackup.from_string(s) for s in TEST_SHARES_2_OF_3[:2]]
        shares.append(ShareBackup.from_string(TEST_SHARES_3_OF_5[3]))
        with pytest.raises(ValueError, match=r"do not belong with the others: #4 \(entry 3\)\."):
            recover_secret(shares, 2)

    def test_polynomial_with_most_fingerprint_bits_is_chosen(self):
        """Discovery keeps the F with the most fingerprint bits, as the Rust reference does.

        Two complete sets are given. The 2-of-3 polynomial is found first but
        carries only 18 bits, so the 3-of-5 one (36 bits) wins and the 2-of-3
        shares are the ones named. Given threshold 2, the 2-of-3 polynomial wins.
        """
        shares = [ShareBackup.from_string(s) for s in TEST_SHARES_2_OF_3[:2] + TEST_SHARES_3_OF_5[:3]]
        with pytest.raises(ValueError, match=r"the others: #1 \(entry 1\), #2 \(entry 2\)\."):
            recover_secret(shares)
        with pytest.raises(ValueError, match=r"the others: #1 \(entry 3\), #2 \(entry 4\), #3 \(entry 5\)\."):
            recover_secret(shares, 2)

    def test_recover_bare_secret(self):
        """A lone #0 backup recovers the secret after its polynomial checksum verifies."""
        secret = recover_secret([ShareBackup.from_string(TEST_BARE_SECRET)])
        assert secret.hex() == EXPECTED_SECRET_1_OF_1

    def test_bare_secret_bad_poly_checksum_fails(self):
        """A #0 backup whose polynomial checksum does not match secret*G is rejected (BIP vector)."""
        share = ShareBackup.from_string(TEST_BARE_SECRET)
        # The words checksum passes, and only the polynomial checksum differs
        corrupted = ShareBackup.from_string(INVALID_BARE_SECRET_POLY_CHECKSUM)
        assert corrupted.scalar_bytes == share.scalar_bytes
        assert corrupted.poly_checksum == share.poly_checksum ^ 0xFF
        with pytest.raises(ValueError, match="Polynomial checksum failed for backup #0"):
            recover_secret([corrupted])

    def test_share_bad_poly_checksum_fails(self):
        """A share whose polynomial checksum does not match the 2-of-3 commitment is rejected (BIP vector)."""
        share = ShareBackup.from_string(TEST_SHARES_2_OF_3[0])
        # The words checksum passes, and only the polynomial checksum differs
        corrupted = ShareBackup.from_string(INVALID_SHARE_POLY_CHECKSUM)
        assert corrupted.scalar_bytes == share.scalar_bytes
        assert corrupted.poly_checksum == share.poly_checksum ^ 0xFF
        assert not verify_polynomial_checksum(corrupted, bytes.fromhex("".join(POLY_COMMITMENT_2_OF_3)))
        others = [ShareBackup.from_string(s) for s in TEST_SHARES_2_OF_3[1:]]
        with pytest.raises(ValueError, match="Polynomial checksum failed for share #1"):
            recover_secret([corrupted, others[0]])
        with pytest.raises(ValueError, match="Polynomial checksum failed for share #1"):
            recover_secret([others[0], others[1], corrupted], 2)

    def test_bare_secret_not_mixed_with_shares(self):
        """#0 backups must not be combined with shares."""
        mixed = [
            ShareBackup.from_string(TEST_BARE_SECRET),
            ShareBackup.from_string(TEST_SHARES_2_OF_3[0]),
        ]
        with pytest.raises(ValueError, match="must not be combined with shares"):
            recover_secret(mixed)

    def test_mismatched_shares_from_different_wallets_fail(self):
        """Test that the fingerprint check detects shares from different wallets."""
        # Try to mix share #1 from 2-of-3 scheme with share #2 from 3-of-5 scheme
        # These are from different wallets (different secrets), so the fingerprint check should fail
        mixed_shares = [
            ShareBackup.from_string(TEST_SHARES_2_OF_3[0]),  # From wallet with secret 0x01...01
            ShareBackup.from_string(TEST_SHARES_3_OF_5[1]),  # From wallet with secret 0xdeadbeef...
        ]
        with pytest.raises(ValueError, match="Fingerprint check failed"):
            recover_secret(mixed_shares)

    def test_invalid_set_fingerprint_failure(self):
        """The BIP's invalid set passes every checksum but lacks the fingerprint, so it is rejected."""
        shares = [ShareBackup.from_string(s) for s in INVALID_SET_NO_FINGERPRINT]
        commitment = interpolate_commitment(INVALID_SET_NO_FINGERPRINT, 2)
        assert commitment.hex() == "".join(POLY_COMMITMENT_INVALID_SET)
        assert all(verify_polynomial_checksum(s, commitment) for s in shares)
        assert check_fingerprint(commitment) is None
        with pytest.raises(ValueError, match="Fingerprint check failed"):
            recover_secret(shares)
        with pytest.raises(ValueError, match="Fingerprint check failed"):
            recover_secret(shares, 2)


class TestFingerprint:
    """Test polynomial commitments and the frost-v0 fingerprint against the BIP."""

    def test_commitments_match_bip(self):
        """Interpolating the shares gives the BIP's commitment, and every polynomial checksum verifies against it."""
        for share_strs, threshold, listed in [
            (TEST_SHARES_2_OF_3, 2, POLY_COMMITMENT_2_OF_3),
            (TEST_SHARES_3_OF_5, 3, POLY_COMMITMENT_3_OF_5),
            (TEST_SHARES_4_OF_4, 4, POLY_COMMITMENT_4_OF_4),
        ]:
            commitment = interpolate_commitment(share_strs, threshold)
            assert commitment.hex() == "".join(listed)
            shares = [ShareBackup.from_string(s) for s in share_strs]
            assert all(verify_polynomial_checksum(s, commitment) for s in shares)
        # A #0 backup's commitment is its own public key s*G
        share = ShareBackup.from_string(TEST_BARE_SECRET)
        _, commitment = compute_share_image(0, share.scalar_bytes)
        assert commitment.hex() == "".join(POLY_COMMITMENT_1_OF_1)
        assert verify_polynomial_checksum(share, commitment)

    def test_fingerprint_bits(self):
        """Each BIP commitment carries the fingerprint, capped at 36 bits; the invalid set does not."""
        assert check_fingerprint(bytes.fromhex("".join(POLY_COMMITMENT_1_OF_1))) == 0
        assert check_fingerprint(bytes.fromhex("".join(POLY_COMMITMENT_2_OF_3))) == 18
        assert check_fingerprint(bytes.fromhex("".join(POLY_COMMITMENT_3_OF_5))) == 36
        assert check_fingerprint(bytes.fromhex("".join(POLY_COMMITMENT_4_OF_4))) == 36
        assert check_fingerprint(bytes.fromhex("".join(POLY_COMMITMENT_INVALID_SET))) is None

    def test_4_of_4_exercises_max_bits_total(self):
        """A_3 of the 4-of-4 vector has fewer than 18 leading zero bits.

        So an implementation demanding bits_per_coeff from every coefficient
        wrongly rejects it, while check_fingerprint (above) accepts it.
        """
        commitment = bytes.fromhex("".join(POLY_COMMITMENT_4_OF_4))
        state = hashlib.sha256(bytes([len(b"frost-v0")]) + b"frost-v0" + commitment[:33])
        state.update(commitment[33:132])  # A_1, A_2 and A_3
        assert 256 - int.from_bytes(state.digest(), 'big').bit_length() < 18


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

        # Format: tr(xpriv/0/0/0/0/<0;1>/*)#<8-char checksum>
        assert descriptor.startswith('tr(')
        assert '/0/0/0/0/<0;1>/*' in descriptor
        assert xpriv in descriptor
        assert descriptor[-9] == '#'
        assert all(c in CHECKSUM_CHARSET for c in descriptor[-8:])

    def test_descriptor_deterministic(self):
        """Test that descriptor generation is deterministic."""
        secret = bytes.fromhex(EXPECTED_SECRET_1_OF_1)
        xpriv = generate_xpriv(secret, 'mainnet')
        descriptor1 = generate_descriptor(xpriv)
        descriptor2 = generate_descriptor(xpriv)
        assert descriptor1 == descriptor2

    def test_xpriv_and_descriptor_match_reference(self):
        """Golden vector: pin the EXACT xpriv and descriptor for a known secret.

        This is the regression guard that the shape-only tests above cannot
        provide. The recovery path depends on three constants taken verbatim
        from the Rust reference frost_backup/src/lib.rs:
          - the all-zero BIP32 chain code (`let chaincode = [0u8; 32];`)
          - the derivation path / script type (`tr({xpriv}/0/0/0/0/<0;1>/*)`)
          - the mainnet xprv version bytes
        If any of these silently changes, the tool would derive a DIFFERENT
        wallet that recovers no funds while every other test still passes.
        Pinning the full output strings makes that failure loud.
        """
        secret = bytes.fromhex(EXPECTED_SECRET_1_OF_1)
        xpriv = generate_xpriv(secret, 'mainnet')
        assert xpriv == (
            "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF"
            "93yjHmmfwkTW7jWmaf7X9aF3GP9D3mXSChQcm2zAZG6kerWdMw"
        )
        assert generate_descriptor(xpriv) == (
            "tr(xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF"
            "93yjHmmfwkTW7jWmaf7X9aF3GP9D3mXSChQcm2zAZG6kerWdMw/0/0/0/0/<0;1>/*)"
            "#5g5wtnwn"
        )


class TestDescriptorChecksum:
    """Test BIP-380 descriptor checksum implementation against the spec."""

    def test_bip380_published_vector(self):
        """BIP-380 test vector: raw(deadbeef) -> raw(deadbeef)#89f8spxm."""
        assert descsum_create("raw(deadbeef)") == "raw(deadbeef)#89f8spxm"

    def test_generated_descriptor_accepted_by_bitcoin_core(self):
        """Generated descriptor must carry an 8-char checksum from CHECKSUM_CHARSET.

        Bitcoin Core's importdescriptors calls Parse(..., require_checksum=true),
        which rejects bare descriptors with "Missing checksum".
        """
        secret = bytes.fromhex(EXPECTED_SECRET_2_OF_3)
        xpriv = generate_xpriv(secret, 'mainnet')
        descriptor = generate_descriptor(xpriv)

        body, _, checksum = descriptor.rpartition('#')
        assert body and len(checksum) == 8
        assert all(c in CHECKSUM_CHARSET for c in checksum)
        # Recomputing the checksum on the body must reproduce the full descriptor.
        assert descsum_create(body) == descriptor


class TestEndToEnd:
    """End-to-end integration tests."""

    def test_full_recovery_1_of_1(self):
        """Test complete recovery flow for 1-of-1."""
        # Parse shares
        shares = [ShareBackup.from_string(s) for s in TEST_SHARES_1_OF_1]

        # Recover secret, stating threshold 1 as the interactive flow does
        secret = recover_secret(shares, 1)
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

    def test_wallet_derivation_vector(self):
        """The 1-of-1 #0 backup and the 2-of-3 shares both recover the BIP's root xprv."""
        bare_secret = recover_secret([ShareBackup.from_string(TEST_BARE_SECRET)])
        shares_secret = recover_secret([ShareBackup.from_string(s) for s in TEST_SHARES_2_OF_3[:2]])
        assert generate_xpriv(bare_secret, 'mainnet') == EXPECTED_XPRV
        assert generate_xpriv(shares_secret, 'mainnet') == EXPECTED_XPRV


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
    print("Running tests against test vectors...")
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
