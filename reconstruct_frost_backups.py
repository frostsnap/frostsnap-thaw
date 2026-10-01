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
import re
from typing import List, Tuple
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


# BIP39 English wordlist, embedded so this tool is fully self-contained and
# has zero third-party wordlist dependency. This list is a frozen public
# standard (BIP39) and never changes. The self-check below fails loudly if a
# single word is altered or transcribed wrong, so a corrupted copy can never
# silently mis-decode a share.
WORDLIST = (
    "abandon ability able about above absent absorb abstract absurd abuse access accident "
    "account accuse achieve acid acoustic acquire across act action actor actress actual "
    "adapt add addict address adjust admit adult advance advice aerobic affair afford "
    "afraid again age agent agree ahead aim air airport aisle alarm album "
    "alcohol alert alien all alley allow almost alone alpha already also alter "
    "always amateur amazing among amount amused analyst anchor ancient anger angle angry "
    "animal ankle announce annual another answer antenna antique anxiety any apart apology "
    "appear apple approve april arch arctic area arena argue arm armed armor "
    "army around arrange arrest arrive arrow art artefact artist artwork ask aspect "
    "assault asset assist assume asthma athlete atom attack attend attitude attract auction "
    "audit august aunt author auto autumn average avocado avoid awake aware away "
    "awesome awful awkward axis baby bachelor bacon badge bag balance balcony ball "
    "bamboo banana banner bar barely bargain barrel base basic basket battle beach "
    "bean beauty because become beef before begin behave behind believe below belt "
    "bench benefit best betray better between beyond bicycle bid bike bind biology "
    "bird birth bitter black blade blame blanket blast bleak bless blind blood "
    "blossom blouse blue blur blush board boat body boil bomb bone bonus "
    "book boost border boring borrow boss bottom bounce box boy bracket brain "
    "brand brass brave bread breeze brick bridge brief bright bring brisk broccoli "
    "broken bronze broom brother brown brush bubble buddy budget buffalo build bulb "
    "bulk bullet bundle bunker burden burger burst bus business busy butter buyer "
    "buzz cabbage cabin cable cactus cage cake call calm camera camp can "
    "canal cancel candy cannon canoe canvas canyon capable capital captain car carbon "
    "card cargo carpet carry cart case cash casino castle casual cat catalog "
    "catch category cattle caught cause caution cave ceiling celery cement census century "
    "cereal certain chair chalk champion change chaos chapter charge chase chat cheap "
    "check cheese chef cherry chest chicken chief child chimney choice choose chronic "
    "chuckle chunk churn cigar cinnamon circle citizen city civil claim clap clarify "
    "claw clay clean clerk clever click client cliff climb clinic clip clock "
    "clog close cloth cloud clown club clump cluster clutch coach coast coconut "
    "code coffee coil coin collect color column combine come comfort comic common "
    "company concert conduct confirm congress connect consider control convince cook cool copper "
    "copy coral core corn correct cost cotton couch country couple course cousin "
    "cover coyote crack cradle craft cram crane crash crater crawl crazy cream "
    "credit creek crew cricket crime crisp critic crop cross crouch crowd crucial "
    "cruel cruise crumble crunch crush cry crystal cube culture cup cupboard curious "
    "current curtain curve cushion custom cute cycle dad damage damp dance danger "
    "daring dash daughter dawn day deal debate debris decade december decide decline "
    "decorate decrease deer defense define defy degree delay deliver demand demise denial "
    "dentist deny depart depend deposit depth deputy derive describe desert design desk "
    "despair destroy detail detect develop device devote diagram dial diamond diary dice "
    "diesel diet differ digital dignity dilemma dinner dinosaur direct dirt disagree discover "
    "disease dish dismiss disorder display distance divert divide divorce dizzy doctor document "
    "dog doll dolphin domain donate donkey donor door dose double dove draft "
    "dragon drama drastic draw dream dress drift drill drink drip drive drop "
    "drum dry duck dumb dune during dust dutch duty dwarf dynamic eager "
    "eagle early earn earth easily east easy echo ecology economy edge edit "
    "educate effort egg eight either elbow elder electric elegant element elephant elevator "
    "elite else embark embody embrace emerge emotion employ empower empty enable enact "
    "end endless endorse enemy energy enforce engage engine enhance enjoy enlist enough "
    "enrich enroll ensure enter entire entry envelope episode equal equip era erase "
    "erode erosion error erupt escape essay essence estate eternal ethics evidence evil "
    "evoke evolve exact example excess exchange excite exclude excuse execute exercise exhaust "
    "exhibit exile exist exit exotic expand expect expire explain expose express extend "
    "extra eye eyebrow fabric face faculty fade faint faith fall false fame "
    "family famous fan fancy fantasy farm fashion fat fatal father fatigue fault "
    "favorite feature february federal fee feed feel female fence festival fetch fever "
    "few fiber fiction field figure file film filter final find fine finger "
    "finish fire firm first fiscal fish fit fitness fix flag flame flash "
    "flat flavor flee flight flip float flock floor flower fluid flush fly "
    "foam focus fog foil fold follow food foot force forest forget fork "
    "fortune forum forward fossil foster found fox fragile frame frequent fresh friend "
    "fringe frog front frost frown frozen fruit fuel fun funny furnace fury "
    "future gadget gain galaxy gallery game gap garage garbage garden garlic garment "
    "gas gasp gate gather gauge gaze general genius genre gentle genuine gesture "
    "ghost giant gift giggle ginger giraffe girl give glad glance glare glass "
    "glide glimpse globe gloom glory glove glow glue goat goddess gold good "
    "goose gorilla gospel gossip govern gown grab grace grain grant grape grass "
    "gravity great green grid grief grit grocery group grow grunt guard guess "
    "guide guilt guitar gun gym habit hair half hammer hamster hand happy "
    "harbor hard harsh harvest hat have hawk hazard head health heart heavy "
    "hedgehog height hello helmet help hen hero hidden high hill hint hip "
    "hire history hobby hockey hold hole holiday hollow home honey hood hope "
    "horn horror horse hospital host hotel hour hover hub huge human humble "
    "humor hundred hungry hunt hurdle hurry hurt husband hybrid ice icon idea "
    "identify idle ignore ill illegal illness image imitate immense immune impact impose "
    "improve impulse inch include income increase index indicate indoor industry infant inflict "
    "inform inhale inherit initial inject injury inmate inner innocent input inquiry insane "
    "insect inside inspire install intact interest into invest invite involve iron island "
    "isolate issue item ivory jacket jaguar jar jazz jealous jeans jelly jewel "
    "job join joke journey joy judge juice jump jungle junior junk just "
    "kangaroo keen keep ketchup key kick kid kidney kind kingdom kiss kit "
    "kitchen kite kitten kiwi knee knife knock know lab label labor ladder "
    "lady lake lamp language laptop large later latin laugh laundry lava law "
    "lawn lawsuit layer lazy leader leaf learn leave lecture left leg legal "
    "legend leisure lemon lend length lens leopard lesson letter level liar liberty "
    "library license life lift light like limb limit link lion liquid list "
    "little live lizard load loan lobster local lock logic lonely long loop "
    "lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics "
    "machine mad magic magnet maid mail main major make mammal man manage "
    "mandate mango mansion manual maple marble march margin marine market marriage mask "
    "mass master match material math matrix matter maximum maze meadow mean measure "
    "meat mechanic medal media melody melt member memory mention menu mercy merge "
    "merit merry mesh message metal method middle midnight milk million mimic mind "
    "minimum minor minute miracle mirror misery miss mistake mix mixed mixture mobile "
    "model modify mom moment monitor monkey monster month moon moral more morning "
    "mosquito mother motion motor mountain mouse move movie much muffin mule multiply "
    "muscle museum mushroom music must mutual myself mystery myth naive name napkin "
    "narrow nasty nation nature near neck need negative neglect neither nephew nerve "
    "nest net network neutral never news next nice night noble noise nominee "
    "noodle normal north nose notable note nothing notice novel now nuclear number "
    "nurse nut oak obey object oblige obscure observe obtain obvious occur ocean "
    "october odor off offer office often oil okay old olive olympic omit "
    "once one onion online only open opera opinion oppose option orange orbit "
    "orchard order ordinary organ orient original orphan ostrich other outdoor outer output "
    "outside oval oven over own owner oxygen oyster ozone pact paddle page "
    "pair palace palm panda panel panic panther paper parade parent park parrot "
    "party pass patch path patient patrol pattern pause pave payment peace peanut "
    "pear peasant pelican pen penalty pencil people pepper perfect permit person pet "
    "phone photo phrase physical piano picnic picture piece pig pigeon pill pilot "
    "pink pioneer pipe pistol pitch pizza place planet plastic plate play please "
    "pledge pluck plug plunge poem poet point polar pole police pond pony "
    "pool popular portion position possible post potato pottery poverty powder power practice "
    "praise predict prefer prepare present pretty prevent price pride primary print priority "
    "prison private prize problem process produce profit program project promote proof property "
    "prosper protect proud provide public pudding pull pulp pulse pumpkin punch pupil "
    "puppy purchase purity purpose purse push put puzzle pyramid quality quantum quarter "
    "question quick quit quiz quote rabbit raccoon race rack radar radio rail "
    "rain raise rally ramp ranch random range rapid rare rate rather raven "
    "raw razor ready real reason rebel rebuild recall receive recipe record recycle "
    "reduce reflect reform refuse region regret regular reject relax release relief rely "
    "remain remember remind remove render renew rent reopen repair repeat replace report "
    "require rescue resemble resist resource response result retire retreat return reunion reveal "
    "review reward rhythm rib ribbon rice rich ride ridge rifle right rigid "
    "ring riot ripple risk ritual rival river road roast robot robust rocket "
    "romance roof rookie room rose rotate rough round route royal rubber rude "
    "rug rule run runway rural sad saddle sadness safe sail salad salmon "
    "salon salt salute same sample sand satisfy satoshi sauce sausage save say "
    "scale scan scare scatter scene scheme school science scissors scorpion scout scrap "
    "screen script scrub sea search season seat second secret section security seed "
    "seek segment select sell seminar senior sense sentence series service session settle "
    "setup seven shadow shaft shallow share shed shell sheriff shield shift shine "
    "ship shiver shock shoe shoot shop short shoulder shove shrimp shrug shuffle "
    "shy sibling sick side siege sight sign silent silk silly silver similar "
    "simple since sing siren sister situate six size skate sketch ski skill "
    "skin skirt skull slab slam sleep slender slice slide slight slim slogan "
    "slot slow slush small smart smile smoke smooth snack snake snap sniff "
    "snow soap soccer social sock soda soft solar soldier solid solution solve "
    "someone song soon sorry sort soul sound soup source south space spare "
    "spatial spawn speak special speed spell spend sphere spice spider spike spin "
    "spirit split spoil sponsor spoon sport spot spray spread spring spy square "
    "squeeze squirrel stable stadium staff stage stairs stamp stand start state stay "
    "steak steel stem step stereo stick still sting stock stomach stone stool "
    "story stove strategy street strike strong struggle student stuff stumble style subject "
    "submit subway success such sudden suffer sugar suggest suit summer sun sunny "
    "sunset super supply supreme sure surface surge surprise surround survey suspect sustain "
    "swallow swamp swap swarm swear sweet swift swim swing switch sword symbol "
    "symptom syrup system table tackle tag tail talent talk tank tape target "
    "task taste tattoo taxi teach team tell ten tenant tennis tent term "
    "test text thank that theme then theory there they thing this thought "
    "three thrive throw thumb thunder ticket tide tiger tilt timber time tiny "
    "tip tired tissue title toast tobacco today toddler toe together toilet token "
    "tomato tomorrow tone tongue tonight tool tooth top topic topple torch tornado "
    "tortoise toss total tourist toward tower town toy track trade traffic tragic "
    "train transfer trap trash travel tray treat tree trend trial tribe trick "
    "trigger trim trip trophy trouble truck true truly trumpet trust truth try "
    "tube tuition tumble tuna tunnel turkey turn turtle twelve twenty twice twin "
    "twist two type typical ugly umbrella unable unaware uncle uncover under undo "
    "unfair unfold unhappy uniform unique unit universe unknown unlock until unusual unveil "
    "update upgrade uphold upon upper upset urban urge usage use used useful "
    "useless usual utility vacant vacuum vague valid valley valve van vanish vapor "
    "various vast vault vehicle velvet vendor venture venue verb verify version very "
    "vessel veteran viable vibrant vicious victory video view village vintage violin virtual "
    "virus visa visit visual vital vivid vocal voice void volcano volume vote "
    "voyage wage wagon wait walk wall walnut want warfare warm warrior wash "
    "wasp waste water wave way wealth weapon wear weasel weather web wedding "
    "weekend weird welcome west wet whale what wheat wheel when where whip "
    "whisper wide width wife wild will win window wine wing wink winner "
    "winter wire wisdom wise wish witness wolf woman wonder wood wool word "
    "work world worry worth wrap wreck wrestle wrist write wrong yard year "
    "yellow you young youth zebra zero zone zoo "
).split()

_BIP39_ENGLISH_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
assert len(WORDLIST) == 2048, f"BIP39 wordlist must be 2048 words, got {len(WORDLIST)}"
assert (
    hashlib.sha256(('\n'.join(WORDLIST) + '\n').encode()).hexdigest()
    == _BIP39_ENGLISH_SHA256
), "Embedded BIP39 wordlist is corrupted (sha256 mismatch)"

# Word -> 11-bit index lookup (BIP39 position).
WORD_INDEX = {word: i for i, word in enumerate(WORDLIST)}


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

        # Convert words to 11-bit indices using the embedded BIP39 wordlist
        word_indices = []
        for i, word in enumerate(words):
            idx = WORD_INDEX.get(word.lower())
            if idx is None:
                raise ShareBackupError(f"Word #{i+1} '{word}' not in BIP39 wordlist")
            word_indices.append(idx)

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
            combined_cdata = weighted_points[0].combine([wp.public_key for wp in weighted_points])
            # Wrap the cdata result back into a PublicKey for serialization
            result_point = secp256k1.PublicKey(combined_cdata)

        # Serialize the coefficient point
        poly_points.append(result_point.serialize(compressed=True))

    return b''.join(poly_points)


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


def recover_secret(shares: List[ShareBackup], threshold: int = None) -> bytes:
    """
    Recover secret from threshold shares using Lagrange interpolation.

    Performs polynomial checksum verification to detect mismatched shares.

    Args:
        shares: List of ShareBackup objects
        threshold: Polynomial threshold (defaults to number of shares)

    Returns:
        32-byte secret

    Raises:
        ValueError: If shares are invalid or polynomial checksum fails
    """
    if not shares:
        raise ValueError("No shares provided")

    if threshold is None:
        threshold = len(shares)

    indices = [share.index for share in shares]
    scalars = [int.from_bytes(share.scalar_bytes, 'big') for share in shares]

    if len(indices) != len(set(indices)):
        raise ValueError("Duplicate share indices detected")

    # Reconstruct polynomial commitment from share images
    share_images = [compute_share_image(s.index, s.scalar_bytes) for s in shares]
    poly_commitment = reconstruct_polynomial_commitment(share_images, threshold)

    # Verify polynomial checksum for each share
    for share in shares:
        if not verify_polynomial_checksum(share, poly_commitment):
            raise ValueError(
                f"Polynomial checksum failed for share #{share.index}. "
                "Shares may be from different wallets."
            )

    # Reconstruct secret using Lagrange interpolation
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
