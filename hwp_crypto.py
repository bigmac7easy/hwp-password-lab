import hashlib
import zlib

from Crypto.Cipher import AES


HWPTAG_DOCUMENT_PROPERTIES = 16
HWPTAG_ID_MAPPINGS = 17


def derive_key(password: str) -> bytes:
    """
    HWP EncryptVersion 4:
    password -> SHA-1 -> AES-128 key
    """

    password_bytes = password.encode("utf-8")

    buf = bytearray(
        len(password_bytes) * 2
    )

    for i, current_byte in enumerate(
        password_bytes
    ):

        previous_byte = (
            password_bytes[i - 1]
            if i > 0
            else 0xEC
        )

        rotated = (
            (previous_byte << 1)
            | (previous_byte >> 7)
        ) & 0xFF

        buf[i * 2] = rotated
        buf[i * 2 + 1] = current_byte

    digest = hashlib.sha1(buf).digest()

    return digest[:16]


def build_cfb1_register_blocks(
    data: bytes
) -> bytes:
    """
    CFB1에서 AES에 입력될 128-bit shift register들을
    미리 생성한다.

    이 값은 ciphertext에만 의존하므로
    비밀번호 후보마다 다시 만들 필요가 없다.
    """

    shift_register = 0
    register_mask = (1 << 128) - 1

    blocks = bytearray(
        len(data) * 8 * 16
    )

    offset = 0

    for cipher_byte in data:

        for bit_index in range(8):

            blocks[offset:offset + 16] = (
                shift_register.to_bytes(
                    16,
                    byteorder="big"
                )
            )

            offset += 16

            cipher_bit = (
                cipher_byte >> (7 - bit_index)
            ) & 1

            shift_register = (
                (
                    shift_register << 1
                ) & register_mask
            ) | cipher_bit

    return bytes(blocks)


def decrypt_cfb1_batched(
    data: bytes,
    key: bytes,
    register_blocks: bytes = None
) -> bytes:
    """
    CFB1 복호화.

    기존처럼 bit마다 AES.encrypt()를 호출하지 않고
    필요한 AES block을 한 번에 처리한다.
    """

    if register_blocks is None:

        register_blocks = (
            build_cfb1_register_blocks(data)
        )

    expected_length = (
        len(data) * 8 * 16
    )

    if len(register_blocks) != expected_length:
        raise ValueError(
            "register_blocks 길이가 올바르지 않습니다."
        )

    cipher = AES.new(
        key,
        AES.MODE_ECB
    )

    # 핵심:
    # 수천 번 AES.encrypt() 호출하지 않고
    # 전체 block을 한 번에 처리
    encrypted_registers = cipher.encrypt(
        register_blocks
    )

    result = bytearray(
        len(data)
    )

    register_offset = 0

    for byte_index, cipher_byte in enumerate(
        data
    ):

        key_byte = 0

        for bit_index in range(8):

            key_bit = (
                encrypted_registers[
                    register_offset
                ] >> 7
            ) & 1

            key_byte |= (
                key_bit
                << (7 - bit_index)
            )

            # AES block 하나 = 16 bytes
            register_offset += 16

        result[byte_index] = (
            cipher_byte ^ key_byte
        )

    return bytes(result)


def decompress_hwp_stream(
    data: bytes
) -> bytes:

    return zlib.decompress(
        data,
        -15
    )


def read_record_headers(
    data: bytes,
    max_records: int = 20
):

    offset = 0
    records = []

    while (
        offset + 4 <= len(data)
        and len(records) < max_records
    ):

        header = int.from_bytes(
            data[offset:offset + 4],
            byteorder="little"
        )

        offset += 4

        tag_id = header & 0x3FF

        level = (
            header >> 10
        ) & 0x3FF

        size = (
            header >> 20
        ) & 0xFFF

        if size == 0xFFF:

            if offset + 4 > len(data):
                break

            size = int.from_bytes(
                data[offset:offset + 4],
                byteorder="little"
            )

            offset += 4

        if offset + size > len(data):
            break

        records.append(
            (
                tag_id,
                level,
                size
            )
        )

        offset += size

    return records


def valid_docinfo(
    data: bytes
) -> bool:
    """
    완전히 복호화된 DocInfo가
    정상 HWP Record 구조인지 확인한다.
    """

    records = read_record_headers(
        data
    )

    if not records:
        return False

    if (
        records[0][0]
        != HWPTAG_DOCUMENT_PROPERTIES
    ):
        return False

    has_id_mappings = any(
        tag_id == HWPTAG_ID_MAPPINGS
        for tag_id, _, _ in records
    )

    return has_id_mappings


def plausible_docinfo_start(
    data: bytes
) -> bool:
    """
    빠른 후보 제거용.

    전체 DocInfo를 검사하지 않고
    첫 Record Header만 확인한다.
    """

    if len(data) < 4:
        return False

    header = int.from_bytes(
        data[0:4],
        byteorder="little"
    )

    tag_id = header & 0x3FF

    level = (
        header >> 10
    ) & 0x3FF

    size = (
        header >> 20
    ) & 0xFFF

    if (
        tag_id
        != HWPTAG_DOCUMENT_PROPERTIES
    ):
        return False

    if level != 0:
        return False

    # extended-size record
    if size == 0xFFF:

        if len(data) < 8:
            return False

        size = int.from_bytes(
            data[4:8],
            byteorder="little"
        )

        if size > 1_000_000:
            return False

    return True


def verify_password(
    encrypted_docinfo: bytes,
    password: str,
    compressed: bool
):
    """
    비밀번호 하나를 정확하게 전체 검증한다.

    hwp2john.py에서 사용하는 함수.
    """

    try:

        key = derive_key(
            password
        )

        registers = (
            build_cfb1_register_blocks(
                encrypted_docinfo
            )
        )

        decrypted = (
            decrypt_cfb1_batched(
                encrypted_docinfo,
                key,
                registers
            )
        )

        if compressed:

            decrypted = (
                decompress_hwp_stream(
                    decrypted
                )
            )

    except (
        ValueError,
        zlib.error
    ):

        return False, None

    if not valid_docinfo(
        decrypted
    ):
        return False, None

    return True, decrypted


class FastHwpVerifier:
    """
    많은 후보 비밀번호를 빠르게 검사할 때 사용.

    DocInfo 전체가 아니라 prefix만 먼저 복호화하여
    대부분의 잘못된 비밀번호를 즉시 제거한다.
    """

    def __init__(
        self,
        encrypted_docinfo: bytes,
        compressed: bool,
        prefix_bytes: int = 256
    ):

        self.encrypted_docinfo = (
            encrypted_docinfo
        )

        self.compressed = compressed

        self.prefix_bytes = min(
            prefix_bytes,
            len(encrypted_docinfo)
        )

        self.prefix = (
            encrypted_docinfo[
                :self.prefix_bytes
            ]
        )

        print(
            "CFB1 prefix 준비 중:",
            self.prefix_bytes,
            "bytes"
        )

        # 후보마다 만들지 않고
        # 파일당 딱 한 번 생성
        self.prefix_registers = (
            build_cfb1_register_blocks(
                self.prefix
            )
        )

        self.full_registers = None


    def _quick_check_key(
        self,
        key: bytes
    ) -> bool:
        """
        key가 맞을 가능성이 있는지만 빠르게 확인.
        """

        try:

            decrypted_prefix = (
                decrypt_cfb1_batched(
                    self.prefix,
                    key,
                    self.prefix_registers
                )
            )

            if self.compressed:

                decompressor = (
                    zlib.decompressobj(
                        -15
                    )
                )

                # 첫 Record 판정에 필요한
                # 앞부분만 얻는다.
                plain_prefix = (
                    decompressor.decompress(
                        decrypted_prefix,
                        64
                    )
                )

            else:

                plain_prefix = (
                    decrypted_prefix[:64]
                )

        except (
            ValueError,
            zlib.error
        ):

            return False

        return plausible_docinfo_start(
            plain_prefix
        )


    def quick_check(
        self,
        password: str
    ) -> bool:
        """
        대량 후보 검사용.
        """

        key = derive_key(
            password
        )

        return self._quick_check_key(
            key
        )


    def verify(
        self,
        password: str
    ):
        """
        quick check 통과 후
        전체 DocInfo까지 검증한다.
        """

        key = derive_key(
            password
        )

        if not self._quick_check_key(
            key
        ):
            return False, None

        try:

            # 실제 후보가 나타났을 때만
            # 전체 DocInfo용 register 계산
            if self.full_registers is None:

                self.full_registers = (
                    build_cfb1_register_blocks(
                        self.encrypted_docinfo
                    )
                )

            decrypted = (
                decrypt_cfb1_batched(
                    self.encrypted_docinfo,
                    key,
                    self.full_registers
                )
            )

            if self.compressed:

                decrypted = (
                    decompress_hwp_stream(
                        decrypted
                    )
                )

        except (
            ValueError,
            zlib.error
        ):

            return False, None

        if not valid_docinfo(
            decrypted
        ):
            return False, None

        return True, decrypted