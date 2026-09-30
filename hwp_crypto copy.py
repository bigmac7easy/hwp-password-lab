import hashlib

from Crypto.Cipher import AES

import zlib

# 사용자 비밀번호
# "1234567"
#      ↓
# UTF-8 바이트 변환
# 31 32 33 ...
#      ↓
# HWP 규칙에 따른 비트 회전 + 배열 재구성
# buf
#      ↓
# SHA-1
#      ↓
# 20바이트 hash
#      ↓
# 일부 바이트를 AES key로 사용
# 예: 앞 16바이트
#      ↓
# AES-128 복호화

def derive_key(password: str) -> bytes:
    password_bytes = password.encode("utf-8")

    buf = bytearray(len(password_bytes) * 2)

    for i, current_byte in enumerate(password_bytes):
        previous_byte = password_bytes[i - 1] if i > 0 else 0xEC

        rotated = (
            (previous_byte << 1) |
            (previous_byte >> 7)
        ) & 0xFF

        buf[i * 2] = rotated
        buf[i * 2 + 1] = current_byte

    digest = hashlib.sha1(buf).digest()

    return digest[:16]


# AES-CFB1 복호화
def decrypt_cfb1(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)

    shift_register = 0
    register_mask = (1 << 128) - 1

    result = bytearray(len(data))

    for byte_index, cipher_byte in enumerate(data):

        plain_byte = 0

        for bit_index in range(8):

            register_bytes = shift_register.to_bytes(
                16,
                byteorder="big"
            )

            encrypted_register = cipher.encrypt(register_bytes)

            key_bit = (encrypted_register[0] >> 7) & 1

            cipher_bit = (
                cipher_byte >> (7 - bit_index)
            ) & 1

            plain_bit = cipher_bit ^ key_bit

            plain_byte |= (
                plain_bit << (7 - bit_index)
            )

            shift_register = (
                ((shift_register << 1) & register_mask)
                | cipher_bit
            )

        result[byte_index] = plain_byte

    return bytes(result)

def decrypt_hwp_stream(data: bytes, password: str) -> bytes:
    key = derive_key(password)
    return decrypt_cfb1(data, key)


# 압축 풀기
def decompress_hwp_stream(data: bytes) -> bytes:
    return zlib.decompress(data, -15)


# HWP 레코드 확인
def read_record_headers(data: bytes, max_records=20):
    offset = 0
    records = []

    while offset + 4 <= len(data) and len(records) < max_records:

        header = int.from_bytes(
            data[offset:offset + 4],
            byteorder="little"
        )

        offset += 4

        tag_id = header & 0x3FF
        level = (header >> 10) & 0x3FF
        size = (header >> 20) & 0xFFF

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
            (tag_id, level, size)
        )

        offset += size

    return records


# DocInfo의 정상 선두 레코드는 HWPTAG_DOCUMENT_PROPERTIES, 즉 tag 16이고, 그 뒤에 HWPTAG_ID_MAPPINGS인 17이 나오는 구조를 이용
# rhwp도 잘못된 비밀번호를 거르기 위해 이 두 레코드를 검증함
def verify_password(
    encrypted_docinfo: bytes,
    password: str,
    compressed: bool
):
    try:
        decrypted = decrypt_hwp_stream(
            encrypted_docinfo,
            password
        )

        if compressed:
            decrypted = decompress_hwp_stream(
                decrypted
            )

    except (ValueError, zlib.error):
        return False, None

    records = read_record_headers(decrypted)

    if not records:
        return False, None

    if records[0][0] != 16:
        return False, None

    if not any(
        tag_id == 17
        for tag_id, _, _ in records
    ):
        return False, None

    return True, decrypted