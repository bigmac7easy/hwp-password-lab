import argparse
import getpass
import struct
import sys

import olefile

from hwp_crypto import verify_password


def read_file_header(ole):
    if not ole.exists("FileHeader"):
        raise ValueError(
            "FileHeader 스트림을 찾을 수 없습니다."
        )

    header = ole.openstream(
        "FileHeader"
    ).read()

    if len(header) < 48:
        raise ValueError(
            "FileHeader가 너무 짧습니다."
        )

    signature = (
        header[0:32]
        .rstrip(b"\x00")
        .decode(
            "ascii",
            errors="replace"
        )
    )

    version_raw = header[32:36]

    version = ".".join(
        str(x)
        for x in reversed(version_raw)
    )

    properties = struct.unpack(
        "<I",
        header[36:40]
    )[0]

    encrypt_version = struct.unpack(
        "<I",
        header[44:48]
    )[0]

    compressed = bool(
        properties & (1 << 0)
    )

    password_protected = bool(
        properties & (1 << 1)
    )

    return {
        "signature": signature,
        "version": version,
        "properties": properties,
        "compressed": compressed,
        "password_protected": password_protected,
        "encrypt_version": encrypt_version,
    }


def main():

    parser = argparse.ArgumentParser(
        description=(
            "HWP5 EncryptVersion 4 "
            "password verifier"
        )
    )

    parser.add_argument(
        "file",
        help="HWP 파일 경로"
    )

    parser.add_argument(
        "-p",
        "--password",
        help="확인할 비밀번호"
    )

    args = parser.parse_args()

    path = args.file

    if not olefile.isOleFile(path):

        print(
            "OLE Compound File이 아닙니다."
        )

        sys.exit(1)

    with olefile.OleFileIO(path) as ole:

        info = read_file_header(ole)

        print("=== HWP FileHeader ===")
        print(
            "Signature      :",
            info["signature"]
        )
        print(
            "Version        :",
            info["version"]
        )
        print(
            "Properties     :",
            f'0x{info["properties"]:08X}'
        )
        print(
            "압축           :",
            info["compressed"]
        )
        print(
            "암호 설정      :",
            info["password_protected"]
        )
        print(
            "EncryptVersion :",
            info["encrypt_version"]
        )

        if not info["password_protected"]:

            print()
            print(
                "암호가 설정된 HWP가 아닙니다."
            )

            sys.exit(0)

        if info["encrypt_version"] != 4:

            print()
            print(
                "현재 코드는 "
                "EncryptVersion 4만 지원합니다."
            )

            sys.exit(1)

        if not ole.exists("DocInfo"):

            print(
                "DocInfo 스트림이 없습니다."
            )

            sys.exit(1)

        encrypted_docinfo = (
            ole.openstream(
                "DocInfo"
            ).read()
        )

    password = args.password

    if password is None:

        password = getpass.getpass(
            "비밀번호: "
        )

    print()
    print("비밀번호 검증 중...")

    success, decrypted_docinfo = (
        verify_password(
            encrypted_docinfo,
            password,
            info["compressed"]
        )
    )

    if success:

        print()
        print("==========================")
        print("비밀번호 일치")
        print("==========================")
        print("Password :", password)
        print(
            "DocInfo 복호화 크기 :",
            len(decrypted_docinfo),
            "bytes"
        )
        print(
            "앞 32 bytes :",
            decrypted_docinfo[:32].hex(" ")
        )

    else:

        print()
        print("비밀번호 불일치")

        sys.exit(2)


if __name__ == "__main__":
    main()