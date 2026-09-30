import argparse
import struct
import time

import olefile

from hwp_crypto import FastHwpVerifier


def load_hwp(path):

    if not olefile.isOleFile(path):
        raise ValueError(
            "OLE Compound File이 아닙니다."
        )

    with olefile.OleFileIO(path) as ole:

        if not ole.exists("FileHeader"):
            raise ValueError(
                "FileHeader가 없습니다."
            )

        header = (
            ole.openstream(
                "FileHeader"
            ).read()
        )

        if len(header) < 48:
            raise ValueError(
                "FileHeader가 너무 짧습니다."
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

        if not password_protected:

            raise ValueError(
                "암호가 설정된 HWP가 아닙니다."
            )

        if encrypt_version != 4:

            raise ValueError(
                "현재 지원하지 않는 "
                f"EncryptVersion: "
                f"{encrypt_version}"
            )

        if not ole.exists("DocInfo"):

            raise ValueError(
                "DocInfo가 없습니다."
            )

        encrypted_docinfo = (
            ole.openstream(
                "DocInfo"
            ).read()
        )

    return (
        encrypted_docinfo,
        compressed
    )


def benchmark(
    verifier,
    count
):

    print()
    print("=== Benchmark ===")
    print(
        "테스트 개수 :",
        f"{count:,}"
    )

    start = time.perf_counter()

    possible_hits = 0

    for number in range(count):

        password = (
            f"{number:07d}"
        )

        if verifier.quick_check(
            password
        ):
            possible_hits += 1

    elapsed = (
        time.perf_counter()
        - start
    )

    speed = (
        count / elapsed
    )

    print()
    print(
        f"소요 시간   : "
        f"{elapsed:.3f}초"
    )

    print(
        f"검사 개수   : "
        f"{count:,}"
    )

    print(
        f"처리 속도   : "
        f"{speed:,.0f} passwords/sec"
    )

    print(
        f"빠른 검사 통과 후보 : "
        f"{possible_hits:,}"
    )

    total_candidates = (
        10_000_000
    )

    worst_seconds = (
        total_candidates
        / speed
    )

    average_seconds = (
        worst_seconds / 2
    )

    print()
    print(
        "=== 숫자 7자리 예상 ==="
    )

    print(
        "전체 후보 :",
        f"{total_candidates:,}"
    )

    print(
        f"최악 예상 : "
        f"{worst_seconds:.1f}초"
    )

    print(
        f"          "
        f"{worst_seconds / 60:.1f}분"
    )

    print(
        f"          "
        f"{worst_seconds / 3600:.2f}시간"
    )

    print()

    print(
        f"평균 예상 : "
        f"{average_seconds:.1f}초"
    )

    print(
        f"          "
        f"{average_seconds / 60:.1f}분"
    )

    print(
        f"          "
        f"{average_seconds / 3600:.2f}시간"
    )


def main():

    parser = argparse.ArgumentParser(
        description=(
            "HWP password verifier benchmark"
        )
    )

    parser.add_argument(
        "file",
        help="HWP 파일 경로"
    )

    parser.add_argument(
        "-n",
        "--count",
        type=int,
        default=1000,
        help=(
            "벤치마크 후보 개수 "
            "(기본 1000)"
        )
    )

    parser.add_argument(
        "--prefix",
        type=int,
        default=256,
        help=(
            "빠른 검증에 사용할 "
            "DocInfo byte 수 "
            "(기본 256)"
        )
    )

    parser.add_argument(
        "--known-password",
        help=(
            "빠른 검증기가 실제 정답을 "
            "인식하는지 확인"
        )
    )

    args = parser.parse_args()

    (
        encrypted_docinfo,
        compressed
    ) = load_hwp(
        args.file
    )

    print(
        "DocInfo 크기 :",
        len(encrypted_docinfo),
        "bytes"
    )

    verifier = FastHwpVerifier(
        encrypted_docinfo,
        compressed,
        prefix_bytes=args.prefix
    )

    if args.known_password:

        print()
        print(
            "=== Known password test ==="
        )

        result = (
            verifier.quick_check(
                args.known_password
            )
        )

        print(
            "Password :",
            args.known_password
        )

        print(
            "빠른 검증 결과 :",
            result
        )

        if not result:

            print()
            print(
                "주의: prefix가 너무 짧을 "
                "가능성이 있습니다."
            )

            print(
                "--prefix 512 또는 "
                "--prefix 1024로 "
                "다시 테스트하세요."
            )

            return

    benchmark(
        verifier,
        args.count
    )


if __name__ == "__main__":
    main()