import argparse
import multiprocessing as mp
import os
import struct
import sys
import time

import olefile

from hwp_crypto import FastHwpVerifier


# 각 worker 프로세스에서 사용할 전역 객체
_worker_verifier = None
_worker_digits = 7


def load_hwp(path):
    """
    HWP에서 암호화된 DocInfo와 필요한 정보를 읽는다.
    """

    if not olefile.isOleFile(path):
        raise ValueError(
            "OLE Compound File이 아닙니다."
        )

    with olefile.OleFileIO(path) as ole:

        if not ole.exists("FileHeader"):
            raise ValueError(
                "FileHeader가 없습니다."
            )

        header = ole.openstream(
            "FileHeader"
        ).read()

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
                f"EncryptVersion: {encrypt_version}"
            )

        if not ole.exists("DocInfo"):
            raise ValueError(
                "DocInfo 스트림이 없습니다."
            )

        encrypted_docinfo = (
            ole.openstream(
                "DocInfo"
            ).read()
        )

    return (
        encrypted_docinfo,
        compressed,
        encrypt_version
    )


def init_worker(
    encrypted_docinfo,
    compressed,
    prefix_bytes,
    digits
):
    """
    각 프로세스가 시작될 때 딱 한 번 실행된다.

    FastHwpVerifier를 프로세스마다 하나씩 생성한다.
    """

    global _worker_verifier
    global _worker_digits

    _worker_digits = digits

    _worker_verifier = FastHwpVerifier(
        encrypted_docinfo,
        compressed,
        prefix_bytes=prefix_bytes
    )


def crack_range(task):
    """
    한 worker가 숫자 범위 하나를 검사한다.

    task:
        (start, end)

    반환:
        (찾은 비밀번호 또는 None, 검사한 개수)
    """

    start, end = task

    tested = 0

    for number in range(start, end):

        password = (
            f"{number:0{_worker_digits}d}"
        )

        tested += 1

        # 먼저 초고속 필터
        if not _worker_verifier.quick_check(
            password
        ):
            continue

        # quick check를 통과했다면
        # 전체 DocInfo로 진짜 정답인지 확인
        success, _ = (
            _worker_verifier.verify(
                password
            )
        )

        if success:

            return (
                password,
                tested
            )

    return (
        None,
        tested
    )


def make_tasks(
    start,
    end,
    chunk_size
):
    """
    전체 범위를 chunk 단위 작업으로 나눈다.
    """

    current = start

    while current < end:

        chunk_end = min(
            current + chunk_size,
            end
        )

        yield (
            current,
            chunk_end
        )

        current = chunk_end


def format_time(seconds):
    """
    초를 보기 좋은 시간으로 변환.
    """

    if seconds < 60:
        return f"{seconds:.1f}초"

    minutes = seconds / 60

    if minutes < 60:
        return f"{minutes:.1f}분"

    hours = minutes / 60

    return f"{hours:.2f}시간"


def main():

    parser = argparse.ArgumentParser(
        description=(
            "HWP5 숫자 비밀번호 "
            "multiprocessing brute-force"
        )
    )

    parser.add_argument(
        "file",
        help="암호화된 HWP 파일"
    )

    parser.add_argument(
        "--digits",
        type=int,
        default=7,
        help=(
            "숫자 비밀번호 자리수 "
            "(기본 7)"
        )
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=max(
            1,
            (os.cpu_count() or 2) - 1
        ),
        help=(
            "worker 프로세스 수 "
            "(기본값: CPU 논리 코어 - 1)"
        )
    )

    parser.add_argument(
        "--chunk",
        type=int,
        default=5000,
        help=(
            "프로세스에 전달할 "
            "후보 숫자 묶음 크기 "
            "(기본 5000)"
        )
    )

    parser.add_argument(
        "--prefix",
        type=int,
        default=256,
        help=(
            "빠른 검증에 사용할 "
            "DocInfo prefix 크기 "
            "(기본 256 bytes)"
        )
    )

    parser.add_argument(
        "--start",
        type=int,
        default=0,
        help="탐색 시작 숫자"
    )

    parser.add_argument(
        "--end",
        type=int,
        default=None,
        help="탐색 종료 숫자"
    )

    args = parser.parse_args()

    if args.digits <= 0:
        print(
            "--digits는 1 이상이어야 합니다."
        )
        sys.exit(1)

    max_candidates = (
        10 ** args.digits
    )

    start_number = args.start

    end_number = (
        args.end
        if args.end is not None
        else max_candidates
    )

    if start_number < 0:
        print(
            "--start는 0 이상이어야 합니다."
        )
        sys.exit(1)

    if end_number > max_candidates:
        print(
            f"{args.digits}자리 숫자의 최대 범위는 "
            f"0 ~ {max_candidates - 1}입니다."
        )
        sys.exit(1)

    if start_number >= end_number:
        print(
            "start는 end보다 작아야 합니다."
        )
        sys.exit(1)

    (
        encrypted_docinfo,
        compressed,
        encrypt_version
    ) = load_hwp(
        args.file
    )

    total_candidates = (
        end_number
        - start_number
    )

    print()
    print("=== HWP Password Cracker ===")
    print(
        "파일            :",
        args.file
    )
    print(
        "EncryptVersion  :",
        encrypt_version
    )
    print(
        "DocInfo 크기    :",
        len(encrypted_docinfo),
        "bytes"
    )
    print(
        "숫자 자리수     :",
        args.digits
    )
    print(
        "탐색 시작       :",
        f"{start_number:0{args.digits}d}"
    )
    print(
        "탐색 종료       :",
        f"{end_number - 1:0{args.digits}d}"
    )
    print(
        "전체 후보       :",
        f"{total_candidates:,}"
    )
    print(
        "Worker 수       :",
        args.workers
    )
    print(
        "Chunk 크기      :",
        f"{args.chunk:,}"
    )
    print(
        "Prefix          :",
        args.prefix,
        "bytes"
    )

    print()
    print("탐색 시작...")

    tasks = make_tasks(
        start_number,
        end_number,
        args.chunk
    )

    start_time = (
        time.perf_counter()
    )

    total_tested = 0
    found_password = None

    # Windows에서는 이 구조가 특히 중요함
    with mp.Pool(
        processes=args.workers,
        initializer=init_worker,
        initargs=(
            encrypted_docinfo,
            compressed,
            args.prefix,
            args.digits
        )
    ) as pool:

        try:

            results = pool.imap_unordered(
                crack_range,
                tasks,
                chunksize=1
            )

            last_status_time = (
                time.perf_counter()
            )

            for password, tested in results:

                total_tested += tested

                if password is not None:

                    found_password = password

                    # 다른 프로세스 즉시 종료
                    pool.terminate()

                    break

                now = (
                    time.perf_counter()
                )

                # 너무 자주 출력하지 않고
                # 약 1초마다 상태 표시
                if (
                    now - last_status_time
                    >= 1.0
                ):

                    elapsed = (
                        now - start_time
                    )

                    speed = (
                        total_tested
                        / elapsed
                    )

                    progress = (
                        total_tested
                        / total_candidates
                        * 100
                    )

                    remaining = (
                        total_candidates
                        - total_tested
                    )

                    eta = (
                        remaining / speed
                        if speed > 0
                        else 0
                    )

                    print(
                        f"\r진행률 {progress:6.2f}%"
                        f" | "
                        f"{total_tested:,}"
                        f"/"
                        f"{total_candidates:,}"
                        f" | "
                        f"{speed:,.0f} pw/s"
                        f" | "
                        f"ETA {format_time(eta)}",
                        end="",
                        flush=True
                    )

                    last_status_time = now

        except KeyboardInterrupt:

            print()
            print("사용자가 중단했습니다.")

            pool.terminate()

            return

    elapsed = (
        time.perf_counter()
        - start_time
    )

    print()
    print()

    if found_password:

        speed = (
            total_tested / elapsed
            if elapsed > 0
            else 0
        )

        print("==========================")
        print("비밀번호 발견")
        print("==========================")
        print(
            "Password :",
            found_password
        )
        print(
            "검사 수   :",
            f"{total_tested:,}"
        )
        print(
            "소요 시간 :",
            format_time(elapsed)
        )
        print(
            "평균 속도 :",
            f"{speed:,.0f} passwords/sec"
        )

    else:

        speed = (
            total_tested / elapsed
            if elapsed > 0
            else 0
        )

        print(
            "지정한 범위에서는 "
            "비밀번호를 찾지 못했습니다."
        )

        print(
            "검사 수   :",
            f"{total_tested:,}"
        )

        print(
            "소요 시간 :",
            format_time(elapsed)
        )

        print(
            "평균 속도 :",
            f"{speed:,.0f} passwords/sec"
        )


if __name__ == "__main__":

    # Windows multiprocessing에서 권장
    mp.freeze_support()

    main()