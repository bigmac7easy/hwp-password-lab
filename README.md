"본 도구는 보안 학술 연구 및 합법적인 권한을 가진 본인 소유 파일의 암호 분실 시 복구 목적으로만 제작되었습니다. 타인의 문서를 무단으로 해독하여 발생하는 모든 법적 책임은 전적으로 사용자 본인에게 있습니다."

# HWP Password Study

HWP 파일의 암호화 구조를 분석하고 복호화 과정을 학습하기 위한 프로젝트입니다.

## Environment

- Python 3.12+
- Windows 10/11

## Installation

필요한 패키지를 설치합니다.

```bash
pip install -r requirements.txt

## Usage

기본 실행 형식:

```bash
py .\hwp_crack.py <HWP파일경로> --start <시작번호> --end <끝번호>