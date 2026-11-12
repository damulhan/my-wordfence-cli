# Wordfence CLI (Community Offline Edition)

> [!NOTE]
> 본 레포지토리는 공식 [Wordfence CLI](https://github.com/wordfence/wordfence-cli/)가 EOL(신규 무료/유료 라이선스 발급 중단)됨에 따라, **외부 중앙 API 키 인증 없이 오프라인 환경에서 로컬 룰셋 및 공개 YARA 웹셸 시그니처를 기반으로 스캔할 수 있도록 커스터마이즈된 버전**입니다.

Wordfence CLI는 Python 기반의 고성능 멀티프로세스 파일 스캐너로, 대용량 파일 시스템을 병렬로 탐색하며 `libpcre` 엔진을 활용해 PHP 웹셸, 백도어 및 악성코드를 초고속으로 검사합니다.

---

## 🛠 커스터마이즈 내역 (Custom Modifications)

1. **라이선스 및 약관 동의 완전 우회 (Bypass)**:
   - 외부 중앙 서버(`noc1.wordfence.com`)에 API Key 검증을 요청하는 과정을 바이패스하여 라이선스 키 없이도 즉시 동작합니다.
   - 초기 실행 시 대화형 설정 프롬프트(`wordfence configure`) 없이 바로 스캔 명령어를 실행할 수 있습니다.
2. **로컬 시그니처 주입 지원 (`--signatures-file`)**:
   - `malware-scan` 하위 명령어에 `--signatures-file <path_to_json>` 옵션이 추가되었습니다.
   - 외부 다운로드 없이 사용자가 지정한 로컬 JSON 룰셋을 로드하여 고속 PCRE 엔진으로 스캔합니다.
3. **YARA 룰셋 자동 변환 도구 제공 (`convert_yara_to_rules.py`)**:
   - 보안 커뮤니티의 오픈소스 YARA 웹셸 룰셋(`.yar`)을 Wordfence CLI 호환 JSON 시그니처로 파싱/변환해 주는 스크립트를 기본 내장합니다.
4. **기본 룰셋 번들 제공**:
   - `rules_sample.json`: 대표적인 PHP 난독화 eval, system/exec 웹셸 룰셋
   - `rules_yara.json`: Florian Roth의 `thor-webshells.yar` 기반 622개 웹셸 탐지 룰셋
   - `rules_all.json`: 기본 샘플과 YARA 룰을 합친 625개 통합 웹셸 룰셋

---

## 🚀 빠른 시작 (Quick Start)

### 1. 요구 사항
- Python >= 3.8
- `libpcre` C 라이브러리 >= 8.38
- 필수 패키지 설치:
  ```bash
  pip install -r requirements.txt # 또는 pip install .
  ```

### 2. 악성코드 검사 실행
기본 탑재된 통합 룰셋(`rules_all.json`)을 사용해 원하는 디렉터리를 스캔합니다:

```bash
# 디렉터리 스캔 (결과 실시간 출력)
python3 main.py malware-scan --signatures-file rules_all.json --output-format human /var/www

# 감염 의심 파일 결과를 CSV 파일로 저장
python3 main.py malware-scan --signatures-file rules_all.json --output-path /tmp/scan_results.csv --output-format csv /var/www

# 모든 확장자의 파일 검사 (-a, --include-all-files)
python3 main.py malware-scan -a --signatures-file rules_all.json /var/www
```

> [!TIP]
> **오탐(False Positive) 방지 및 빠른 진단 팁**:
> `rules_all.json`에는 광범위한 YARA 룰이 포함되어 있어 정상 프레임워크나 워드프레스 코어 파일 등에서 검색 결과가 과도하게 많이 나올 수 있습니다.
> 명확하고 핵심적인 웹셸/난독화 패턴만 빠르게 스캔하려면 먼저 **`rules_sample.json`**을 지정하여 실행해 보시는 것을 권장합니다:
> ```bash
> # 핵심 웹셸 패턴만 정밀 스캔 (추천)
> python3 main.py malware-scan --signatures-file rules_sample.json --output-format human /var/www
> ```


---

## 🔍 YARA 룰셋 변환 및 커스텀 룰 관리 (`convert_yara_to_rules.py`)

기존에 사용 중이던 YARA 웹셸 룰셋이나 최신 공개 룰셋을 손쉽게 Wordfence CLI 규격으로 변환할 수 있습니다.

> [!NOTE]
> **공개 YARA 룰셋 다운로드 참고**:
> 웹셸 및 악성코드 시그니처 원본 파일들은 [Neo23x0/signature-base YARA 저장소](https://github.com/Neo23x0/signature-base/tree/master/yara)에서 다운로드하여 사용할 수 있습니다.
> 웹 서버 환경에서는 주로 `thor-webshells.yar`, `gen_webshells.yar`, `apt_webshell_chinachopper.yar` 등이 참조됩니다.

### 1. 최신 공개 웹셸 룰 자동 다운로드 & 변환
```bash
python3 convert_yara_to_rules.py --download-thor rules_yara.json
```

### 2. 보유 중인 로컬 `.yar` 파일 변환
```bash
python3 convert_yara_to_rules.py /path/to/my_webshell.yar my_custom_rules.json
```

### 3. 직접 커스텀 룰 작성 (`rules_sample.json` 구조)
JSON 파일에 아래와 같이 정규식 패턴을 직접 등록하여 검사할 수도 있습니다:

```json
[
  {
    "id": 10001,
    "name": "PHP.Webshell.EvalBase64",
    "description": "난독화된 eval(base64_decode) 탐지",
    "regex": "(?:eval|assert)\\s*\\(\\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)"
  },
  {
    "id": 10002,
    "name": "PHP.Webshell.DangerousSystemExec",
    "description": "외부 입력값 직접 실행 탐지",
    "regex": "(?:system|shell_exec|passthru|exec|popen|proc_open)\\s*\\(\\s*\\$_(?:GET|POST|REQUEST|COOKIE)"
  }
]
```

---

## 📖 라이선스 (License)

Wordfence CLI 원본 엔진은 **GPLv3** 라이선스 하에 배포됩니다. 상세 라이선스는 [LICENSE](LICENSE) 파일을 참조하세요.
