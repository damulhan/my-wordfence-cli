# AGENTS.md

This document provides operational context, codebase architecture, and instructions for AI agents working in this repository.

---

## 1. Repository Purpose & Context

* **Project**: Wordfence CLI (Community Offline Edition)
* **License**: GPLv3
* **Origin**: Upstream `wordfence/wordfence-cli` (v5.0.6)
* **Status**: The upstream Wordfence CLI has reached EOL with new free/paid license registration disabled. This repository has been modified to operate **completely offline without license keys or external centralized API dependencies**.

---

## 2. Core Architectural Customizations

### A. License & Terms Bypass
* **`wordfence/cli/licensing.py`**: Bypasses `ping_api_key()` network calls and returns a valid `COMMUNITY-EDITION` license.
* **`wordfence/cli/context.py`**: Ensures a fallback license is always provided so `LicenseRequiredException` is never raised.
* **`wordfence/cli/configurer.py` & `wordfence/cli/terms_management.py`**: Removed interactive initial setup/configuration and terms acceptance prompts.

### B. Local Signature Injection
* **`wordfence/cli/malwarescan/definition.py`**: Added CLI flag `--signatures-file <path>` to accept custom JSON rule definitions.
* **`wordfence/cli/malwarescan/malwarescan.py`**: Passes `signatures_file` down to the signature retrieval layer and creates unique cache keys per ruleset.
* **`wordfence/api/noc1.py`**: `get_malware_signatures(signatures_file=...)` reads the local JSON file instead of sending HTTP requests to `noc1.wordfence.com`. It maps custom regexes to Wordfence's native `SignatureSet` and `Signature` objects.

### C. YARA Conversion Utility
* **`convert_yara_to_rules.py`**: Parses `.yar` rules (both regex and string literals) and converts them into the Wordfence JSON format.
* Pre-packaged rulesets:
  - `rules_sample.json`: Common PHP obfuscated exec patterns.
  - `rules_yara.json`: Converted webshell rules from Florian Roth's `thor-webshells.yar`.
  - `rules_all.json`: Combined ready-to-use ruleset (~625 rules).

---

## 3. Key Workflows & Commands

### Running Malware Scan
```bash
# Scan a directory with human-readable real-time output
python3 main.py malware-scan --signatures-file rules_all.json --output-format human /path/to/target

# Scan and export to CSV
python3 main.py malware-scan --signatures-file rules_all.json --output-path /tmp/results.csv --output-format csv /path/to/target

# Scan all files regardless of extension
python3 main.py malware-scan -a --signatures-file rules_all.json /path/to/target

# Clear cached compiled rules before a fresh scan
python3 main.py malware-scan --purge-cache --signatures-file rules_all.json /path/to/target
```

### Converting YARA Rules
```bash
# Fetch and convert Thor webshells
python3 convert_yara_to_rules.py --download-thor rules_yara.json

# Convert local .yar file
python3 convert_yara_to_rules.py /path/to/rules.yar output_rules.json
```

---

## 4. Guidelines for Future Agent Tasks

1. **Do not re-enable Wordfence NOC1 network calls**: Any changes to `noc1.py` or `licensing.py` must maintain offline operation.
2. **Regex Compatibility**: The scanning engine utilizes `libpcre` via `wordfence/util/pcre`. When authoring or converting new rules, ensure patterns conform to PCRE syntax.
3. **Cache Invalidation**: The scan engine caches compiled signatures under `~/.cache/wordfence/`. When modifying rule files during testing, use `--purge-cache`.
4. **Git Branching**: Customizations are maintained on active working branches (e.g., `dev-offline-scanner`). Verify the active branch with `git status` before committing.

