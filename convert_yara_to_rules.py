#!/usr/bin/env python3
"""
Convert YARA webshell rules to Wordfence CLI rules.json format with condition and false-positive filtering.
"""
import sys
import os
import re
import json
import urllib.request
from typing import List, Dict, Any, Optional

# Generic words / phrases that frequently trigger false positives when matched alone
STOPWORDS = {
    'password', 'admin', 'login', 'default', 'system', 'config', 'database',
    'connect', 'server', 'update', 'delete', 'select', 'insert', 'create',
    'action', 'submit', 'button', 'status', 'hidden', 'center', 'border',
    'string', 'number', 'format', 'result', 'header', 'footer', 'author',
    'package', 'wordpress', 'plugin', 'script', 'styles', 'version',
    'diamond', 'corporation', 'powered by ', 'powered by', 'unable to connect to ',
    'unable to connect to', '@hotmail.com', 'press any key', 'press any ke',
    'font-weight: bold', 'padding-left: 8px', 'padding-right: 8px'
}

def is_stopword(s: str) -> bool:
    clean = s.strip().lower()
    if clean in STOPWORDS:
        return True
    if len(clean) < 6:
        return True
    return False

def parse_yara_rule_advanced(rule_name: str, block: str, rule_id: int) -> Optional[Dict[str, Any]]:
    desc_match = re.search(r'description\s*=\s*"([^"]+)"', block)
    description = desc_match.group(1) if desc_match else rule_name

    cond_match = re.search(r'condition:(.*)', block, re.DOTALL)
    cond_str = cond_match.group(1).strip() if cond_match else ''

    # Filter out rules that rely on negative conditions for benign WordPress/CMS headers
    # (e.g. "not $x1 in (0..1000)" or "not 1 of ($fp*)") as regex engines cannot safely invert this without AST parsing
    if 'not $x1 in' in cond_str or 'not 1 of ($fp*)' in cond_str:
        return None

    # Filter out rules that strictly require tiny files (e.g. filesize < 150) with short generic phrases
    if 'filesize < 150' in cond_str or 'filesize < 200' in cond_str:
        return None

    strings_match = re.search(r'strings:(.*?)(?:condition:|$)', block, re.DOTALL)
    if not strings_match:
        return None
    strings_block = strings_match.group(1)

    patterns = {}
    # Regex definitions: $var = /regex/ modifiers
    for var, pat in re.findall(r'(\$[a-zA-Z0-9_]*)\s*=\s*/(.*?)/(?:[a-z\s]*)', strings_block):
        if len(pat) > 3 and not pat.startswith('..'):
            patterns[var] = pat

    # Literal definitions: $var = "literal"
    for var, lit in re.findall(r'(\$[a-zA-Z0-9_]*)\s*=\s*"([^"\\]*(?:\\.[^"\\]*)*)"', strings_block):
        if lit.startswith('\\x') and len(lit) < 10:
            continue
        patterns[var] = re.escape(lit)

    if not patterns:
        return None

    meaningful_patterns = {v: p for v, p in patterns.items() if not is_stopword(p.replace('\\', ''))}

    cond_clean = ' '.join(cond_str.split())
    n_of_match = re.search(r'(\d+)\s+of\s+(?:them|\(\$[a-zA-Z0-9_\*]*\))', cond_clean)
    all_of_match = 'all of' in cond_clean

    if all_of_match:
        targets = list(meaningful_patterns.values())
        if len(targets) < 2 and len(patterns) >= 2:
            return None
        if not targets:
            return None
        # In PCRE, all of them requires all lookaheads to match anywhere in the file
        lookaheads = "".join(f"(?=.*{p})" for p in targets[:6])
        regex = f"(?s){lookaheads}.+"
    elif n_of_match:
        n = int(n_of_match.group(1))
        targets = list(meaningful_patterns.values())
        if len(targets) < n:
            return None
        if n == 1:
            # For 1 of them: require strong signatures (>=15 chars or known webshell terms)
            strong = [t for t in targets if len(t) >= 15 or any(k in t.lower() for k in ['shell', 'eval', 'exec', 'system', 'passthru', 'base64', 'assert', 'upload'])]
            if not strong:
                return None
            regex = "(?:" + "|".join(strong[:6]) + ")"
        elif n >= 2:
            lookaheads = "".join(f"(?=.*{p})" for p in targets[:n])
            regex = f"(?s){lookaheads}.+"
    else:
        # Fallback: only strong indicators
        targets = list(meaningful_patterns.values())
        strong = [t for t in targets if len(t) >= 15 or any(k in t.lower() for k in ['shell', 'eval', 'exec', 'system', 'passthru', 'base64', 'assert', 'upload'])]
        if not strong:
            return None
        regex = "(?:" + "|".join(strong[:6]) + ")"

    # Verify standard PCRE compilation
    try:
        re.compile(regex)
    except Exception:
        return None

    return {
        "id": rule_id,
        "name": f"YARA.{rule_name}",
        "description": description,
        "regex": regex,
        "common_strings": []
    }

def parse_yara_content(content: str, start_id: int = 20000) -> List[Dict[str, Any]]:
    rules = []
    current_id = start_id
    rule_blocks = re.findall(r'rule\s+([A-Za-z0-9_]+)[^{]*\{(.*?)\n\}', content, re.DOTALL)

    for rule_name, block in rule_blocks:
        rule_data = parse_yara_rule_advanced(rule_name, block, current_id)
        if rule_data:
            rules.append(rule_data)
            current_id += 1

    return rules

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 convert_yara_to_rules.py <yara_file_or_url> [output.json]")
        print("   or: python3 convert_yara_to_rules.py --download-thor [output.json]")
        sys.exit(1)

    target = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "rules_yara.json"

    if target == "--download-thor":
        url = "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/thor-webshells.yar"
        print(f"Downloading thor-webshells.yar from {url} ...")
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
    elif target.startswith("http://") or target.startswith("https://"):
        print(f"Downloading from {target} ...")
        req = urllib.request.Request(target, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
    else:
        with open(target, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

    print("Parsing and validating YARA rules with condition filtering...")
    rules = parse_yara_content(content)
    print(f"Successfully converted {len(rules)} safe rules (filtered out false-positive prone patterns).")

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(rules, f, indent=2, ensure_ascii=False)

    print(f"Saved to {output_path}")

if __name__ == "__main__":
    main()
