#!/usr/bin/env python3
"""
Convert YARA webshell rules to Wordfence CLI rules.json format.
"""
import sys
import os
import re
import json
import urllib.request
from typing import List, Dict, Any

def parse_yara_content(content: str, start_id: int = 20000) -> List[Dict[str, Any]]:
    rules = []
    current_id = start_id

    # Match each rule block: rule <Name> { ... }
    # Using regex to find rules
    rule_blocks = re.findall(r'rule\s+([A-Za-z0-9_]+)[^{]*\{(.*?)\n\}', content, re.DOTALL)
    
    for rule_name, block in rule_blocks:
        # Extract description
        desc_match = re.search(r'description\s*=\s*"([^"]+)"', block)
        description = desc_match.group(1) if desc_match else rule_name

        # Extract strings section
        strings_match = re.search(r'strings:(.*?)(?:condition:|$)', block, re.DOTALL)
        if not strings_match:
            continue
        strings_block = strings_match.group(1)

        patterns = []
        # Find regex strings: $var = /regex/ modifiers
        regex_matches = re.findall(r'\$[a-zA-Z0-9_]*\s*=\s*/(.*?)/(?:[a-z\s]*)', strings_block)
        for r in regex_matches:
            if len(r) > 3 and not r.startswith('..'):
                patterns.append(r)

        # Find literal strings: $var = "literal" modifiers
        literal_matches = re.findall(r'\$[a-zA-Z0-9_]*\s*=\s*"([^"\\]*(?:\\.[^"\\]*)*)"(?:\s+([a-z\s]+))?', strings_block)
        for lit, modifiers in literal_matches:
            # Skip very short generic strings (< 5 chars)
            if len(lit) < 5 or lit.lower() in ('<?php', '?>', '<html>', 'body', 'post', 'get', 'script'):
                continue
            escaped = re.escape(lit)
            patterns.append(escaped)

        if not patterns:
            continue

        # Combine up to 8 patterns with OR for high coverage and speed
        # Filter duplicates
        unique_patterns = list(dict.fromkeys(patterns))[:8]
        if len(unique_patterns) == 1:
            combined_regex = unique_patterns[0]
        else:
            combined_regex = "(?:" + "|".join(unique_patterns) + ")"

        # Sanity check: test if regex can compile with python re
        try:
            re.compile(combined_regex)
        except re.error:
            # If complex YARA regex fails standard regex compilation, skip it
            continue

        rules.append({
            "id": current_id,
            "name": f"YARA.{rule_name}",
            "description": description,
            "regex": combined_regex,
            "common_strings": []
        })
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

    print("Parsing YARA rules...")
    rules = parse_yara_content(content)
    print(f"Successfully converted {len(rules)} rules.")

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(rules, f, indent=2, ensure_ascii=False)

    print(f"Saved to {output_path}")

if __name__ == "__main__":
    main()

