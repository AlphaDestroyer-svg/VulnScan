from typing import List
from ..core import HttpClient, SecurityFinding
import os
import re

DEFAULT_WORDLIST = os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'small_paths.txt')
INTERESTING = {200: 'ok', 204: 'no content', 301: 'redirect', 302: 'redirect', 401: 'auth required', 403: 'forbidden'}

MAX_ENTRIES = 150  # safety guard

def run(client: HttpClient, target_url: str, wordlist: str = DEFAULT_WORDLIST) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    if not os.path.isfile(wordlist):
        findings.append(SecurityFinding('paths', 'info', 'Wordlist missing', wordlist))
        return findings
    try:
        with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            entries = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    except Exception as e:
        findings.append(SecurityFinding('paths', 'info', 'Wordlist read error', str(e)))
        return findings

    entries = entries[:MAX_ENTRIES]

    for p in entries:
        try:
            resp = client.get(p)
            if resp.status_code in INTERESTING:
                title = f"Путь {p} -> {resp.status_code}"
                raw_detail = INTERESTING[resp.status_code]
                mapping = {'forbidden':'доступ запрещён','redirect':'перенаправление','ok':'найден','no content':'нет содержимого'}
                detail = mapping.get(raw_detail, raw_detail)
                severity = 'info' if resp.status_code != 403 else 'low'
                # Light directory listing heuristic
                if resp.status_code == 200 and 'Index of /' in resp.text[:500]:
                    severity = 'low'
                    detail += ' | возможен листинг каталога'
                findings.append(SecurityFinding('paths', severity, title, detail))
        except Exception as e:
            findings.append(SecurityFinding('paths', 'info', f'Error {p}', str(e)))
    return findings
