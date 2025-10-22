from typing import List, Dict
from urllib.parse import urlparse, parse_qs
from ..core import HttpClient, SecurityFinding

import urllib.parse

CANDIDATE_KEYS = ['url','next','redirect','return','target','dest','destination','continue','r','go']
EXTERNAL_DEST = 'https://example.org'
SCHEMELESS_DEST = '//example.org'
ENC_DEST = urllib.parse.quote('//example.org')  # %2F%2Fexample.org


def run(client: HttpClient, target_url: str) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
    raw_q = parse_qs(parsed.query)
    # Simplify query map single values
    params: Dict[str,str] = {k:v[0] for k,v in raw_q.items() if v}

    candidates = [k for k in params.keys() if any(c in k.lower() for c in CANDIDATE_KEYS)]
    if not candidates:
        findings.append(SecurityFinding('redirect','info','Параметры не найдены','Нет типичных redirect параметров'))
        return findings

    variants = [
        ('abs', EXTERNAL_DEST, 'medium'),
        ('schemeless', SCHEMELESS_DEST, 'medium'),
        ('encoded', ENC_DEST, 'low'),
    ]

    for k in candidates:
        for vtag, payload, base_sev in variants:
            test_params = dict(params)
            test_params[k] = payload
            try:
                resp = client.request_variant(base_url, test_params)
                loc = resp.headers.get('Location')
                if resp.status_code in (301,302,303,307,308) and loc:
                    if 'example.org' in loc:
                        findings.append(SecurityFinding('redirect', base_sev, f'Open redirect вариант {vtag}', f'param={k} -> {loc}'))
                    else:
                        findings.append(SecurityFinding('redirect','info','Редирект c модификацией', f'param={k} status={resp.status_code}'))
                else:
                    if 'example.org' in resp.text:
                        findings.append(SecurityFinding('redirect','low','Отражение redirect URL', f'param={k} variant={vtag}'))
            except Exception as e:
                findings.append(SecurityFinding('redirect','info','Ошибка проверки параметра', f'{k}/{vtag}: {e}'))
    return findings
