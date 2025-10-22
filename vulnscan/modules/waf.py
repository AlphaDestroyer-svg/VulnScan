from typing import List
from urllib.parse import urlparse
from ..core import HttpClient, SecurityFinding

WAF_HEADER_HINTS = [
    'x-sucuri-id', 'x-sucuri-cache', 'x-waf', 'x-mod-security', 'x-imperva-id',
    'cf-ray', 'x-cdn', 'x-akamai', 'x-akamai-request-id', 'x-datadome', 'x-distil-cs'
]

BLOCK_STATUSES = {403, 406, 429, 501, 502, 503}

def run(client: HttpClient, target_url: str) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    try:
        parsed = urlparse(target_url)
        path = parsed.path or '/'
        baseline = client.get(path)
        base_len = len(baseline.text)
    except Exception as e:
        findings.append(SecurityFinding('waf', 'info', 'Базовый запрос не выполнен', str(e)))
        return findings

    # Header fingerprint
    hdr_lower = {k.lower(): v for k,v in baseline.headers.items()}
    waf_header_hits = []
    for h in WAF_HEADER_HINTS:
        if h in hdr_lower:
            waf_header_hits.append(h)
    if waf_header_hits:
        findings.append(SecurityFinding('waf', 'info', 'Подозрение на WAF по заголовкам', ', '.join(waf_header_hits)))

    # Simple differential probes (harmless patterns)
    probes = [
        ('waf_test', '1<test>'),
        ('waf_test', '1%3Ctest%3E'),
        ('waf_test', 'OR1=1'),  # benign token
    ]
    blocked = 0
    for k, v in probes:
        try:
            resp = client.request_variant(f"{parsed.scheme}://{parsed.netloc}{path}", {k: v})
        except Exception:
            continue
        rlen = len(resp.text)
        if resp.status_code in BLOCK_STATUSES and resp.status_code != baseline.status_code:
            blocked += 1
        elif resp.status_code == baseline.status_code and abs(rlen - base_len) > 250 and rlen < base_len * 0.60:
            # Large shrink might indicate generic block page
            blocked += 1
    if blocked:
        sev = 'low' if blocked >= 2 else 'info'
        findings.append(SecurityFinding('waf', sev, 'Возможна активная фильтрация (WAF)', f'Количество блок-паттернов={blocked}'))
    return findings
