from typing import List, Dict
from urllib.parse import urlparse, parse_qs
from ..core import HttpClient, SecurityFinding

CANDIDATES = ['url','uri','endpoint','feed','source','dest','redirect','callback','webhook']


def run(client: HttpClient, target_url: str) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    parsed = urlparse(target_url)
    q = parse_qs(parsed.query)
    if not q:
        findings.append(SecurityFinding('ssrf','info','Параметры отсутствуют','Нет query для анализа'))
        return findings
    flat: Dict[str,str] = {k:v[0] for k,v in q.items() if v}
    for k,v in flat.items():
        lk = k.lower()
        if any(c in lk for c in CANDIDATES):
            sev = 'info'
            if v.startswith('http://') or v.startswith('https://'):
                sev = 'low'
            findings.append(SecurityFinding('ssrf', sev, 'SSRF кандидат', f'{k}={v[:160]}'))
    if not any(f.module=='ssrf' for f in findings):
        findings.append(SecurityFinding('ssrf','info','SSRF кандидаты не найдены',''))
    return findings
