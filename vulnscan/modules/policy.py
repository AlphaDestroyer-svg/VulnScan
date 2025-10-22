from typing import List
from ..core import HttpClient, SecurityFinding

SECURITY_TXT = '.well-known/security.txt'
MAX_BODY = 8000
REQUIRED_FIELDS = ['contact']
OPTIONAL_FIELDS = ['encryption','acknowledgments','preferred-languages','policy','hiring']


def run(client: HttpClient, target_url: str) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    try:
        r = client.get(SECURITY_TXT)
    except Exception as e:
        findings.append(SecurityFinding('policy','info','security.txt ошибка', str(e)))
        return findings
    if r.status_code != 200:
        findings.append(SecurityFinding('policy','info','security.txt отсутствует', f'status={r.status_code}'))
        return findings
    body = r.text[:MAX_BODY]
    lines = [ln.strip() for ln in body.splitlines() if ln.strip() and not ln.strip().startswith('#')]
    present = {}
    for ln in lines:
        if ':' in ln:
            k,v = ln.split(':',1)
            k_low = k.strip().lower()
            present.setdefault(k_low, []).append(v.strip())
    for rf in REQUIRED_FIELDS:
        if rf not in present:
            findings.append(SecurityFinding('policy','low','Отсутствует обязательное поле', rf))
    for opt in OPTIONAL_FIELDS:
        if opt in present:
            findings.append(SecurityFinding('policy','info', f'Поле {opt}', ', '.join(present[opt])[:160]))
    findings.append(SecurityFinding('policy','info','security.txt найден', f'полей={len(present)}'))
    return findings
