import re
from typing import List
from ..core import HttpClient, SecurityFinding

HTTP_RES_RE = re.compile(r'http://[^"\'\s>]+', re.IGNORECASE)
MAX_FINDINGS = 40

def run(client: HttpClient, target_url: str) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    if not client.base_url.startswith('https://'):
        findings.append(SecurityFinding('mixed','info','Не HTTPS схема','Проверка смешанного контента пропущена'))
        return findings
    try:
        r = client.get('')
    except Exception as e:
        findings.append(SecurityFinding('mixed','info','Ошибка загрузки корня', str(e)))
        return findings
    body = r.text[:300000]
    http_refs = []
    for m in HTTP_RES_RE.finditer(body):
        val = m.group(0)
        if val not in http_refs:
            http_refs.append(val)
        if len(http_refs) >= MAX_FINDINGS:
            break
    if http_refs:
        findings.append(SecurityFinding('mixed','low','HTTP ресурсы на HTTPS', f'количество={len(http_refs)}'))
        for ref in http_refs[:10]:
            findings.append(SecurityFinding('mixed','info','HTTP ресурс', ref[:160]))
    else:
        findings.append(SecurityFinding('mixed','info','Смешанный контент не обнаружен',''))
    return findings
