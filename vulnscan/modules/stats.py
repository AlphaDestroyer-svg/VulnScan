from typing import List
from ..core import HttpClient, SecurityFinding

BASE_PATHS = ['', 'robots.txt', 'sitemap.xml']


def run(client: HttpClient, target_url: str) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    counts = {}
    for p in BASE_PATHS:
        try:
            r = client.get(p)
            sc = r.status_code
            counts[sc] = counts.get(sc,0)+1
            findings.append(SecurityFinding('stats','info','Запрос', f'{p or "/"} -> {sc}'))
        except Exception as e:
            findings.append(SecurityFinding('stats','info','Ошибка', f'{p}: {e}'))
    if counts:
        summary = ', '.join(f'{k}:{v}' for k,v in sorted(counts.items()))
        findings.append(SecurityFinding('stats','info','Сводка статусов', summary))
        if any(k>=500 for k in counts.keys()):
            findings.append(SecurityFinding('stats','low','Обнаружены 5xx коды', summary))
    return findings
