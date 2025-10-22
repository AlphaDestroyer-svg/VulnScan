import re
from typing import List
from ..core import HttpClient, SecurityFinding

ROBOTS_PATH = 'robots.txt'
SITEMAP_PATH = 'sitemap.xml'
MAX_BODY = 120000
MAX_URLS = 60
LOC_RE = re.compile(r'<loc>([^<]+)</loc>', re.IGNORECASE)


def run(client: HttpClient, target_url: str) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    # robots
    try:
        r = client.get(ROBOTS_PATH)
        if r.status_code == 200 and 'text' in r.headers.get('Content-Type',''):
            content = r.text[:MAX_BODY]
            lines = content.splitlines()
            disallows = [ln.split(':',1)[1].strip() for ln in lines if ln.lower().startswith('disallow:')]
            for d in disallows[:40]:
                if d:
                    findings.append(SecurityFinding('discovery','info','ROBOTS disallow', d))
            findings.append(SecurityFinding('discovery','info','ROBOTS найден', f'Всего disallow={len(disallows)}'))
        else:
            findings.append(SecurityFinding('discovery','info','ROBOTS отсутствует',''))
    except Exception as e:
        findings.append(SecurityFinding('discovery','info','ROBOTS ошибка', str(e)))
    # sitemap
    try:
        s = client.get(SITEMAP_PATH)
        if s.status_code == 200 and 'xml' in s.headers.get('Content-Type',''):
            body = s.text[:MAX_BODY]
            urls = LOC_RE.findall(body)
            if urls:
                findings.append(SecurityFinding('discovery','info','SITEMAP найден', f'url_count={len(urls)}'))
                for u in urls[:MAX_URLS]:
                    findings.append(SecurityFinding('discovery','info','SITEMAP url', u[:200]))
            else:
                findings.append(SecurityFinding('discovery','info','SITEMAP пустой',''))
        else:
            findings.append(SecurityFinding('discovery','info','SITEMAP отсутствует',''))
    except Exception as e:
        findings.append(SecurityFinding('discovery','info','SITEMAP ошибка', str(e)))
    if not findings:
        findings.append(SecurityFinding('discovery','info','Нет данных',''))
    return findings
