from typing import List, Tuple
from ..core import HttpClient, SecurityFinding

# Limited safe path checks (HEAD first, optional small GET)
SENSITIVE_PATHS: List[Tuple[str,str]] = [
    ('.env','env'),
    ('.git/config','git'),
    ('db.sql','db'),
    ('backup.zip','backup'),
    ('backup.sql','db'),
    ('config.php','config'),
    ('composer.json','config'),
    ('package.json','config'),
    ('.DS_Store','misc'),
    ('.well-known/security.txt','policy'),
    ('.well-known/assetlinks.json','misc'),
    ('crossdomain.xml','legacy'),
]

MAX_BODY = 1000

HIGH_IMPACT = {'env','git','db'}
LOW_IMPACT = {'misc','legacy','policy'}


def run(client: HttpClient, target_url: str) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    for p, tag in SENSITIVE_PATHS:
        try:
            r = client.head(p)
            status = r.status_code
            if status == 405:  # Method not allowed, try GET
                r = client.get(p)
                status = r.status_code
            if status == 200:
                # dynamic severity mapping
                if tag in HIGH_IMPACT:
                    sev = 'medium'
                elif tag in LOW_IMPACT:
                    sev = 'info'
                elif tag == 'backup':
                    sev = 'low'
                elif tag == 'config':
                    sev = 'low'
                else:
                    sev = 'low'
                size = r.headers.get('Content-Length')
                detail_parts = [f'status=200', f'path=/{p}']
                if size:
                    detail_parts.append(f'len={size}')
                else:
                    # fetch small snippet if not already
                    if not r.text:
                        try:
                            g = client.get(p)
                            snippet = g.text[:MAX_BODY]
                        except Exception:
                            snippet = ''
                    else:
                        snippet = r.text[:MAX_BODY]
                    if snippet:
                        detail_parts.append('snippet=' + snippet.replace('\n',' ')[:120])
                findings.append(SecurityFinding('exposures', sev, f'Доступен чувствительный файл', ' '.join(detail_parts)))
            elif status in (301,302,303,307,308):
                # Redirect might indicate rewriting; note but info only
                findings.append(SecurityFinding('exposures','info','Перенаправление файла', f'/{p} -> {status}'))
        except Exception as e:
            findings.append(SecurityFinding('exposures','info','Ошибка запроса файла', f'/{p}: {e}'))
    if not findings:
        findings.append(SecurityFinding('exposures','info','Нет результатов',''))
    return findings
