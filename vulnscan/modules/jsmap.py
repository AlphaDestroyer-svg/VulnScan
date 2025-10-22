import re
from typing import List, Set
from urllib.parse import urljoin
from ..core import HttpClient, SecurityFinding

SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)', re.IGNORECASE)
ROUTE_RE = re.compile(r'/rest/[a-zA-Z0-9_\-/]+' )
ANG_BIND_RE = re.compile(r'\{\{[^}]+\}\}')
JS_MAX_BYTES = 400_000
MAX_SCRIPTS = 40

def _fetch(client: HttpClient, path: str) -> str:
    try:
        r = client.get(path)
        ctype = r.headers.get('Content-Type','')
        if 'javascript' in ctype or path.endswith('.js') or path == '' or 'text/html' in ctype:
            return r.text[:JS_MAX_BYTES]
        return ''
    except Exception:
        return ''

def run(client: HttpClient, target_url: str) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    root_body = _fetch(client, '')
    if not root_body:
        findings.append(SecurityFinding('jsmap','info','Не удалось получить корневую страницу',''))
        return findings
    # collect script sources
    scripts = []
    for m in SCRIPT_SRC_RE.finditer(root_body):
        src = m.group(1)
        if src.startswith('http://') or src.startswith('https://'):
            scripts.append(src)
        else:
            scripts.append(urljoin(client.base_url, src.lstrip('/')))
        if len(scripts) >= MAX_SCRIPTS:
            break
    findings.append(SecurityFinding('jsmap','info','Скриптов найдено', str(len(scripts))))

    routes: Set[str] = set()
    angular_binds = 0
    for s in scripts:
        rel = s.replace(client.base_url,'')
        body = _fetch(client, rel)
        if not body:
            continue
        for r in ROUTE_RE.findall(body):
            if len(routes) < 200 and r not in routes:
                routes.add(r)
                findings.append(SecurityFinding('jsmap','info','API маршрут', r))
        # angular binding patterns
        bcount = len(ANG_BIND_RE.findall(body[:50000]))
        if bcount:
            angular_binds += bcount
    if angular_binds:
        findings.append(SecurityFinding('jsmap','info','Angular шаблонные выражения','количество ~'+str(angular_binds)))
    findings.append(SecurityFinding('jsmap','info','Итого API маршрутов', str(len(routes))))
    return findings
