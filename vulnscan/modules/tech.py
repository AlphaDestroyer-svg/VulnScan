import re
from typing import List
from ..core import HttpClient, SecurityFinding

META_GEN_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.IGNORECASE)
SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)', re.IGNORECASE)

MAX_SCAN_BYTES = 300_000

def run(client: HttpClient, target_url: str) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    try:
        resp = client.get('')
    except Exception as e:
        findings.append(SecurityFinding('tech','info','Ошибка запроса', str(e)))
        return findings
    server = resp.headers.get('Server')
    if server:
        findings.append(SecurityFinding('tech','info','Server', server))
    xpowered = resp.headers.get('X-Powered-By')
    if xpowered:
        findings.append(SecurityFinding('tech','info','X-Powered-By', xpowered))
    body = resp.text[:MAX_SCAN_BYTES]
    mg = META_GEN_RE.search(body)
    if mg:
        findings.append(SecurityFinding('tech','info','Meta generator', mg.group(1)[:120]))
    scripts = SCRIPT_SRC_RE.findall(body)
    hosts = {}
    for s in scripts[:200]:
        if s.startswith('//'):
            s = 'https:' + s
        if s.startswith('http://') or s.startswith('https://'):
            host = s.split('/')[2]
            hosts[host] = hosts.get(host,0)+1
    for h, cnt in list(hosts.items())[:20]:
        findings.append(SecurityFinding('tech','info','Script host', f'{h} ({cnt})'))
    findings.append(SecurityFinding('tech','info','Всего внешних script', str(len(hosts))))
    return findings
