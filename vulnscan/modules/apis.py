from typing import List, Optional
import json
from ..core import HttpClient, SecurityFinding

COMMON_ENDPOINTS = [
    '/rest/products',
    '/rest/products/1',
    '/rest/user/login',
    '/rest/user/whoami',
    '/rest/basket/1',
    '/rest/admin/application-version',
    '/rest/complaints',
    '/rest/reviews',
]

def run(client: HttpClient, target_url: str, extra: Optional[List[str]] = None) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    endpoints = list(COMMON_ENDPOINTS)
    if extra:
        # sanitize
        for e in extra:
            if e.startswith('/rest/') and e not in endpoints and len(endpoints) < 200:
                endpoints.append(e)
    for ep in endpoints:
        try:
            r = client.get(ep)
            ct = r.headers.get('Content-Type','')
            sev = 'info'
            body_snip = ''
            sensitive_keys_found: List[str] = []
            json_keys: List[str] = []
            if r.status_code == 200 and 'json' in ct.lower():
                sev = 'low'
                # Parse small JSON bodies safely
                text_trim = r.text[:5000]
                try:
                    data = json.loads(text_trim)
                    # collect top-level keys only to avoid deep recursion
                    if isinstance(data, dict):
                        json_keys = list(data.keys())[:40]
                        sens_patterns = ['token','jwt','auth','role','admin','password']
                        for k in json_keys:
                            lk = k.lower()
                            for sp in sens_patterns:
                                if sp in lk and sp not in sensitive_keys_found:
                                    sensitive_keys_found.append(sp)
                        if any(x in sensitive_keys_found for x in ['password','jwt']):
                            sev = 'medium'
                        elif any(x in sensitive_keys_found for x in ['token','auth','admin','role']):
                            if sev == 'low':
                                sev = 'low'  # keep low (already) but mark sensitive
                    body_snip = json.dumps({k: '...' for k in json_keys[:8]}, ensure_ascii=False)
                except Exception:
                    pass
            findings.append(SecurityFinding('apis', sev, f'API {ep} -> {r.status_code}', (ct[:60] + (' keys=' + ','.join(json_keys[:6]) if json_keys else '') + ( ' sens=' + ','.join(sensitive_keys_found) if sensitive_keys_found else ''))[:160]))
            # Separate finding if sensitive keys detected
            if sensitive_keys_found:
                findings.append(SecurityFinding('apis', 'info', f'Чувствительные поля {ep}', ','.join(sensitive_keys_found)))
        except Exception as e:
            findings.append(SecurityFinding('apis','info', f'API {ep} ошибка', str(e)))
    return findings
