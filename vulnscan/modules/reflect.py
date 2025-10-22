import re
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs
from ..core import HttpClient, SecurityFinding

TOKEN_PREFIX = 'REFLECT_TEST_'

SAFE_VALUE = TOKEN_PREFIX + '12345'
ALT_VALUE = TOKEN_PREFIX + 'A_B'
MAX_BODY = 300000


def run(client: HttpClient, target_url: str, extra_params: Optional[List[str]] = None) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
    qs = parse_qs(parsed.query)
    params: Dict[str,str] = {k:v[0] for k,v in qs.items() if v}
    if extra_params:
        for p in extra_params:
            params.setdefault(p, '1')
    if not params:
        findings.append(SecurityFinding('reflect','info','Нет параметров','Нечего тестировать'))
        return findings
    tested = 0
    for k in list(params.keys())[:20]:  # safety cap
        test_params = dict(params)
        test_params[k] = SAFE_VALUE
        try:
            resp = client.request_variant(base_url, test_params)
            body = resp.text[:MAX_BODY]
            if SAFE_VALUE in body:
                # try variant alt value to confirm controllable reflection
                test_params[k] = ALT_VALUE
                resp2 = client.request_variant(base_url, test_params)
                body2 = resp2.text[:MAX_BODY]
                if ALT_VALUE in body2:
                    findings.append(SecurityFinding('reflect','low','Отражение параметра', f'{k} отражён в HTML'))
                else:
                    findings.append(SecurityFinding('reflect','info','Нестабильное отражение', k))
            tested += 1
        except Exception as e:
            findings.append(SecurityFinding('reflect','info','Ошибка проверки параметра', f'{k}: {e}'))
    if not any(f.module=='reflect' and f.title.startswith('Отражение') for f in findings):
        findings.append(SecurityFinding('reflect','info','Отражений не найдено', f'параметров проверено={tested}'))
    return findings
