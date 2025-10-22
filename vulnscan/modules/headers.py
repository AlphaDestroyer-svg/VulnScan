from typing import List
from ..core import HttpClient, SecurityFinding

SEC_HEADERS = [
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Referrer-Policy',
    'Strict-Transport-Security'
]

COOKIE_FLAGS = ['httponly', 'secure']

def run(client: HttpClient, target_url: str) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    try:
        resp = client.get('')
    except Exception as e:
        findings.append(SecurityFinding('headers', 'info', 'Fetch failed', f'Root request failed: {e}'))
        return findings

    # Missing headers
    header_keys_lower = {k.lower(): v for k,v in resp.headers.items()}
    for h in SEC_HEADERS:
        if h.lower() not in header_keys_lower:
            sev = 'info'
            if h in ('Content-Security-Policy','Strict-Transport-Security','Referrer-Policy'):
                sev = 'low'
            findings.append(SecurityFinding('headers', sev, f'Отсутствует {h}', f'Заголовок {h} не обнаружен'))

    # Weak / extended CSP heuristics
    csp = header_keys_lower.get('content-security-policy')
    if csp:
        lc_csp = csp.lower()
        if 'unsafe-inline' in lc_csp or 'unsafe-eval' in lc_csp:
            findings.append(SecurityFinding('headers','low','Слабая CSP','Используется unsafe-inline/unsafe-eval'))
        if 'script-src *' in lc_csp or 'script-src  *' in lc_csp:
            findings.append(SecurityFinding('headers','low','Широкий script-src','script-src содержит *'))
        if 'default-src *' in lc_csp:
            findings.append(SecurityFinding('headers','info','Широкий default-src','default-src=*'))
        if 'object-src' not in lc_csp:
            findings.append(SecurityFinding('headers','info','Нет object-src','object-src отсутствует'))
        # script-src * without nonce/hash
        if 'script-src *' in lc_csp and ('nonce-' not in lc_csp and 'sha256-' not in lc_csp and 'sha384-' not in lc_csp and 'sha512-' not in lc_csp):
            findings.append(SecurityFinding('headers','low','script-src * без nonce/hash','Рекомендуется nonce или хеши'))
    # Missing X-Content-Type-Options is already covered above, but if present ensure value nosniff
    xcto = header_keys_lower.get('x-content-type-options')
    if xcto and xcto.lower() != 'nosniff':
        findings.append(SecurityFinding('headers','low','Некорректный X-Content-Type-Options', xcto))

    # Referrer-Policy weak values
    refpol = header_keys_lower.get('referrer-policy')
    if refpol:
        weak_vals = {'no-referrer-when-downgrade','unsafe-url','origin-when-cross-origin'}
        if refpol.lower() in weak_vals:
            findings.append(SecurityFinding('headers','info','Слабый Referrer-Policy', refpol))

    # HSTS quality
    hsts = header_keys_lower.get('strict-transport-security')
    if hsts:
        import re
        m = re.search(r'max-age=(\d+)', hsts, re.IGNORECASE)
        if m:
            try:
                ma = int(m.group(1))
                if ma < 10886400:  # 18 weeks (common recommended minimum 15552000 ~ 180 days; we choose 18w)
                    findings.append(SecurityFinding('headers','info','Короткий HSTS max-age', f'max-age={ma}'))
            except ValueError:
                findings.append(SecurityFinding('headers','info','Некорректный HSTS max-age', hsts[:120]))
        if 'includesubdomains' not in hsts.lower():
            findings.append(SecurityFinding('headers','info','HSTS без includeSubDomains', hsts[:120]))

    # Cookie flags check + SameSite analysis + grouping
    set_cookies = resp.headers.get('Set-Cookie')
    if set_cookies:
        parts = set_cookies.split('\n') if '\n' in set_cookies else [set_cookies]
        no_secure = 0
        no_httponly = 0
        no_samesite = 0
        for c in parts:
            low = c.lower()
            for flag in COOKIE_FLAGS:
                if flag not in low:
                    findings.append(SecurityFinding('headers', 'low', f'Cookie без флага {flag.title()}', c.strip()[:120]))
                    if flag == 'secure':
                        no_secure += 1
                    if flag == 'httponly':
                        no_httponly += 1
            # SameSite
            if 'samesite=' not in low:
                findings.append(SecurityFinding('headers','info','Cookie без SameSite', c.strip()[:120]))
                no_samesite += 1
            else:
                # parse value
                import re
                sm = re.search(r'samesite=([^;]+)', low)
                if sm:
                    ss_val = sm.group(1).strip()
                    if ss_val == 'none' and 'secure' not in low:
                        findings.append(SecurityFinding('headers','medium','SameSite=None без Secure', c.strip()[:120]))
        # summary
        if no_secure or no_httponly or no_samesite:
            findings.append(SecurityFinding('headers','info','Cookie сводка', f'noSecure={no_secure} noHttpOnly={no_httponly} noSameSite={no_samesite}'))
    else:
        findings.append(SecurityFinding('headers', 'info', 'Set-Cookie отсутствует', 'Корневой ответ не установил cookie'))

    # Server disclosure
    if 'Server' in resp.headers:
        findings.append(SecurityFinding('headers', 'info', 'Заголовок Server присутствует', resp.headers['Server']))

    return findings
