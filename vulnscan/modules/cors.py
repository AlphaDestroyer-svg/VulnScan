from typing import List
from ..core import HttpClient, SecurityFinding

TEST_ORIGIN = 'https://example-bugbounty-origin.test'

# Simple safe CORS probe: preflight OPTIONS + GET
CHECK_HEADERS = {
    'Origin': TEST_ORIGIN,
    'Access-Control-Request-Method': 'GET'
}

def run(client: HttpClient, target_url: str) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    # Preflight (OPTIONS)
    try:
        r_opt = client.options('', headers=CHECK_HEADERS)
        acao = r_opt.headers.get('Access-Control-Allow-Origin')
        acac = r_opt.headers.get('Access-Control-Allow-Credentials')
        detail = []
        sev = 'info'
        if acao:
            detail.append(f"ACAO={acao}")
            if acao == '*':
                sev = 'low'
        else:
            detail.append('ACAO=absent')
        if acac:
            detail.append(f"ACAC={acac}")
            if acac.lower() == 'true' and acao == '*':
                sev = 'medium'
        findings.append(SecurityFinding('cors', sev, 'CORS preflight', ', '.join(detail)))
    except Exception as e:
        findings.append(SecurityFinding('cors','info','CORS preflight error', str(e)))

    # Simple GET with Origin
    try:
        r_get = client.get('', headers={'Origin': TEST_ORIGIN})
        acao = r_get.headers.get('Access-Control-Allow-Origin')
        acac = r_get.headers.get('Access-Control-Allow-Credentials')
        if acao:
            sev = 'info'
            if acao == '*':
                sev = 'low'
            if acac and acac.lower() == 'true' and acao == TEST_ORIGIN:
                sev = 'low'
            findings.append(SecurityFinding('cors', sev, 'CORS GET ответ', f"ACAO={acao}; ACAC={acac}"))
        else:
            findings.append(SecurityFinding('cors','info','CORS GET без ACAO', ''))
    except Exception as e:
        findings.append(SecurityFinding('cors','info','CORS GET error', str(e)))

    return findings
