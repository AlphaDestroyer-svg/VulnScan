import re
from typing import List
from ..core import HttpClient, SecurityFinding

FORM_RE = re.compile(r'<form[^>]*>', re.IGNORECASE)
INPUT_RE = re.compile(r'<input[^>]+>', re.IGNORECASE)
NAME_RE = re.compile(r'name=["\']([^"\']+)', re.IGNORECASE)
TYPE_RE = re.compile(r'type=["\']([^"\']+)', re.IGNORECASE)
ACTION_RE = re.compile(r'action=["\']([^"\']+)', re.IGNORECASE)
METHOD_RE = re.compile(r'method=["\']([^"\']+)', re.IGNORECASE)

MAX_SCAN_BYTES = 250_000

def run(client: HttpClient, target_url: str) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    try:
        resp = client.get('')
    except Exception as e:
        findings.append(SecurityFinding('forms','info','Ошибка запроса', str(e)))
        return findings
    body = resp.text[:MAX_SCAN_BYTES]
    forms = list(FORM_RE.finditer(body))
    findings.append(SecurityFinding('forms','info','Всего форм', str(len(forms))))
    for fm in forms[:50]:  # limit 50
        tag = fm.group(0)
        m_m = METHOD_RE.search(tag)
        method = m_m.group(1).lower() if m_m else 'get'
        a_m = ACTION_RE.search(tag)
        action = a_m.group(1) if a_m else ''
        # look ahead small window for inputs
        window = body[fm.end(): fm.end()+1500]
        inputs = INPUT_RE.findall(window)
        names = []
        pw = False
        for it in inputs[:40]:
            name_m = NAME_RE.search(it)
            type_m = TYPE_RE.search(it)
            if name_m:
                nm = name_m.group(1)
                if nm not in names:
                    names.append(nm)
            if type_m and type_m.group(1).lower() == 'password':
                pw = True
        title = f'Форма {method.upper()} {action[:60]}'
        detail = f'поля={",".join(names[:10])}'
        sev = 'info'
        if pw:
            sev = 'low'
            detail += ' | содержит password'
        findings.append(SecurityFinding('forms', sev, title, detail))
    return findings
