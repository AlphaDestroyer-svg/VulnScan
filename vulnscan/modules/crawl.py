import re
from collections import deque
from typing import List, Set, Tuple, Dict
from urllib.parse import urlparse, urljoin, parse_qs
from ..core import HttpClient, SecurityFinding

MAX_PAGE_SIZE = 400_000  # bytes safety cap
HTML_TYPES = ('text/html', 'application/xhtml')

HREF_RE = re.compile(r'href=["\']([^"\'#]+)')
FORM_RE = re.compile(r'<form[^>]+>', re.IGNORECASE)
INPUT_RE = re.compile(r'<input[^>]+name=["\']([^"\']+)', re.IGNORECASE)

def _same_host(base_netloc: str, url: str) -> bool:
    try:
        p = urlparse(url)
        if not p.netloc:
            return True
        return p.netloc == base_netloc
    except Exception:
        return False

def _norm_path(u: str) -> str:
    p = urlparse(u)
    path = p.path or '/'
    if not path.startswith('/'):
        path = '/' + path
    return path

def run(client: HttpClient, target_url: str, depth: int = 1, max_pages: int = 20) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    parsed_root = urlparse(target_url)
    root = f"{parsed_root.scheme}://{parsed_root.netloc}"

    queue: deque[Tuple[str,int]] = deque()
    start_path = parsed_root.path or '/'
    queue.append((start_path, 0))
    seen_paths: Set[str] = set()
    discovered_params: Set[str] = set()

    pages_processed = 0
    while queue and pages_processed < max_pages:
        path, d = queue.popleft()
        if path in seen_paths:
            continue
        seen_paths.add(path)
        try:
            resp = client.get(path)
        except Exception as e:
            findings.append(SecurityFinding('crawl','info','Ошибка запроса', f'{path}: {e}'))
            continue
        pages_processed += 1
        ctype = resp.headers.get('Content-Type','')
        if any(ht in ctype for ht in HTML_TYPES) and resp.text:
            body = resp.text[:MAX_PAGE_SIZE]
            # links
            for m in HREF_RE.finditer(body):
                href = m.group(1).strip()
                if href.startswith('mailto:') or href.startswith('javascript:'):
                    continue
                full = urljoin(root + '/', href)
                if not _same_host(parsed_root.netloc, full):
                    continue
                np = _norm_path(full)
                if np not in seen_paths and d < depth:
                    queue.append((np, d+1))
                # query params
                q = urlparse(full).query
                if q:
                    qd = parse_qs(q)
                    for k in qd.keys():
                        if len(discovered_params) < 200:  # safety limit
                            if k not in discovered_params:
                                discovered_params.add(k)
                                findings.append(SecurityFinding('crawl','info', f'PARAM:{k}', f'из ссылки {np}'))
            # forms (GET only heuristic)
            for fm in FORM_RE.finditer(body):
                form_tag = fm.group(0)
                method_m = re.search(r'method=["\']([^"\']+)', form_tag, re.IGNORECASE)
                method = (method_m.group(1).lower() if method_m else 'get')
                if method != 'get':
                    continue
                # gather input names in rest of doc from this index window
                window = body[fm.start(): fm.start()+2000]
                for im in INPUT_RE.finditer(window):
                    name = im.group(1)
                    if name and name not in discovered_params and len(discovered_params) < 200:
                        discovered_params.add(name)
                        findings.append(SecurityFinding('crawl','info', f'PARAM:{name}', 'из GET формы'))

        findings.append(SecurityFinding('crawl','info','Страница просмотрена', f'{path} статус={resp.status_code}'))

    findings.append(SecurityFinding('crawl','info','Итого страниц', str(pages_processed)))
    findings.append(SecurityFinding('crawl','info','Итого параметров', str(len(discovered_params))))
    return findings