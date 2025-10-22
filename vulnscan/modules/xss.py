from typing import List, Dict
from ..core import HttpClient, SecurityFinding
from urllib.parse import urlparse, parse_qs
import time, random, html

SAFE_PREFIX = "XSS_TEST_"

def _context_classify(snippet: str) -> str:
    low = snippet.lower()
    if 'script' in low:
        return 'script-block'
    if 'onerror' in low or 'onload' in low or 'onclick' in low:
        return 'event-handler'
    if '="' in snippet or "='" in snippet:
        return 'attribute'
    return 'text'

def run(client: HttpClient, target_url: str, params: List[str], lang: str = 'ru', evasion: bool = False) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    if not params:
        return findings

    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    original_query = parse_qs(parsed.query)

    try:
        baseline = client.request_variant(base_url, {k: v[0] for k,v in original_query.items()}) if original_query else client.get(parsed.path)
        baseline_len = len(baseline.text)
    except Exception as e:
        findings.append(SecurityFinding('xss', 'info', 'Базовый запрос не выполнен', str(e)))
        return findings

    for p in params:
        base_params: Dict[str,str] = {k: v[0] for k,v in original_query.items()}
        marker = SAFE_PREFIX + str(int(time.time())) + str(random.randint(100,999))
        attempts = [
            (marker, 'ref'),
            (marker + '"', 'quote'),
            (marker + '" benign="1', 'attr_injection')
        ]
        if evasion:
            # Дополнительные безопасные варианты для выявления фильтров/контекстов.
            attempts.extend([
                (marker + '%22', 'pct_quote'),
                (marker + '&#34;', 'html_ent_q'),
                (marker + '`', 'backtick'),
                (marker + '\\', 'backslash'),
            ])
        results = {}
        for payload, tag in attempts:
            test_params = dict(base_params)
            test_params[p] = payload
            try:
                resp = client.request_variant(base_url, test_params)
            except Exception as e:
                findings.append(SecurityFinding('xss', 'info', f'Ошибка параметра {p}', str(e)))
                break
            body = resp.text
            reflected = payload in body
            encoded_quote = '&quot;' in body or '&#34;' in body
            idx = body.find(marker)
            snippet = ''
            if idx != -1:
                snippet = html.escape(body[max(0, idx-50): idx+len(marker)+50])
            results[tag] = {
                'reflected': reflected,
                'encoded_quote': encoded_quote,
                'snippet': snippet,
                'len': len(body)
            }
            time.sleep(0.15)  # мягкая пауза

        # Анализ
        if not results.get('ref', {}).get('reflected'):
            diff = abs(results.get('ref', {}).get('len', baseline_len) - baseline_len)
            if diff > 80:
                findings.append(SecurityFinding('xss', 'info', f'Параметр {p}: значимое изменение длины', f'Δ={diff} (нет прямого отражения)'))
            continue

        # Есть отражение маркера
        snippet = results['ref']['snippet']
        context_type = _context_classify(snippet)
        encoded = results['ref']['encoded_quote']

        severity = 'low'
        detail_bits = []
        detail_bits.append(f'контекст={context_type}')
        if encoded:
            detail_bits.append('кавычки экранированы')
        else:
            detail_bits.append('кавычки не экранированы')

        # Проверка попытки закрытия атрибута
        if results.get('quote', {}).get('reflected') and not encoded:
            severity = 'medium'
            detail_bits.append('попытка добавления кавычки отражена как сырая')
        if results.get('attr_injection', {}).get('reflected') and not encoded:
            severity = 'medium'
            if 'benign="1' in snippet:
                detail_bits.append('возможен разрыв атрибута (benign="1 найден)')

        title = f'Параметр {p} отражён'
        if severity == 'medium' and context_type == 'attribute' and not encoded:
            title = f'Параметр {p} потенциально эксплуатируем (атрибут)'

        # Отметим, если какая-то из evasion попыток отражена в неизменном виде при отсутствии quote/attr успехов
        if evasion:
            ev_ok = [k for k,v in results.items() if k not in ('ref','quote','attr_injection') and v.get('reflected')]
            if ev_ok:
                detail_bits.append(f'evasion={";".join(ev_ok)}')
        findings.append(SecurityFinding('xss', severity, title, ' | '.join(detail_bits) + f' | фрагмент=...{snippet}...'))
    return findings
