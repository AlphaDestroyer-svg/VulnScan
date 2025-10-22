from typing import List, Dict, Tuple
from ..core import HttpClient, SecurityFinding
from urllib.parse import urlparse, parse_qs

TEST_SUFFIX_TRUE = "' AND 1=1--"
TEST_SUFFIX_FALSE = "' AND 1=2--"
MAX_PARAM_LEN = 80

ERROR_PATTERNS = [
    'you have an error in your sql syntax',
    'warning: mysql',
    'unclosed quotation mark after the character string',
    'pg_query():',
    'psql:',
    'syntax error at or near',
    'oracle error',
    'ora-0',
    'sqlite error',
    'mysql_fetch',
]


def run(client: HttpClient, target_url: str, params: List[str], evasion: bool = False) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    if not params:
        return findings

    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    original_query = parse_qs(parsed.query)
    base_params: Dict[str,str] = {k: v[0] for k,v in original_query.items() if v}

    try:
        baseline = client.request_variant(base_url, base_params) if base_params else client.get(parsed.path)
        base_len = len(baseline.text)
    except Exception as e:
        findings.append(SecurityFinding('sqli', 'info', 'Базовый запрос не выполнен', str(e)))
        return findings

    for p in params:
        if p not in base_params:
            # create synthetic baseline if param absent
            base_params.setdefault(p, '1')
        original_value = base_params[p]
        short_val = original_value[:MAX_PARAM_LEN]
        variant_pairs: List[Tuple[str,str,str]] = [
            (TEST_SUFFIX_TRUE, TEST_SUFFIX_FALSE, 'base')
        ]
        if evasion:
            variant_pairs.extend([
                ("' AnD 1=1--", "' AnD 1=2--", 'mixed_case'),
                ("'/**/AND/**/1=1--", "'/**/AND/**/1=2--", 'inline_comment'),
                ("%27 AND 1=1--", "%27 AND 1=2--", 'encoded_quote'),
                ("' AND 1=1#", "' AND 1=2#", 'hash_comment')
            ])
        boolean_flagged = False
        error_flagged = False
        for true_suffix, false_suffix, tag in variant_pairs:
            true_params = dict(base_params)
            false_params = dict(base_params)
            true_params[p] = short_val + true_suffix
            false_params[p] = short_val + false_suffix
            try:
                resp_true = client.request_variant(base_url, true_params)
                resp_false = client.request_variant(base_url, false_params)
            except Exception as e:
                findings.append(SecurityFinding('sqli', 'info', f'Ошибка параметра {p}', str(e)))
                break
            len_true = len(resp_true.text)
            len_false = len(resp_false.text)
            body_true_lower = resp_true.text.lower()
            if not error_flagged:
                for pat in ERROR_PATTERNS:
                    if pat in body_true_lower:
                        findings.append(SecurityFinding('sqli', 'medium', f'Параметр {p} возможна error-based SQLi', f'{pat[:70]} (вариант={tag})'))
                        error_flagged = True
                        break
            if not boolean_flagged and abs(len_true - len_false) > 80 and abs(len_true - base_len) > 40:
                findings.append(SecurityFinding('sqli', 'medium', f'Параметр {p} возможна boolean SQLi', f'База={base_len} ИСТИНА={len_true} ЛОЖЬ={len_false} вариант={tag}'))
                boolean_flagged = True
            # stop early if both heuristics already flagged for this param
            if boolean_flagged and error_flagged:
                break
    return findings
