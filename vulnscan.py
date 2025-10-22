#!/usr/bin/env python
import argparse, json, sys, os
from urllib.parse import urlparse
from colorama import Fore, Style, init as color_init
from vulnscan.core import HttpClient
from vulnscan.modules import headers_run, paths_run, xss_run, sqli_run, crawl_run, forms_run, tech_run, jsmap_run, apis_run, cors_run, exposures_run, redirect_run, mixed_run, discovery_run, ssrf_run, policy_run, reflect_run, stats_run, waf_run
from vulnscan.locale import t, map_severity

MODULE_MAP = {
    'headers': headers_run,
    'paths': paths_run,
    'xss': xss_run,
    'sqli': sqli_run,
    'crawl': crawl_run,
    'forms': forms_run,
    'tech': tech_run,
    'jsmap': jsmap_run,
    'apis': apis_run,
    'cors': cors_run,
    'exposures': exposures_run,
    'redirect': redirect_run,
    'mixed': mixed_run,
    'discovery': discovery_run,
    'ssrf': ssrf_run,
    'policy': policy_run,
    'reflect': reflect_run,
    'stats': stats_run,
    'waf': waf_run,
}

SAFE_DEFAULT_MODULES = ['headers','paths']

BANNER = """VulnScan 0.1 (Restricted Ethical Scanner)\nUse only with explicit authorization & inside allowed scope.\n"""

def color_for(sev: str):
    s = sev.lower()
    if s == 'medium': return Fore.YELLOW
    if s == 'high' or s == 'critical': return Fore.RED
    if s == 'low': return Fore.CYAN
    return Fore.WHITE

def parse_args():
    ap = argparse.ArgumentParser(description='Ограниченный безопасный помощник-сканер уязвимостей')
    ap.add_argument('--url', required=True, help='Target URL (may include query params for xss/sqli modules)')
    ap.add_argument('--modules', default=','.join(SAFE_DEFAULT_MODULES), help='Comma list: headers,paths,xss,sqli')
    ap.add_argument('--params', help='Comma list of parameter names for xss/sqli modules')
    ap.add_argument('--max-rps', type=float, default=6.0, help='Max requests per second (<=10 as per policy)')
    ap.add_argument('--json', help='Output findings to JSON file')
    ap.add_argument('--timeout', type=int, default=12, help='Request timeout seconds')
    ap.add_argument('--lang', default='ru', help='Interface language ru|en (default ru)')
    ap.add_argument('--crawl-depth', type=int, default=1, help='Depth for crawl module (default 1)')
    ap.add_argument('--max-pages', type=int, default=20, help='Max pages for crawl module (default 20)')
    ap.add_argument('--auto-xss-sqli', action='store_true', help='After crawl: auto run xss & sqli on discovered params')
    ap.add_argument('--auto-params-limit', type=int, default=12, help='Limit of auto discovered params used for XSS/SQLi')
    ap.add_argument('--all', action='store_true', help='Run all modules in recommended order')
    ap.add_argument('--max-requests', type=int, help='Global max HTTP requests safety limit')
    ap.add_argument('--md', help='Write Markdown report to file')
    ap.add_argument('--apis-auto', action='store_true', help='After jsmap feed found /rest/ routes to apis module')
    ap.add_argument('--min-severity', help='Filter output (info|low|medium|high|critical)')
    ap.add_argument('--jsonl', help='Write findings as JSON Lines file')
    ap.add_argument('--csv', help='Write findings to CSV file')
    ap.add_argument('--profile', help='Predefined module set: light|full|hardening|api')
    ap.add_argument('--augment-paths', action='store_true', help='After discovery augment paths via quick HEAD of disallow/sitemap URLs')
    ap.add_argument('--no-adaptive-rps', action='store_true', help='Disable adaptive RPS backoff')
    ap.add_argument('--evasion', action='store_true', help='Enable safe XSS/SQLi evasion variants (more payload diversity)')
    return ap.parse_args()

def main():
    args = parse_args()
    color_init(autoreset=True)
    print(BANNER)

    lang = args.lang.lower()

    try:
        parsed = urlparse(args.url)
        if not parsed.scheme.startswith('http'):
            print(t('target_invalid', lang))
            return 2
    except Exception:
        print(t('target_invalid', lang))
        return 2

    base_root = f"{parsed.scheme}://{parsed.netloc}/"

    modules = [m.strip().lower() for m in args.modules.split(',') if m.strip()]
    for m in modules:
        if m not in MODULE_MAP:
            print(f"{t('unknown_module', lang)}: {m}")
            return 2

    if args.max_rps > 10:
        print('Max RPS capped at 10 for safety; lowering.')
        args.max_rps = 10

    # Adaptive RPS event logger
    def _adaptive_event(ev_type: str, new_rps: float):
        if ev_type == 'decrease':
            print(f"[ADAPT] {t('adaptive_rps_decrease', lang)}: {new_rps:.2f}")
        elif ev_type == 'increase':
            print(f"[ADAPT] {t('adaptive_rps_increase', lang)}: {new_rps:.2f}")

    http = HttpClient(base_root, max_rps=args.max_rps, timeout=args.timeout, max_requests=args.max_requests, adaptive=not args.no_adaptive_rps, on_adaptive_event=_adaptive_event)
    if args.no_adaptive_rps:
        print(t('adaptive_rps_disabled', lang))
    findings_all = []
    js_routes = []  # cache of routes from jsmap

    params = []
    if args.params:
        params = [p.strip() for p in args.params.split(',') if p.strip()]

    if args.profile and not args.all and args.modules == ','.join(SAFE_DEFAULT_MODULES):
        prof = args.profile.lower()
        if prof == 'light':
            modules = ['headers','paths','xss']
        elif prof == 'hardening':
            modules = ['headers','policy','tech','cors','mixed']
        elif prof == 'api':
            modules = ['headers','policy','jsmap','apis','cors','reflect']
        elif prof == 'full':
            modules = ['headers','policy','paths','discovery','crawl','forms','tech','cors','exposures','redirect','jsmap','apis','mixed','xss','sqli','ssrf','reflect','waf','stats']
        else:
            print(f"Unknown profile {args.profile}")
        if prof in ('light','hardening','full','api'):
            print(f"Profile {prof}: {', '.join(modules)}")

    if args.all:
        modules = ['headers','policy','paths','discovery','crawl','forms','tech','cors','exposures','redirect','jsmap','apis','mixed','xss','sqli','ssrf','reflect','waf','stats']
        print(f"--all => {t('all_modules', lang)}: {', '.join(modules)}")

    severity_rank = {'info':0,'low':1,'medium':2,'high':3,'critical':4}
    min_rank = None
    if args.min_severity:
        ms = args.min_severity.lower()
        if ms in severity_rank:
            min_rank = severity_rank[ms]
        else:
            print(f"Unknown --min-severity {args.min_severity}, ignoring")

    for m in modules:
        print(f"\n[{m.upper()}] {t('running_module', lang)}...")
        try:
            if m == 'headers':
                fds = MODULE_MAP[m](http, args.url)
            elif m == 'paths':
                fds = MODULE_MAP[m](http, args.url)
            elif m == 'xss':
                fds = MODULE_MAP[m](http, args.url, params, lang, evasion=args.evasion)
            elif m == 'sqli':
                fds = MODULE_MAP[m](http, args.url, params, evasion=args.evasion)
            elif m == 'crawl':
                fds = MODULE_MAP[m](http, args.url, depth=args.crawl_depth, max_pages=args.max_pages)
            elif m == 'forms':
                fds = MODULE_MAP[m](http, args.url)
            elif m == 'tech':
                fds = MODULE_MAP[m](http, args.url)
            elif m == 'jsmap':
                fds = MODULE_MAP[m](http, args.url)
                js_routes = [f.detail for f in fds if f.title == 'API маршрут']
            elif m == 'apis':
                extra = []
                if args.apis_auto and js_routes:
                    extra = js_routes
                fds = MODULE_MAP[m](http, args.url, extra=extra)
            elif m == 'policy':
                fds = MODULE_MAP[m](http, args.url)
            elif m == 'mixed':
                fds = MODULE_MAP[m](http, args.url)
            elif m == 'discovery':
                fds = MODULE_MAP[m](http, args.url)
            elif m == 'ssrf':
                fds = MODULE_MAP[m](http, args.url)
            elif m == 'reflect':
                fds = MODULE_MAP[m](http, args.url)
            elif m == 'stats':
                fds = MODULE_MAP[m](http, args.url)
            else:
                fds = []
        except Exception as e:
            print(f"Module {m} error: {e}")
            fds = []
        findings_all.extend([f.to_dict() for f in fds])
        for f in fds:
            if min_rank is not None and severity_rank.get(f.severity,0) < min_rank:
                continue
            sev_local = map_severity(f.severity, lang)
            print(color_for(f.severity) + f" - {sev_local.upper():9} {f.title}: {f.detail}" + Style.RESET_ALL)

    # Auto-run XSS/SQLi if requested and crawl executed
    if args.auto_xss_sqli and 'crawl' in modules:
        discovered = []
        for f in findings_all:
            if f['module'] == 'crawl' and f['title'].startswith('PARAM:'):
                pname = f['title'].split(':',1)[1]
                if pname not in discovered:
                    discovered.append(pname)
        if discovered:
            print(f"\n{t('auto_run_xss_sqli', lang)}: {', '.join(discovered[:args.auto_params_limit])}")
            auto_params = discovered[:args.auto_params_limit]
            # run xss
            xss_f = xss_run(http, args.url, auto_params, lang, evasion=args.evasion)
            findings_all.extend([f.to_dict() for f in xss_f])
            for f in xss_f:
                if min_rank is not None and severity_rank.get(f.severity,0) < min_rank:
                    continue
                sev_local = map_severity(f.severity, lang)
                print(color_for(f.severity) + f" - {sev_local.upper():9} {f.title}: {f.detail}" + Style.RESET_ALL)
            # run sqli
            sqli_f = sqli_run(http, args.url, auto_params, evasion=args.evasion)
            findings_all.extend([f.to_dict() for f in sqli_f])
            for f in sqli_f:
                if min_rank is not None and severity_rank.get(f.severity,0) < min_rank:
                    continue
                sev_local = map_severity(f.severity, lang)
                print(color_for(f.severity) + f" - {sev_local.upper():9} {f.title}: {f.detail}" + Style.RESET_ALL)

    # Auto API probing second pass (only if apis not explicitly run)
    if args.apis_auto and 'jsmap' in modules and 'apis' not in modules and js_routes:
        print(f"\n{t('apis_auto', lang)}: {len(js_routes)} маршрутов")
        api_f = apis_run(http, args.url, extra=js_routes)
        findings_all.extend([f.to_dict() for f in api_f])
        for f in api_f:
            if min_rank is not None and severity_rank.get(f.severity,0) < min_rank:
                continue
            sev_local = map_severity(f.severity, lang)
            print(color_for(f.severity) + f" - {sev_local.upper():9} {f.title}: {f.detail}" + Style.RESET_ALL)

    # Apply min severity filter for reporting outputs
    report_findings = []
    summary_counts = {}
    for f in findings_all:
        if min_rank is not None and severity_rank.get(f['severity'],0) < min_rank:
            continue
        report_findings.append(f)
        summary_counts[f['severity']] = summary_counts.get(f['severity'],0)+1

    print(f"\n{t('summary', lang)}:")
    for sev, count in sorted(summary_counts.items()):
        print(f"  {map_severity(sev, lang)}: {count}")

    if args.json:
        out_obj = { 'target': args.url, 'findings': report_findings }
        try:
            with open(args.json, 'w', encoding='utf-8') as jf:
                json.dump(out_obj, jf, indent=2, ensure_ascii=False)
            print(f"{t('saved_json', lang)} -> {args.json}")
        except Exception as e:
            print(f"Failed write JSON: {e}")

    if args.jsonl:
        try:
            with open(args.jsonl, 'w', encoding='utf-8') as jl:
                for f in report_findings:
                    jl.write(json.dumps(f, ensure_ascii=False) + '\n')
            print(f"{t('jsonl_saved', lang)} -> {args.jsonl}")
        except Exception as e:
            print(f"Failed write JSONL: {e}")

    if args.md:
        try:
            # group by module
            by_mod = {}
            for f in report_findings:
                by_mod.setdefault(f['module'], []).append(f)
            lines = [f"# Report for {args.url}", '', '## Summary', '']
            sev_counts = {}
            for f in report_findings:
                sev_counts[f['severity']] = sev_counts.get(f['severity'],0)+1
            for s,c in sorted(sev_counts.items()):
                lines.append(f"- {s}: {c}")
            lines.append('\n## Findings by module\n')
            for mod, lst in by_mod.items():
                lines.append(f"### {mod} ({len(lst)})")
                for item in lst:
                    lines.append(f"* [{item['severity']}] {item['title']} — {item['detail'][:160]}")
                lines.append('')
            with open(args.md, 'w', encoding='utf-8') as mf:
                mf.write('\n'.join(lines))
            print(f"{t('md_saved', lang)} -> {args.md}")
        except Exception as e:
            print(f"Failed write MD: {e}")
    # CSV export
    if args.csv:
        import csv
        try:
            with open(args.csv, 'w', encoding='utf-8', newline='') as cf:
                w = csv.writer(cf)
                w.writerow(['module','severity','title','detail'])
                for f in report_findings:
                    w.writerow([f['module'], f['severity'], f['title'], f['detail'].replace('\n',' ')[:500]])
            print(f"CSV saved -> {args.csv}")
        except Exception as e:
            print(f"Failed write CSV: {e}")

    # Augment paths with discovery results (quick HEAD) if requested
    if args.augment_paths and 'discovery' in modules:
        from urllib.parse import urlparse as _up
        added = 0
        for f in report_findings:
            if f['module']=='discovery' and f['title'] in ('ROBOTS disallow','SITEMAP url'):
                raw = f['detail']
                path = raw
                if raw.startswith('http://') or raw.startswith('https://'):
                    pu = _up(raw)
                    path = pu.path
                if not path or path == '/':
                    continue
                try:
                    r_head = http.head(path)
                    findings_all.append({'module':'paths','severity':'info','title':'Augmented path','detail':f'{path} status={r_head.status_code}'})
                    added += 1
                except Exception:
                    pass
                if added >= 50:
                    break
        if added:
            print(f"Augmented paths: {added}")
    return 0

if __name__ == '__main__':
    sys.exit(main())
