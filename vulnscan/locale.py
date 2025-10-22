TRANSLATIONS = {
    'ru': {
        'running_module': 'Запуск модуля',
        'summary': 'Сводка',
        'saved_json': 'JSON сохранён',
        'unknown_module': 'Неизвестный модуль',
        'target_invalid': 'Нужно указать полный URL со схемой (http/https)',
        'auto_params': 'Авто параметры (crawl)',
        'auto_run_xss_sqli': 'Автозапуск XSS/SQLi по найденным параметрам',
    'all_modules': 'Запуск всех модулей',
    'md_saved': 'Markdown отчёт сохранён',
    'forms': 'Формы',
    'tech': 'Технологии',
    'jsmap': 'JS карта',
    'apis': 'API проверка',
    'apis_auto': 'Авто API проверка',
    'cors': 'CORS проверка',
    'min_severity_filtered': 'Применён фильтр минимальной важности',
    'exposures': 'Чувствительные файлы',
    'redirect': 'Redirect проверка',
    'mixed': 'Смешанный контент',
    'discovery': 'Discovery',
    'ssrf': 'SSRF кандидаты',
    'policy': 'Security.txt',
    'csv_saved': 'CSV сохранён',
    'profile': 'Профиль',
    'augment_paths': 'Дополненные пути',
    'reflect': 'Отражение параметров',
    'stats': 'Статусы запросов',
    'waf': 'WAF обнаружение',
    'jsonl_saved': 'JSONL сохранён',
    'adaptive_rps_decrease': 'Снижение скорости (ошибки сервера) новый RPS',
    'adaptive_rps_increase': 'Восстановление скорости новый RPS',
    'adaptive_rps_disabled': 'Адаптивное снижение RPS отключено',
        'severity.info': 'инфо',
        'severity.low': 'низкий',
        'severity.medium': 'средний',
        'severity.high': 'высокий',
        'severity.critical': 'критический'
    },
    'en': {}
}

def t(key: str, lang: str) -> str:
    return TRANSLATIONS.get(lang, {}).get(key, key)

def map_severity(sev: str, lang: str) -> str:
    return TRANSLATIONS.get(lang, {}).get(f'severity.{sev.lower()}', sev)
