<div align="center">

# 🔍 VulnScan

**Модульный этичный сканер безопасности веб-приложений**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

*Инструмент для безопасного и разрешенного тестирования веб-приложений программ и этичного аудита*

[Возможности](#-возможности) • [Установка](#-установка) • [Использование](#-использование) • [Web Interface](#-web-interface) • [Модули](#-модули)

</div>

---

## ✨ Возможности

- 🎯 **19 специализированных модулей** — от security headers до WAF detection
- 🚀 **Адаптивное управление нагрузкой** — автоматическое снижение RPS при ошибках сервера
- 🎨 **Web Dashboard** — современный интерфейс для управления сканами (RU/EN)
- 📊 **Множественные форматы экспорта** — JSON, JSONL, CSV, Markdown
- 🛡️ **Безопасный дизайн** — лимиты RPS, максимум запросов, без деструктивных действий
- ⚡ **Гибкие профили** — light, hardening, api, full
- 🔐 **Evasion режим** — расширенные варианты проверки XSS/SQLi для обхода базовых фильтров

## 📦 Установка

```powershell
# Клонировать репозиторий
git clone https://github.com/yourusername/vulnscan.git
cd vulnscan

# Создать виртуальное окружение
python -m venv .venv
.venv\Scripts\Activate.ps1

# Установить зависимости
pip install -r requirements.txt
```

## 🚀 Использование

### CLI (Командная строка)

#### Базовый скан
```powershell
python vulnscan.py --url https://example.com --modules headers,paths
```

#### Полный скан с лимитами
```powershell
python vulnscan.py --url https://example.com --all --max-rps 6 --max-requests 250
```

#### Использование профилей
```powershell
# API тестирование
python vulnscan.py --url https://api.example.com --profile api --apis-auto

# Hardening проверка
python vulnscan.py --url https://example.com --profile hardening
```

#### Автоматический поиск XSS/SQLi
```powershell
python vulnscan.py --url https://example.com --modules crawl --auto-xss-sqli --crawl-depth 2
```

#### С evasion режимом
```powershell
python vulnscan.py --url https://example.com --modules xss,sqli --params q --evasion
```

#### Экспорт результатов
```powershell
python vulnscan.py --url https://example.com --all --json report.json --md report.md --csv report.csv
```

### 🎨 Web Interface

Запустить веб-интерфейс:
```powershell
start.bat
# или
python web_server.py
```

Откройте браузер: **http://localhost:5000**

**Возможности UI:**
- ✅ Dashboard с real-time статистикой
- ✅ Запуск сканов через GUI
- ✅ История всех сканов
- ✅ Детальный просмотр результатов
- ✅ Фильтрация по severity
- ✅ Автообновление каждые 3 секунды
- ✅ Переключение языка RU/EN

## 📋 Модули

| Модуль | Описание |
|--------|----------|
| **headers** | Анализ security headers (CSP, HSTS, X-Frame-Options и др.) |
| **policy** | Парсинг security.txt |
| **paths** | Проверка распространенных путей |
| **discovery** | Извлечение robots.txt, sitemap.xml |
| **crawl** | Обход ссылок, сбор параметров |
| **forms** | Анализ HTML форм |
| **tech** | Fingerprinting технологий |
| **cors** | Проверка CORS конфигурации |
| **exposures** | Поиск чувствительных файлов (.env, backups) |
| **redirect** | Тестирование open redirect |
| **jsmap** | Извлечение API endpoints из JavaScript |
| **apis** | Проверка REST API endpoints |
| **mixed** | Обнаружение mixed content |
| **xss** | Контекстный анализ reflected XSS |
| **sqli** | Boolean & error-based SQL injection |
| **ssrf** | Эвристика SSRF кандидатов |
| **reflect** | Контролируемое отражение параметров |
| **waf** | Определение WAF по заголовкам и поведению |
| **stats** | Статистика HTTP статусов |

## ⚙️ Профили

| Профиль | Модули |
|---------|--------|
| `light` | headers, paths, xss |
| `hardening` | headers, policy, tech, cors, mixed |
| `api` | headers, policy, jsmap, apis, cors, reflect |
| `full` | все модули |

## 🔧 Основные флаги

| Флаг | Описание |
|------|----------|
| `--url` | Целевой URL (обязательно) |
| `--modules` | Список модулей через запятую |
| `--all` | Запустить все модули |
| `--profile` | light/hardening/api/full |
| `--evasion` | Расширенные варианты XSS/SQLi |
| `--max-rps` | Макс. запросов в секунду (≤10) |
| `--max-requests` | Глобальный лимит запросов |
| `--min-severity` | Фильтр: info/low/medium/high/critical |
| `--auto-xss-sqli` | Авто XSS/SQLi после crawl |
| `--apis-auto` | Авто проверка API из jsmap |
| `--augment-paths` | HEAD для путей из discovery |
| `--no-adaptive-rps` | Отключить авто-снижение RPS |
| `--json / --csv / --md / --jsonl` | Форматы экспорта |
| `--lang` | ru/en |

## 📊 Формат результатов

### JSON
```json
{
  "target": "https://example.com",
  "findings": [
    {
      "module": "headers",
      "severity": "medium",
      "title": "Missing CSP",
      "detail": "Content-Security-Policy header is absent"
    }
  ]
}
```

### Markdown
Автоматически группирует находки по модулям с сводкой по severity.

### CSV
Простая табличная структура для анализа в Excel/Google Sheets.

## 🛡️ Безопасность и этика

⚠️ **ВАЖНО:**
- Используйте **только на разрешенных целях** 
- Инструмент **не содержит деструктивных функций**
- RPS ограничен до **≤10** для предотвращения DoS
- Останавливайте скан при признаках деградации сервиса

## 🔄 Адаптивный RPS

Система автоматически снижает скорость запросов при:
- Росте 5xx ошибок (>40% от последних 30 запросов)
- Плавное восстановление при стабилизации

Отключить: `--no-adaptive-rps`

## 🎯 Примеры использования

### Быстрая проверка security headers
```powershell
python vulnscan.py --url https://example.com --modules headers
```

### Поиск чувствительных файлов
```powershell
python vulnscan.py --url https://example.com --modules exposures,discovery
```

### API тестирование
```powershell
python vulnscan.py --url https://api.example.com --profile api --apis-auto --evasion
```

### Полный аудит с отчетом
```powershell
python vulnscan.py --url https://example.com --all --max-rps 4 --json report.json --md report.md
```

## 🤝 Контрибьюция

Pull requests приветствуются! Для крупных изменений сначала откройте issue для обсуждения.

## � Поддержать проект

Если этот инструмент оказался полезен, вы можете поддержать разработку:

[![Donation Alerts](https://img.shields.io/badge/Donate-DonationAlerts-orange?style=for-the-badge&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAYAAAAfSC3RAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAIGNIUk0AAHolAACAgwAA+f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAErSURBVHjarJK/S8NAGMXf3dwl1xDaIjgoiB38Uw46ODi5OLk6ODo4ODi5ODg4ODi5ODg4ODi5ODg4ODg4uDg4ODi4ODg4ODg4ODg4/AO+4YXk0iTFwYUjud/73fe+O0IIQRAEQRAEQRAEQRAEQRAEQfwv4v+Mjx8fH+/v7+/v7+/v7+8EQRAEQRAEQRAE8f+o1WrVarVarVarVavVCoIgCIIgCIIgCOJ/0O12u91ut9vtdrvdbhAEQRAEQRAEQRD/g8lkMplMJpPJZDKZTIIgCIIgCIIgCIL4H0yn0+l0Op1Op9PpdBoEQRAEQRAEQRDE/2A+n8/n8/l8Pp/P53OsVqvVarVarVar1QqCIAiCIAiCIIj/wWKxWCwWi8VisVgsFgRBEARBEARBEMT/YLlcLpfL5XK5XC6XS4IgCIIgCIIgCOJv+RoAj5p0NnQ4rPUAAAAASUVORK5CYII=)](https://www.donationalerts.com/r/thebestcode)

## �📄 Лицензия

[MIT](LICENSE)

## 🔮 Roadmap

- [ ] POST request fingerprinting
- [ ] Расширенные XSS контексты (SVG, CSS)
- [ ] GraphQL endpoint discovery
- [ ] Легкий parameter fuzzing
- [ ] Docker контейнер
- [ ] CI/CD интеграция

---

<div align="center">

**Сделано с ❤️ для этичного тестирования безопасности**

</div>
