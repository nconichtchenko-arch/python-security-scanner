# Python Security Scanner

Простой сканер уязвимостей в Python-коде. Находит SQL-инъекции, хардкод секретов, XSS, CORS-проблемы и слабую криптографию.

## Содержание

- Возможности
- Установка
- Использование
- Правила
- Структура
- Пример работы
- Автор

## Возможности

- 🔍 37 правил для поиска уязвимостей
- 🎯 Фильтр по серьёзности (--severity HIGH)
- 📝 Игнор-лист (.scannerignore)
- 📊 JSON-отчёт
- 🎨 Красивый вывод через rich
- 🔄 Код возврата для CI/CD (--strict)
- 🚫 Исключение папок (--exclude venv)
- 📁 Сканирование файлов и папок

## Установка

pip install -r requirements.txt

## Использование

python scanner.py ./my_project

## Правила

| ID | Название | Серьёзность |
|----|----------|-------------|
| SQL001 | SQL-инъекция через f-string | CRITICAL |
| SQL003 | SQL-запрос через конкатенацию | HIGH |
| SEC001 | Хардкод пароля | HIGH |
| SEC002 | Хардкод API-ключа | HIGH |
| SEC005 | Хардкод JWT-секрета | CRITICAL |
| EXE001 | Использование eval() | CRITICAL |
| EXE002 | Использование exec() | HIGH |
| SUB001 | subprocess с shell=True | HIGH |
| CRY001 | Слабый хеш MD5 | MEDIUM |
| CRY005 | Отключение проверки SSL | CRITICAL |
| XSS001 | XSS через render_template_string | HIGH |
| CORS002 | CORS с allow_credentials=True | CRITICAL |
| ... | всего 37 правил | |

## Структура
```
python-security-scanner/
├── scanner.py
├── rules.py
├── test_vulnerable.py
├── requirements.txt
├── .scannerignore
└── README.md
```

## Пример работы

```
🔍 Сканирую 1 файлов...

┌─────────────────────────────────────────┐
│ Найдено 12 проблем                       │
│ CRITICAL: 2 | HIGH: 6 | MEDIUM: 3 | LOW: 1 │
└─────────────────────────────────────────┘
```
1. EXE001 Использование eval()
   Файл: test_vulnerable.py:24
   Код:  return eval(code)
   Описание: eval() выполняет произвольный код. Это критическая уязвимость.
## Автор

Онищенко Павел Владимирович

GitHub: https://github.com/nconichtchenko-arch
