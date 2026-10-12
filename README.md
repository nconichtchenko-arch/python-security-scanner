# Python Security Scanner

Простой сканер уязвимостей в Python-коде.

## Возможности

- 37 правил для поиска уязвимостей
- Фильтр по серьёзности
- JSON-отчёт
- Красивый вывод через rich

## Установка

pip install -r requirements.txt

## Использование

python scanner.py ./my_project

## Структура

python-security-scanner/
├── scanner.py
├── rules.py
├── test_vulnerable.py
├── requirements.txt
├── .scannerignore
└── README.md

## Пример работы

🔍 Сканирую 1 файлов...

┌─────────────────────────────────────────┐
│ Найдено 12 проблем                       │
│ CRITICAL: 2 | HIGH: 6 | MEDIUM: 3 | LOW: 1 │
└─────────────────────────────────────────┘

## Автор

Онищенко Павел Владимирович

GitHub: https://github.com/nconichtchenko-arch
