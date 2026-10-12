Python Security Scanner 🔒
Простой сканер уязвимостей в Python-коде. Находит SQL-инъекции, хардкод секретов, XSS, CORS-проблемы, слабую криптографию и другие типичные ошибки.

Зачем этот проект: статический анализ кода помогает находить проблемы безопасности до того, как они попадут в продакшен. Этот сканер — простой инструмент для быстрой проверки Python-проектов.

📋 Содержание
Возможности

Установка

Использование

Правила

Структура

Автор

✨ Возможности
🔍 37 правил для поиска уязвимостей

🎯 Фильтр по серьёзности (--severity HIGH)

📝 Игнор-лист (.scannerignore)

🚫 Исключение папок (--exclude venv)

📊 JSON-отчёт с метаданными

🎨 Красивый вывод через rich

🔄 Код возврата для CI/CD (--strict)

🛠 Установка
bash
git clone https://github.com/nconichtchenko-arch/python-security-scanner.git
cd python-security-scanner
python -m venv venv
venv\Scripts\activate     # Windows
# source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
🚀 Использование
Базовый запуск
bash
python scanner.py ./my_project
Фильтр по серьёзности
bash
python scanner.py ./my_project --severity HIGH
Игнор-лист
bash
python scanner.py ./my_project --ignore .scannerignore
Исключение папок
bash
python scanner.py . --exclude venv --exclude tests/
JSON-отчёт
bash
python scanner.py ./my_project --json report.json
Строгий режим (CI/CD)
bash
python scanner.py ./my_project --strict
📜 Правила
ID	Название	Серьёзность
SQL001	SQL-инъекция через f-string	CRITICAL
SQL003	SQL-запрос через конкатенацию	HIGH
SEC001	Хардкод пароля	HIGH
SEC002	Хардкод API-ключа	HIGH
SEC005	Хардкод JWT-секрета	CRITICAL
EXE001	Использование eval()	CRITICAL
EXE002	Использование exec()	HIGH
SUB001	subprocess с shell=True	HIGH
CRY001	Слабый хеш MD5	MEDIUM
CRY005	Отключение проверки SSL	CRITICAL
XSS001	XSS через render_template_string	HIGH
CORS002	CORS с allow_credentials=True и origins='*'	CRITICAL
...	всего 37 правил	
📁 Структура
text
python-security-scanner/
├── scanner.py            # основной код
├── rules.py              # 37 правил
├── test_vulnerable.py    # тестовый файл
├── requirements.txt
├── .scannerignore
└── README.md
📊 Пример работы
text
🔍 Сканирую 1 файлов...

┌─────────────────────────────────────────┐
│ Найдено 12 проблем                       │
│ CRITICAL: 2 | HIGH: 6 | MEDIUM: 3 | LOW: 1 │
└─────────────────────────────────────────┘

1. EXE001 Использование eval()
   Файл: test_vulnerable.py:24
   Код:  return eval(code)
   Описание: eval() выполняет произвольный код. Это критическая уязвимость.
👤 Автор
Онищенко Павел Владимирович

GitHub: @nconichtchenko-arch

Проект создан как инструмент для быстрой проверки Python-кода на типичные уязвимости.

