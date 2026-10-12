"""
Правила для сканера безопасности Python-кода.
Каждое правило: тип уязвимости, серьёзность, описание, паттерн для поиска.
"""

RULES = [
    # === SQL-инъекции ===
    {
        "id": "SQL001",
        "name": "SQL-инъекция через f-string",
        "severity": "CRITICAL",
        "description": "Использование f-string в SQL-запросе может привести к SQL-инъекции. Используйте параметризованные запросы.",
        "pattern": "execute(f\"",
        "language": "python",
    },
    {
        "id": "SQL002",
        "name": "SQL-инъекция через % или .format()",
        "severity": "CRITICAL",
        "description": "Использование % или .format() в SQL-запросе может привести к SQL-инъекции.",
        "pattern": "execute(\"",
        "language": "python",
    },
    {
        "id": "SQL003",
        "name": "SQL-запрос через конкатенацию",
        "severity": "HIGH",
        "description": "Конкатенация строк в SQL-запросе может привести к SQL-инъекции.",
        "pattern": "SELECT * FROM",
        "language": "python",
    },

    # === Хардкод секретов ===
    {
        "id": "SEC001",
        "name": "Хардкод пароля",
        "severity": "HIGH",
        "description": "Пароль в коде — это уязвимость. Используйте переменные окружения или секреты.",
        "pattern": "password = \"",
        "language": "python",
    },
    {
        "id": "SEC002",
        "name": "Хардкод API-ключа",
        "severity": "HIGH",
        "description": "API-ключ в коде — это уязвимость. Используйте переменные окружения.",
        "pattern": "api_key = \"",
        "language": "python",
    },
    {
        "id": "SEC003",
        "name": "Хардкод секрета",
        "severity": "HIGH",
        "description": "Секрет в коде — это уязвимость. Используйте переменные окружения.",
        "pattern": "secret = \"",
        "language": "python",
    },
    {
        "id": "SEC004",
        "name": "Хардкод токена",
        "severity": "HIGH",
        "description": "Токен в коде — это уязвимость. Используйте переменные окружения.",
        "pattern": "token = \"",
        "language": "python",
    },
    {
        "id": "SEC005",
        "name": "Хардкод JWT-секрета",
        "severity": "CRITICAL",
        "description": "JWT-секрет в коде — это критическая уязвимость. Используйте переменные окружения.",
        "pattern": "jwt_secret = \"",
        "language": "python",
    },

    # === Опасные функции ===
    {
        "id": "EXE001",
        "name": "Использование eval()",
        "severity": "CRITICAL",
        "description": "eval() выполняет произвольный код. Это критическая уязвимость.",
        "pattern": "eval(",
        "language": "python",
    },
    {
        "id": "EXE002",
        "name": "Использование exec()",
        "severity": "HIGH",
        "description": "exec() выполняет произвольный код. Это уязвимость.",
        "pattern": "exec(",
        "language": "python",
    },
    {
        "id": "EXE003",
        "name": "Использование compile()",
        "severity": "HIGH",
        "description": "compile() может выполнять произвольный код.",
        "pattern": "compile(",
        "language": "python",
    },

    # === Subprocess / OS ===
    {
        "id": "SUB001",
        "name": "subprocess с shell=True",
        "severity": "HIGH",
        "description": "shell=True позволяет инъекции команд. Используйте shell=False и список аргументов.",
        "pattern": "shell=True",
        "language": "python",
    },
    {
        "id": "IMP002",
        "name": "Использование os.system()",
        "severity": "HIGH",
        "description": "os.system() уязвим для инъекций команд. Используйте subprocess.",
        "pattern": "os.system(",
        "language": "python",
    },
    {
        "id": "IMP003",
        "name": "Использование os.popen()",
        "severity": "HIGH",
        "description": "os.popen() уязвим для инъекций команд. Используйте subprocess.",
        "pattern": "os.popen(",
        "language": "python",
    },

    # === Криптография ===
    {
        "id": "CRY001",
        "name": "Слабый хеш MD5",
        "severity": "MEDIUM",
        "description": "MD5 — устаревший и небезопасный хеш. Используйте SHA-256 или bcrypt.",
        "pattern": "hashlib.md5(",
        "language": "python",
    },
    {
        "id": "CRY002",
        "name": "Слабый хеш SHA1",
        "severity": "MEDIUM",
        "description": "SHA1 — устаревший и небезопасный хеш. Используйте SHA-256 или bcrypt.",
        "pattern": "hashlib.sha1(",
        "language": "python",
    },
    {
        "id": "CRY003",
        "name": "Использование DES",
        "severity": "HIGH",
        "description": "DES — устаревший алгоритм шифрования. Используйте AES.",
        "pattern": "DES.new(",
        "language": "python",
    },
    {
        "id": "CRY004",
        "name": "Использование RC4",
        "severity": "HIGH",
        "description": "RC4 — небезопасный алгоритм. Используйте AES.",
        "pattern": "RC4.new(",
        "language": "python",
    },
    {
        "id": "CRY005",
        "name": "Отключение проверки SSL",
        "severity": "CRITICAL",
        "description": "verify=False отключает проверку SSL-сертификата. Это критическая уязвимость.",
        "pattern": "verify=False",
        "language": "python",
    },

    # === Отладка ===
    {
        "id": "DBG001",
        "name": "Отладочная точка breakpoint()",
        "severity": "LOW",
        "description": "breakpoint() в коде может остановить выполнение. Уберите перед продакшеном.",
        "pattern": "breakpoint()",
        "language": "python",
    },
    {
        "id": "DBG002",
        "name": "Отладочная точка pdb.set_trace()",
        "severity": "LOW",
        "description": "pdb.set_trace() в коде может остановить выполнение. Уберите перед продакшеном.",
        "pattern": "pdb.set_trace()",
        "language": "python",
    },
    {
        "id": "DBG003",
        "name": "Режим отладки Flask",
        "severity": "CRITICAL",
        "description": "debug=True в Flask опасен для продакшена. Отключите.",
        "pattern": "debug=True",
        "language": "python",
    },
    {
        "id": "DBG004",
        "name": "Режим отладки Django",
        "severity": "CRITICAL",
        "description": "DEBUG = True в Django опасен для продакшена. Отключите.",
        "pattern": "DEBUG = True",
        "language": "python",
    },

    # === Небезопасные импорты ===
    {
        "id": "IMP001",
        "name": "Импорт pickle",
        "severity": "MEDIUM",
        "description": "pickle небезопасен для ненадёжных данных. Используйте JSON.",
        "pattern": "import pickle",
        "language": "python",
    },
    {
        "id": "IMP004",
        "name": "Импорт marshal",
        "severity": "MEDIUM",
        "description": "marshal небезопасен для ненадёжных данных.",
        "pattern": "import marshal",
        "language": "python",
    },
    {
        "id": "IMP005",
        "name": "Импорт shelve",
        "severity": "MEDIUM",
        "description": "shelve использует pickle, небезопасен.",
        "pattern": "import shelve",
        "language": "python",
    },

    # === Пути и файлы ===
    {
        "id": "PATH001",
        "name": "Path Traversal через open()",
        "severity": "HIGH",
        "description": "open() с пользовательским вводом может привести к path traversal.",
        "pattern": "open(user",
        "language": "python",
    },
    {
        "id": "PATH002",
        "name": "Path Traversal через os.path.join",
        "severity": "MEDIUM",
        "description": "os.path.join с пользовательским вводом может привести к path traversal.",
        "pattern": "os.path.join(user",
        "language": "python",
    },
    {
        "id": "PATH003",
        "name": "Открытие файла в режиме w без проверки",
        "severity": "MEDIUM",
        "description": "Открытие файла в режиме 'w' может перезаписать важные данные.",
        "pattern": "open(",
        "language": "python",
    },

    # === XSS / Веб ===
    {
        "id": "XSS001",
        "name": "XSS через render_template_string",
        "severity": "HIGH",
        "description": "render_template_string с пользовательским вводом может привести к XSS.",
        "pattern": "render_template_string(",
        "language": "python",
    },
    {
        "id": "XSS002",
        "name": "XSS через Markup",
        "severity": "MEDIUM",
        "description": "Markup с пользовательским вводом может привести к XSS.",
        "pattern": "Markup(",
        "language": "python",
    },
    {
        "id": "XSS003",
        "name": "Отключение экранирования Jinja2",
        "severity": "HIGH",
        "description": "|safe в Jinja2 отключает экранирование, что может привести к XSS.",
        "pattern": "|safe",
        "language": "python",
    },

    # === CORS / Безопасность ===
    {
        "id": "CORS001",
        "name": "CORS с разрешением всех источников",
        "severity": "HIGH",
        "description": "CORS с origins='*' разрешает все источники. Это небезопасно.",
        "pattern": "origins=\"*\"",
        "language": "python",
    },
    {
        "id": "CORS002",
        "name": "CORS с allow_credentials=True и origins='*'",
        "severity": "CRITICAL",
        "description": "CORS с allow_credentials=True и origins='*' — критическая уязвимость.",
        "pattern": "allow_credentials=True",
        "language": "python",
    },

    # === Прочее ===
    {
        "id": "MISC001",
        "name": "Использование assert для проверок безопасности",
        "severity": "MEDIUM",
        "description": "assert может быть отключён при оптимизации (-O). Не используйте для проверок безопасности.",
        "pattern": "assert ",
        "language": "python",
    },
    {
        "id": "MISC002",
        "name": "Использование random для паролей",
        "severity": "HIGH",
        "description": "random небезопасен для генерации паролей. Используйте secrets.",
        "pattern": "random.randint(",
        "language": "python",
    },
    {
        "id": "MISC003",
        "name": "Использование random.choice для токенов",
        "severity": "HIGH",
        "description": "random.choice небезопасен для токенов. Используйте secrets.",
        "pattern": "random.choice(",
        "language": "python",
    },
]


# Цвета для вывода (rich)
SEVERITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "orange1",
    "MEDIUM": "yellow",
    "LOW": "blue",
}


# Порядок серьёзности (для сортировки)
SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
}


# Уровни серьёзности для фильтра
SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]