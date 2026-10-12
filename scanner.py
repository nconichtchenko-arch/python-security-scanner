"""
Python Security Scanner — простой сканер уязвимостей в Python-коде.
Использование:
    python scanner.py <path>            — сканировать файл или папку
    python scanner.py <path> --json     — вывести отчёт в JSON
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from rules import RULES, SEVERITY_COLORS, SEVERITY_ORDER, SEVERITY_LEVELS


console = Console()


def find_python_files(path, exclude_dirs=None):
    """
    Находит все .py файлы в указанном пути.
    exclude_dirs: список папок для исключения.
    """
    path = Path(path)

    if not path.exists():
        console.print(f"[red]❌ Путь не найден: {path}[/red]")
        sys.exit(1)

    if path.is_file():
        if path.suffix == ".py":
            return [path]
        else:
            console.print(f"[red]❌ Файл не является .py: {path}[/red]")
            sys.exit(1)

    # Папка — ищем все .py рекурсивно
    py_files = list(path.rglob("*.py"))

    # Базовые исключения
    exclude = {"venv", ".venv", "env", "__pycache__", ".git", "node_modules", ".tox", "build", "dist"}

    # Добавляем пользовательские исключения
    if exclude_dirs:
        exclude.update(exclude_dirs)

    py_files = [f for f in py_files if not any(part in exclude for part in f.parts)]

    return py_files


def scan_file(file_path):
    """
    Сканирует один файл на уязвимости.
    Возвращает список найденных проблем.
    """
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except UnicodeDecodeError:
        console.print(f"[yellow]⚠️ Не удалось прочитать {file_path} (кодировка)[/yellow]")
        return findings

    for line_num, line in enumerate(lines, start=1):
        for rule in RULES:
            if rule["pattern"] in line:
                findings.append({
                    "file": str(file_path),
                    "line": line_num,
                    "code": line.strip(),
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                })

    return findings


def print_findings(findings):
    """
    Красиво выводит находки в консоль через rich.
    """
    if not findings:
        console.print(Panel(
            "[green]✅ Уязвимостей не найдено![/green]",
            title="Результат сканирования",
            border_style="green",
        ))
        return

    # Сводка
    severity_count = {}
    for f in findings:
        sev = f["severity"]
        severity_count[sev] = severity_count.get(sev, 0) + 1

    summary_lines = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in severity_count:
            color = SEVERITY_COLORS.get(sev, "white")
            summary_lines.append(f"[{color}]{sev}: {severity_count[sev]}[/{color}]")

    console.print(Panel(
        " | ".join(summary_lines),
        title=f"[bold]Найдено {len(findings)} проблем[/bold]",
        border_style="red",
    ))
    console.print()

    # Таблица находок
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("#", style="dim", width=4)
    table.add_column("Файл", style="cyan", width=30)
    table.add_column("Строка", justify="right", width=6)
    table.add_column("Правило", width=8)
    table.add_column("Серьёзность", width=10)
    table.add_column("Название", width=30)
    table.add_column("Код", width=40, overflow="fold")

    for i, f in enumerate(findings, 1):
        color = SEVERITY_COLORS.get(f["severity"], "white")
        file_short = Path(f["file"]).name
        table.add_row(
            str(i),
            file_short,
            str(f["line"]),
            f["rule_id"],
            Text(f["severity"], style=color),
            f["name"],
            f["code"][:40] + ("..." if len(f["code"]) > 40 else ""),
        )

    console.print(table)
    console.print()

    # Детали
    console.print("[bold]Детали:[/bold]\n")
    for i, f in enumerate(findings, 1):
        color = SEVERITY_COLORS.get(f["severity"], "white")
        console.print(f"[bold]{i}. [{color}]{f['rule_id']}[/{color}] {f['name']}[/bold]")
        console.print(f"   Файл: {f['file']}:{f['line']}")
        console.print(f"   Код:  {f['code']}")
        console.print(f"   Описание: {f['description']}")
        console.print()


def save_json_report(findings, output_path):
    """
    Сохраняет отчёт в JSON с метаданными.
    """
    # Сводка по серьёзности
    severity_summary = {}
    for sev in SEVERITY_LEVELS:
        count = sum(1 for f in findings if f["severity"] == sev)
        if count > 0:
            severity_summary[sev] = count

    report = {
        "metadata": {
            "scanner": "Python Security Scanner",
            "version": "1.0.0",
            "generated_at": datetime.now().isoformat(),
            "total_findings": len(findings),
        },
        "summary": {
            "by_severity": severity_summary,
        },
        "findings": findings,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    console.print(f"[green]✅ Отчёт сохранён: {output_path}[/green]")
    console.print(f"[dim]   Всего находок: {len(findings)}[/dim]")
    for sev, count in severity_summary.items():
        color = SEVERITY_COLORS.get(sev, "white")
        console.print(f"[dim]   [{color}]{sev}[/{color}]: {count}[/dim]")


def load_ignore_list(ignore_path):
    """
    Загружает список игнорируемых правил из файла.
    Каждая строка — ID правила (например, SQL001).
    """
    if not ignore_path:
        return set()

    try:
        with open(ignore_path, "r", encoding="utf-8") as f:
            ignore = {line.strip() for line in f if line.strip() and not line.startswith("#")}
        console.print(f"[dim]📋 Игнорируем правила: {', '.join(sorted(ignore)) or 'нет'}[/dim]")
        return ignore
    except FileNotFoundError:
        console.print(f"[yellow]⚠️ Файл игнора не найден: {ignore_path}[/yellow]")
        return set()


def filter_findings(findings, min_severity=None, ignore_rules=None):
    """
    Фильтрует находки:
    - min_severity: показывать только эту серьёзность и выше
    - ignore_rules: set ID правил для игнорирования
    """
    result = findings

    if ignore_rules:
        result = [f for f in result if f["rule_id"] not in ignore_rules]

    if min_severity:
        if min_severity not in SEVERITY_LEVELS:
            console.print(f"[red]❌ Неверная серьёзность: {min_severity}. Доступны: {', '.join(SEVERITY_LEVELS)}[/red]")
            sys.exit(1)

        min_index = SEVERITY_LEVELS.index(min_severity)
        allowed = set(SEVERITY_LEVELS[:min_index + 1])
        result = [f for f in result if f["severity"] in allowed]

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Python Security Scanner — сканер уязвимостей в Python-коде",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python scanner.py ./my_project
  python scanner.py ./my_project --severity HIGH
  python scanner.py ./my_project --ignore .scannerignore
  python scanner.py ./my_project --exclude tests/ --exclude migrations/
  python scanner.py script.py --json report.json
  python scanner.py script.py --strict
        """,
    )
    parser.add_argument("path", help="Путь к файлу или папке для сканирования")
    parser.add_argument(
        "--severity",
        choices=SEVERITY_LEVELS,
        default=None,
        help="Минимальная серьёзность для показа (CRITICAL, HIGH, MEDIUM, LOW)",
    )
    parser.add_argument(
        "--ignore",
        default=None,
        help="Файл с ID правил для игнорирования (по одному на строку)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Папки для исключения (можно указать несколько раз)",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        default=None,
        help="Сохранить отчёт в JSON",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Код возврата 1 при любой находке (не только CRITICAL)",
    )

    args = parser.parse_args()

    console.print(Panel(
        "[bold cyan]🐍 Python Security Scanner[/bold cyan]\n"
        "[dim]Простой сканер уязвимостей в Python-коде[/dim]",
        border_style="cyan",
    ))
    console.print()

    # Загружаем игнор-лист
    ignore_rules = load_ignore_list(args.ignore)

    # Сканируем
    files = find_python_files(args.path, exclude_dirs=args.exclude)
    if not files:
        console.print("[yellow]⚠️ Не найдено .py файлов для сканирования[/yellow]")
        sys.exit(0)

    console.print(f"[cyan]🔍 Сканирую {len(files)} файлов...[/cyan]\n")

    all_findings = []
    for file in files:
        findings = scan_file(file)
        all_findings.extend(findings)

    # Фильтруем
    all_findings = filter_findings(all_findings, args.severity, ignore_rules)

    # Сортируем
    all_findings.sort(key=lambda x: (SEVERITY_ORDER.get(x["severity"], 99), x["file"], x["line"]))

    # Выводим
    print_findings(all_findings)

    # JSON
    if args.json_output:
        save_json_report(all_findings, args.json_output)

    # Код возврата
    if args.strict and all_findings:
        sys.exit(1)
    if any(f["severity"] == "CRITICAL" for f in all_findings):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()