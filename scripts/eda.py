import csv
import hashlib
import json
import re
import subprocess
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
raw = ROOT / "data/raw/BenchmarkJava"
out = ROOT / "reports"
(out / "figures").mkdir(parents=True, exist_ok=True)
rows = list(csv.reader((raw / "expectedresults-1.2.csv").read_text().splitlines()[1:]))
counts = Counter((r[1], r[2]) for r in rows)
files = {
    p.stem: p
    for p in (raw / "src/main/java/org/owasp/benchmark/testcode").glob("BenchmarkTest*.java")
}
lengths = []
hashes = Counter()
normalized = Counter()
missing = []
for name, _cat, _label, _cwe in rows:
    if name not in files:
        missing.append(name)
        continue
    text = files[name].read_text(encoding="utf-8")
    lengths.append(len(text.splitlines()))
    hashes[hashlib.sha256(text.encode()).hexdigest()] += 1
    clean = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)
    clean = re.sub(r"BenchmarkTest\d+", "BenchmarkTestID", clean)
    clean = re.sub(r"\s+", "", clean)
    normalized[hashlib.sha256(clean.encode()).hexdigest()] += 1
cats = sorted({r[1] for r in rows})
fig, ax = plt.subplots(figsize=(10, 5))
a = [counts[c, "true"] for c in cats]
b = [counts[c, "false"] for c in cats]
ax.bar(cats, a, label="Vulnerable")
ax.bar(cats, b, bottom=a, label="Safe")
ax.set_ylabel("Cases")
ax.tick_params(axis="x", rotation=35)
ax.legend()
fig.tight_layout()
fig.savefig(out / "figures/class_balance.png", dpi=150)
plt.close(fig)
fig, ax = plt.subplots(figsize=(8, 4))
ax.hist(lengths, bins=35)
ax.set(xlabel="Java source lines per case", ylabel="Cases")
fig.tight_layout()
fig.savefig(out / "figures/source_length.png", dpi=150)
plt.close(fig)
summary = {
    "commit": subprocess.check_output(  # noqa: S603 - fixed arguments for local metadata
        ["git", "-C", str(raw), "rev-parse", "HEAD"],
        text=True,  # noqa: S607 - git resolved from user environment
    ).strip(),
    "csv_sha256": hashlib.sha256((raw / "expectedresults-1.2.csv").read_bytes()).hexdigest(),
    "cases": len(rows),
    "labels": dict(Counter(r[2] for r in rows)),
    "categories": len(cats),
    "cwes": len({r[3] for r in rows}),
    "missing_fields": sum(any(not x.strip() for x in r) for r in rows),
    "duplicate_ids": len(rows) - len({r[0] for r in rows}),
    "missing_sources": missing,
    "exact_duplicate_excess": sum(v - 1 for v in hashes.values()),
    "normalized_duplicate_excess": sum(v - 1 for v in normalized.values()),
    "source_lines": {
        "min": min(lengths),
        "median": sorted(lengths)[len(lengths) // 2],
        "max": max(lengths),
    },
}
(out / "eda_summary.json").write_text(
    json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
)
table = "\n".join(f"| {c} | {counts[c, 'true']} | {counts[c, 'false']} |" for c in cats)
report = f"""# EDA: корпус для верификатора SAST

Анализ выполнен 2026-11-05. Источник: https://github.com/OWASP-Benchmark/BenchmarkJava , commit `{summary["commit"]}`. Разметка `expectedresults-1.2.csv`, SHA-256 `{summary["csv_sha256"]}`. Корпус GPL-2.0; исходники не копируются в репозиторий сдачи.

## Состав и качество

Единица анализа — тестовый Java-файл; это не находка сканера. Всего {len(rows)} кейсов, {summary["labels"]}, {len(cats)} категорий / {summary["cwes"]} CWE. Пропущенных полей: {summary["missing_fields"]}; повторов ID: {summary["duplicate_ids"]}; отсутствующих исходников: {len(missing)}. Точных повторов файлов сверх первого: {summary["exact_duplicate_excess"]}; после удаления комментариев, пробелов и нормализации имени теста: {summary["normalized_duplicate_excess"]}. Эта эвристика не доказывает независимость остальных кейсов.

| Категория | Уязвимые | Безопасные |
|---|---:|---:|
{table}

![Баланс классов](figures/class_balance.png)

Общий баланс близок к равному, но объем категорий различается. Accuracy скроет слабые CWE: нужны метрики по категориям и macro-average. Доля безопасных кейсов не равна доле ложных срабатываний: последняя зависит от сканера.

![Длина исходников](figures/source_length.png)

Число строк min/median/max: {summary["source_lines"]}. Длина файла помогает оценить размер контекста, но строки не равны токенам: лимит и стоимость нужно измерить токенизатором выбранной модели. Обрезка контекста может удалить санитайзер или источник и исказить решение.

## Ограничения разметки и переносимости

CSV содержит имя теста, категорию, boolean и CWE, но не номер строки. Утверждение ранней версии дизайн-документа о наличии строки в CSV требует исправления: точную локализацию надо получать отдельно и проверять вручную. CWE следует брать из файла, а не восстанавливать по названию категории.

Корпус синтетический и Java-only. Он не подтверждает качество на Python/JS, реальных проектах и ИИ-коде. Публичность создает риск запоминания LLM. Комментарии и имена тестов могут выдавать принадлежность бенчмарку: их исключают из контекста модели. Даже при отсутствии точных дублей общий шаблон кода создает утечку между случайными train/test.

Собственный набор из 20 уязвимостей и сырые результаты четырех сканеров отсутствуют в ветке hw_1. Поэтому precision/recall, дубли находок, покрытие инструментов и качество разметки этого набора здесь не измерены. Числа ДЗ1 не являются результатом данного EDA. Без находок невозможно построить распределение именно целевой переменной верификатора.

## Решения по результатам EDA

1. Зафиксировать commit и хеш разметки; проверять схему и соответствие исходникам при обновлении.
2. Сначала собрать JSONL находок и provenance, затем сопоставить с эталоном; неизвестное совпадение передать эксперту, не объявлять автоматически ложным.
3. Разбивать по проектам и семействам шаблонов, удерживать парные safe/vulnerable примеры вместе. OWASP использовать как отдельный диагностический корпус.
4. Добавить реальные Python/JS-проекты и отрицательные примеры. Начальный план — 1000 размеченных находок из >=20 проектов; достаточность проверить learning curve и доверительными интервалами, а не считать гарантированной.
5. Не запускать учебный уязвимый код для EDA. Наличие публичных исходников не дает разрешения отправлять частный код внешней модели.

## Воспроизведение

Из корня репозитория:

```sh
python -m pip install -r requirements-eda.txt
git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git data/raw/BenchmarkJava
git -C data/raw/BenchmarkJava checkout {summary["commit"]}
python scripts/eda.py
```

Скрипт читает только локальные файлы, не исполняет анализируемый код и сохраняет два графика, JSON и этот отчет. Машинные результаты: [eda_summary.json](eda_summary.json).
"""
(out / "eda.md").write_text(report, encoding="utf-8")
print(json.dumps(summary, indent=2))
