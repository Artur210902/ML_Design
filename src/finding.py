"""Единый формат находки.

Четыре сканера с разным выводом приводятся к одной структуре — иначе их результаты
нельзя ни сравнить между собой, ни сопоставить с эталонной разметкой.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum


class Status(StrEnum):
    """Статус находки.

    Подтверждённой находка становится только после трёх воспроизведений в чистом
    окружении; до этого она остаётся гипотезой. Правило продублировано ограничением
    в схеме базы данных, поэтому выставить статус в обход проверки нельзя.
    """

    HYPOTHESIS = "hypothesis"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class CweSource(StrEnum):
    """Откуда взялся класс уязвимости.

    Нужно, чтобы отличать данные инструмента от нашей интерпретации: gitleaks,
    например, не сообщает ни CWE, ни серьёзность — их проставляет харнес.
    """

    TOOL = "tool"
    HARNESS_MAP = "harness_map"
    NONE = "none"


MIN_RUNS_TO_CONFIRM = 3


@dataclass(slots=True)
class Finding:
    """Находка сканера, приведённая к единому виду."""

    source: str
    rule_id: str
    file: str
    line_start: int
    line_end: int
    message: str
    cwe: int | None = None
    cwe_source: CweSource = CweSource.NONE
    severity: str | None = None
    tool_version: str | None = None
    status: Status = Status.HYPOTHESIS
    reproduced_runs: int = 0
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Устойчивый идентификатор находки.

        Намеренно не включает серьёзность и текст сообщения: они меняются между
        версиями инструментов, а идентификатор должен совпадать между прогонами,
        иначе нельзя посчитать число воспроизведений.
        """
        parts = f"{self.source}|{self.rule_id}|{self.file}|{self.line_start}|{self.cwe}"
        return hashlib.sha256(parts.encode()).hexdigest()[:16]

    def can_confirm(self) -> bool:
        """Можно ли пометить находку подтверждённой."""
        return self.reproduced_runs >= MIN_RUNS_TO_CONFIRM
