"""Тесты контракта находки."""

from src.finding import CweSource, Finding, Status


def make_finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "source": "semgrep",
        "rule_id": "python.lang.security.audit.eval-detected",
        "file": "app/views.py",
        "line_start": 42,
        "line_end": 42,
        "message": "Detected eval() on user input",
        "cwe": 95,
        "cwe_source": CweSource.TOOL,
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


def test_fingerprint_is_stable_across_runs():
    """Один и тот же дефект в разных прогонах даёт один идентификатор."""
    assert make_finding().fingerprint == make_finding().fingerprint


def test_fingerprint_ignores_volatile_fields():
    """Серьёзность и текст сообщения меняются между версиями инструмента.

    Если бы они входили в идентификатор, обновление сканера обнуляло бы счётчик
    воспроизведений и находка никогда не стала бы подтверждённой.
    """
    base = make_finding()
    changed = make_finding(severity="critical", message="Другой текст")
    assert base.fingerprint == changed.fingerprint


def test_fingerprint_differs_for_different_locations():
    assert make_finding().fingerprint != make_finding(line_start=99).fingerprint


def test_cannot_confirm_below_three_runs():
    """Правило «подтверждено 3 из 3»."""
    for runs in (0, 1, 2):
        assert not make_finding(reproduced_runs=runs).can_confirm()


def test_can_confirm_at_three_runs():
    assert make_finding(reproduced_runs=3).can_confirm()


def test_new_finding_is_hypothesis_by_default():
    """По умолчанию находка — гипотеза, а не подтверждённая уязвимость."""
    assert make_finding().status is Status.HYPOTHESIS
