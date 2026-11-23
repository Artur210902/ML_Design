from scripts.evaluate_hw3 import evaluate, keep_consensus, keep_single


def finding(line=10, severity="medium", code=89):
    return {"file": "a.py", "line_start": line, "cwe": code, "severity": severity}


def test_matching_deduplicates_and_does_not_double_match():
    seeds = [{"id": "s", "file": "a.py", "line": 10, "cwe": 89}]
    result = evaluate([finding(), finding(), finding(11)], seeds)
    assert (result["tp"], result["fp"], result["fn"]) == (1, 1, 0)


def test_matching_requires_location_and_cwe():
    seeds = [{"id": "s", "file": "a.py", "line": 10, "cwe": 89}]
    result = evaluate([finding(14), finding(code=79)], seeds)
    assert result["tp"] == 0 and result["fn"] == 1


def test_high_and_missing_votes_are_retained():
    assert keep_consensus(finding(severity="high"), ["false_positive"] * 3)
    assert keep_consensus(finding(), ["false_positive"] * 2)
    assert keep_consensus(finding(), ["false_positive", "uncertain", "false_positive"])
    assert not keep_consensus(finding(), ["false_positive"] * 3)


def test_unknown_output_is_retained():
    assert keep_single({"verdict": "uncertain"})
    assert keep_single({"verdict": "malformed"})
