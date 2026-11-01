from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyzer import analyse_email, _extract_urls  # noqa: E402

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def read_sample(name: str) -> str:
    return (SAMPLES / name).read_text(encoding="utf-8")


def test_suspicious_sample_reports_multiple_indicators():
    result = analyse_email(read_sample("suspicious_sample.eml"), "suspicious_sample.eml")
    codes = {item["code"] for item in result["indicators"]}
    assert result["score"] >= 50
    assert result["risk_level"] in {"High", "Very high"}
    assert {"display_name_mismatch", "shortener_url", "urgency_language", "credential_request", "auth_failure"} <= codes
    assert result["urls"] == ["http://bit.ly/demo-check"]


def test_legitimate_sample_does_not_trigger_phishing_rules():
    result = analyse_email(read_sample("legitimate_sample.eml"))
    positive_codes = {item["code"] for item in result["indicators"] if item["points"] > 0}
    assert positive_codes == set()
    assert result["score"] == 0
    assert result["risk_level"] == "Low"


def test_missing_headers_are_informational_not_a_penalty():
    result = analyse_email(read_sample("missing_headers_sample.txt"))
    codes = {item["code"] for item in result["indicators"]}
    assert "headers_missing" in codes
    assert "auth_unavailable" in codes
    assert result["score"] == 0


def test_malformed_or_empty_input_is_rejected():
    with pytest.raises(ValueError, match="empty"):
        analyse_email("  \n\t")


def test_large_input_is_rejected():
    with pytest.raises(ValueError, match="1 MB"):
        analyse_email("x" * 1_000_001)


def test_url_extraction_deduplicates_and_strips_punctuation():
    urls = _extract_urls("Visit https://example.test/path, then https://example.test/path.")
    assert urls == ["https://example.test/path"]


def test_urls_are_only_extracted_as_text():
    result = analyse_email("Subject: Demo\n\nSee https://example.test/a")
    assert result["urls"] == ["https://example.test/a"]
    # This project has no network client; URL parsing is a local string operation.
    assert result["url_note"].startswith("1 link(s) extracted")


def test_score_is_capped_at_100():
    text = ("From: PayPal Support <x@bad.test>\nSubject: urgent account suspended\n\n"
            "verify your account password OTP immediately http://bit.ly/x http://192.168.1.4/login")
    result = analyse_email(text)
    assert result["score"] <= 100


def test_malformed_email_is_handled_without_crashing():
    result = analyse_email("From this is not a valid header\n%%%\n\x00\ufffd")
    codes = {item["code"] for item in result["indicators"]}
    assert "headers_missing" in codes
    assert result["risk_level"] == "Low"


def test_second_suspicious_sample_triggers_ip_and_sender_signals():
    result = analyse_email(read_sample("suspicious_sample_2.eml"))
    codes = {item["code"] for item in result["indicators"]}
    assert result["score"] >= 50
    assert {"display_name_mismatch", "ip_url", "urgency_language", "credential_request"} <= codes
