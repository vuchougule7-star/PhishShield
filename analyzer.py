"""Local, explainable phishing-email analysis for the PhishShield project.

This module never opens URLs, downloads remote content, or executes attachments.
It uses only Python's standard library.
"""
from __future__ import annotations

import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Any
from urllib.parse import urlsplit

MAX_EMAIL_CHARS = 1_000_000

URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")
TRAILING_URL_PUNCTUATION = ".,;:!?)]}"

URGENCY_TERMS = (
    "urgent", "immediately", "act now", "final warning", "account suspended",
    "account will be closed", "within 24 hours", "verify now", "action required",
    "unusual activity", "limited time",
)
CREDENTIAL_TERMS = (
    "password", "one-time password", "one time password", "otp", "pin",
    "bank details", "card number", "security code", "login credentials",
    "verify your account", "confirm your identity", "payment details",
)

# This is a deliberately small teaching list, not a complete brand/domain database.
BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "google": {"google.com", "google.co.in"},
    "microsoft": {"microsoft.com", "microsoftonline.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in"},
    "netflix": {"netflix.com"},
}
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "shorturl.at",
    "ow.ly", "rb.gy", "buff.ly",
}

RISK_LEVELS = (
    (75, "Very high", "#ef4444"),
    (50, "High", "#f97316"),
    (25, "Moderate", "#eab308"),
    (0, "Low", "#22c55e"),
)


def _add_indicator(items: list[dict[str, Any]], *, code: str, title: str,
                   severity: str, points: int, evidence: str,
                   explanation: str, advice: str) -> None:
    items.append({
        "code": code,
        "title": title,
        "severity": severity,
        "points": points,
        "evidence": evidence[:500],
        "explanation": explanation,
        "advice": advice,
    })


def _decode_body(message: Any) -> str:
    """Extract readable text parts only; attachments are not opened or executed."""
    chunks: list[str] = []
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_disposition() == "attachment":
                continue
            if part.get_content_type() == "text/plain":
                try:
                    content = part.get_content()
                    if isinstance(content, str):
                        chunks.append(content)
                except (LookupError, UnicodeError, TypeError):
                    continue
    else:
        try:
            content = message.get_content()
            if isinstance(content, str) and message.get_content_type() in {"text/plain", "text/html"}:
                # For HTML-only mail, tags are left as text; no HTML is rendered in the UI.
                chunks.append(content)
        except (LookupError, UnicodeError, TypeError):
            pass
    return "\n".join(chunks).strip()


def _normalise_domain(address: str) -> str:
    _, parsed = parseaddr(address)
    if "@" not in parsed:
        return ""
    return parsed.rsplit("@", 1)[1].strip().lower().rstrip(".")


def _domain_matches(domain: str, allowed: set[str]) -> bool:
    return any(domain == candidate or domain.endswith("." + candidate) for candidate in allowed)


def _extract_urls(text: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for match in URL_RE.findall(text):
        candidate = match.rstrip(TRAILING_URL_PUNCTUATION)
        if candidate.lower().startswith("www."):
            candidate = "http://" + candidate
        if candidate not in seen:
            seen.add(candidate)
            found.append(candidate)
    return found


def _url_host(url: str) -> tuple[str, str]:
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        return host, parsed.netloc
    except ValueError:
        return "", ""


def _is_ip_address(host: str) -> bool:
    return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host))


def _risk_level(score: int) -> tuple[str, str]:
    for threshold, label, color in RISK_LEVELS:
        if score >= threshold:
            return label, color
    return "Low", "#22c55e"


def analyse_email(raw_email: str, filename: str | None = None) -> dict[str, Any]:
    """Parse and score an email sample. Input is never persisted by this function."""
    if not isinstance(raw_email, str):
        raise ValueError("Email content must be text.")
    if not raw_email.strip():
        raise ValueError("The email is empty. Paste an email or upload a .eml/.txt file.")
    if len(raw_email) > MAX_EMAIL_CHARS:
        raise ValueError("The email is larger than the 1 MB text limit.")

    raw_bytes = raw_email.encode("utf-8", errors="replace")
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    except Exception as exc:  # parser errors are converted to a safe validation message
        raise ValueError("The email could not be parsed. Check the file and try again.") from exc

    headers = {key.lower(): str(value) for key, value in message.items()}
    body = _decode_body(message)
    sender_header = headers.get("from", "")
    sender_name, sender_address = parseaddr(sender_header)
    sender_domain = _normalise_domain(sender_header)
    subject = headers.get("subject", "(No subject supplied)")
    to_value = headers.get("to", "Not provided")

    indicators: list[dict[str, Any]] = []
    available_headers = bool(headers)
    if not available_headers:
        _add_indicator(
            indicators, code="headers_missing", title="Email headers are unavailable",
            severity="info", points=0, evidence="No standard email headers were found.",
            explanation="Without headers, sender and authentication details cannot be verified. This is missing evidence, not proof of phishing.",
            advice="Use a complete .eml sample when possible. Verify the sender through a separate trusted channel.",
        )

    if sender_header:
        lowered_name = sender_name.lower()
        for brand, allowed_domains in BRAND_DOMAINS.items():
            if brand in lowered_name and sender_domain and not _domain_matches(sender_domain, allowed_domains):
                _add_indicator(
                    indicators, code="display_name_mismatch", title="Sender display name may imitate a known brand",
                    severity="high", points=25,
                    evidence=f"Display name: {sender_name or '(none)'} | Sender domain: {sender_domain}",
                    explanation=f"The display name mentions {brand.title()}, but the sender domain is not in this project's small reference list for that brand. Display names can be chosen by senders.",
                    advice="Do not use the message's links. Open the organisation's official app or type its known website address yourself.",
                )
                break

    # URL checks are local string inspections only. No DNS lookup or HTTP request occurs.
    combined_text = subject + "\n" + body
    urls = _extract_urls(combined_text)
    url_findings: list[str] = []
    for url in urls:
        host, netloc = _url_host(url)
        if not host:
            continue
        if host in SHORTENER_DOMAINS:
            url_findings.append(f"Shortened link host: {host}")
        if _is_ip_address(host):
            url_findings.append(f"Link uses an IP address instead of a domain: {host}")
        if "@" in netloc:
            url_findings.append(f"Link contains user-info before the host: {url[:160]}")
        if "xn--" in host:
            url_findings.append(f"Link contains an internationalised/punycode host: {host}")

    # Add separate, explainable findings so each URL signal has clear evidence.
    for code, title, match_text, points, explanation in (
        ("shortener_url", "URL shortener detected", "Shortened link host", 15,
         "Shortened URLs hide the final destination until independently expanded. This alone does not prove a link is malicious."),
        ("ip_url", "Link uses an IP address", "Link uses an IP address", 25,
         "A URL that uses a raw IP address can be harder to associate with a legitimate organisation."),
        ("userinfo_url", "URL contains misleading user-info syntax", "Link contains user-info", 25,
         "Some URLs place text before an @ symbol in the authority section, which can make the actual host less obvious."),
        ("punycode_url", "Internationalised/punycode domain detected", "punycode host", 20,
         "Punycode can represent international characters in domain names. Similar-looking characters may be used to imitate another domain."),
    ):
        matches = [item for item in url_findings if match_text.lower() in item.lower()]
        if matches:
            _add_indicator(
                indicators, code=code, title=title, severity="high" if points >= 20 else "medium",
                points=points, evidence="; ".join(matches[:3]), explanation=explanation,
                advice="Treat the link as untrusted. Verify the destination independently; this tool never opens it.",
            )

    lower_text = (subject + "\n" + body).lower()
    urgency_hits = [term for term in URGENCY_TERMS if term in lower_text]
    if urgency_hits:
        _add_indicator(
            indicators, code="urgency_language", title="Urgency or pressure language detected",
            severity="low", points=10, evidence=", ".join(urgency_hits[:6]),
            explanation="The message uses language that pressures the reader to act quickly. Legitimate notices can also use urgent wording.",
            advice="Pause before acting. Check the request using the organisation's official app, website, or phone number.",
        )

    credential_hits = [term for term in CREDENTIAL_TERMS if term in lower_text]
    if credential_hits:
        _add_indicator(
            indicators, code="credential_request", title="Sensitive information or account-verification language detected",
            severity="high", points=20, evidence=", ".join(credential_hits[:6]),
            explanation="The message refers to credentials, account verification, or payment information. This can be used in phishing, but context matters.",
            advice="Never share passwords, OTPs, PINs, or card security codes in response to an email.",
        )

    auth_values = " ".join(
        value for key, value in headers.items()
        if key in {"authentication-results", "received-spf"}
    ).lower()
    failed_auth = []
    for mechanism in ("spf", "dkim", "dmarc"):
        if re.search(rf"\b{mechanism}\s*[=:]\s*fail\b", auth_values):
            failed_auth.append(mechanism.upper())
    if failed_auth:
        _add_indicator(
            indicators, code="auth_failure", title="Email authentication failure reported",
            severity="high", points=25,
            evidence="Failed result(s): " + ", ".join(failed_auth),
            explanation="An available authentication-results header reports a failure. Headers can be incomplete or untrusted in copied samples, so this signal needs context.",
            advice="Treat the sender as unverified and confirm the message through a separate trusted channel.",
        )
    elif not auth_values:
        _add_indicator(
            indicators, code="auth_unavailable", title="Authentication results not available",
            severity="info", points=0,
            evidence="No Authentication-Results or Received-SPF header was supplied.",
            explanation="The sample does not contain authentication results. Missing results are unavailable evidence, not a phishing verdict.",
            advice="Use a full .eml export from a trusted mail client if authentication details are needed.",
        )

    score = min(100, sum(item["points"] for item in indicators))
    level, color = _risk_level(score)
    if not urls:
        url_note = "No web links were found in the supplied subject/body text."
    else:
        url_note = f"{len(urls)} link(s) extracted. They are displayed as plain text and were not opened or checked online."

    # A pasted body without headers is still analysable, but the UI makes the limitation visible.
    return {
        "filename": filename or "Pasted email",
        "subject": subject,
        "sender_name": sender_name or "Not available",
        "sender_address": sender_address or "Not available",
        "sender_domain": sender_domain or "Not available",
        "recipient": to_value,
        "date": headers.get("date", "Not provided"),
        "reply_to": headers.get("reply-to", "Not provided"),
        "headers_available": available_headers,
        "body_preview": body[:600],
        "urls": urls,
        "url_note": url_note,
        "indicators": indicators,
        "score": score,
        "risk_level": level,
        "risk_color": color,
        "indicator_count": len([item for item in indicators if item["points"] > 0]),
        "disclaimer": "This is a rule-based teaching aid, not a definitive verdict. A low score does not prove an email is safe.",
    }
