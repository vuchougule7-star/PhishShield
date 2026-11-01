# PhishShield — Phishing Email Analysis & Awareness Tool (CS-03)

A local, rule-based student project for analysing pasted email text or sanitised `.eml` / `.txt` samples. It extracts available sender and header information, identifies selected suspicious indicators, explains its evidence and scoring, and provides an awareness quiz.

> **Important:** Despite the project name, the current detector is an explainable, deterministic rule engine — not a trained AI model and not an OpenAI API integration. Scores are heuristic risk indicators, not probabilities or definitive verdicts. A low score does not prove an email is safe.

## Features

- Paste email content or import a `.eml` / `.txt` file (1 MB maximum).
- Parse headers and readable text locally using Python's standard `email` package.
- Check for selected sender display-name mismatches, URL shorteners, IP-address URLs, user-info URL syntax, punycode hosts, urgency language, sensitive-information requests, and SPF/DKIM/DMARC failures when supplied in authentication headers.
- Show each indicator's evidence, explanation, severity, points, and practical advice.
- Display extracted URLs as plain text. The app never opens them, performs DNS lookups, fetches remote pages, downloads content, or executes attachments.
- Show missing authentication/header information as unavailable evidence, not automatic proof of phishing.
- Provide an awareness quiz with answer feedback and reset/retry.
- Export an analysis result as JSON.
- Keep analysis in memory only; no database, telemetry, or email-content logging is used.
- Mobile-friendly dashboard interface.

## Requirements

- Python 3.10 or newer.
- A modern browser.
- No runtime third-party packages are required. `pytest` is optional for tests.

## Run on Windows (VS Code)

1. Extract this project folder.
2. Open the `PhishShield_AI` folder in VS Code.
3. Open **Terminal → New Terminal**.
4. Run:

   ```powershell
   python --version
   python app.py
   ```

5. Open `http://127.0.0.1:8000` in your browser.
6. To stop the server, return to the terminal and press `Ctrl+C`.

If your computer uses the Python launcher instead, run `py app.py`.

## Run tests

Install the optional test dependency:

```powershell
python -m pip install -r requirements.txt
```

Run the automated test suite from the project folder:

```powershell
python -m pytest -q
```

The tests cover suspicious and benign examples, missing headers, empty and oversized input, URL extraction, score capping, and the local HTTP API.

## Sample data

- `samples/suspicious_sample.eml` — synthetic suspicious sample with a brand display-name mismatch, urgency, short link, credential language, and authentication failures.
- `samples/suspicious_sample_2.eml` — synthetic suspicious sample with a brand display-name mismatch and an IP-address URL.
- `samples/legitimate_sample.eml` — synthetic benign teaching sample.
- `samples/missing_headers_sample.txt` — body-only sample to demonstrate unavailable header information.

All sample names, domains, and content are synthetic; they are not copied from real private email. The `.test` domain is reserved for testing.

## Scoring rules (current version)

| Indicator | Points |
|---|---:|
| Sender display name imitates a small listed brand but sender domain differs | 25 |
| URL uses a raw IP address | 25 |
| URL contains user-info syntax | 25 |
| SPF, DKIM, or DMARC failure is present in supplied auth headers | 25 |
| Sensitive-information / account-verification language | 20 |
| Punycode host | 20 |
| URL shortener | 15 |
| Urgency / pressure language | 10 |

The score is the sum of triggered rules, capped at 100:

- 0–24: Low
- 25–49: Moderate
- 50–74: High
- 75–100: Very high

Rules can overlap. For example, one email may contain both urgency and credential-request language. These weights are initial teaching heuristics and should be evaluated against more benign and suspicious samples before making real-world decisions.

## Project structure

```text
PhishShield_AI/
├── app.py
├── analyzer.py
├── index.html
├── requirements.txt
├── README.md
├── samples/
│   ├── suspicious_sample.eml
│   ├── legitimate_sample.eml
│   └── missing_headers_sample.txt
└── tests/
    ├── test_analyzer.py
    └── test_server.py
```

## Privacy and safe-use notes

- Run the server on `127.0.0.1` only; do not expose it to a public network.
- Use synthetic, sanitised, public, or explicitly authorised samples only.
- Do not paste personal, confidential, or real account information.
- Submitted email content is processed in memory by the local server and is not written to files or logs by this project. Exported reports are downloaded only when the user clicks the export button.
- Links are never opened, and remote resources or attachments are never retrieved or executed.
- Authentication results in copied headers may be missing or untrusted. A copied header alone is not proof that the message passed or failed authentication.
- The small brand-domain list is incomplete. Legitimate senders may use third-party email services, and attackers can imitate brands not included in the list.
- HTML email content is not rendered as HTML; only text is analysed. This may create false positives or miss some context.
- The tool does not verify sender identity, determine whether a destination is malicious, or guarantee detection of phishing.

## Demonstration checklist

1. Analyse `samples/legitimate_sample.eml` and explain why the configured rules produce a low score.
2. Analyse `samples/suspicious_sample.eml` and explain the evidence for each triggered indicator.
3. Analyse `samples/suspicious_sample_2.eml` and explain the IP-address URL and sender signals.
4. Analyse `samples/missing_headers_sample.txt` and show that absent headers are treated as unavailable evidence.
5. Try an empty input and show the validation message.
6. Show that extracted links are plain text and are not opened.
7. Complete the awareness quiz, review feedback, and reset it.
8. Export a JSON report and explain that the score is a heuristic, not a probability.

## Individual contribution / report template

For the event report, document the work actually completed by each team member. Suggested headings:

1. Problem statement and objectives
2. System architecture and workflow
3. Detection rules and scoring methodology
4. Test cases and results (benign, suspicious, missing-header, malformed/empty)
5. Safe handling and privacy measures
6. Limitations and false-positive analysis
7. Individual contributions
8. Future improvements
