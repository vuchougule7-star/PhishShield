# PhishShield – Phishing Email Analysis & Awareness Tool

## About the Project

PhishShield is a web-based phishing email analysis tool developed as part of the COSMOS JEC Cybersecurity Project.

Phishing emails are commonly used to trick people into sharing personal information, clicking suspicious links, or interacting with fraudulent messages. Identifying such emails can be difficult, especially when they look similar to genuine messages.

PhishShield analyses email content and identifies suspicious indicators that may suggest a phishing attempt. It provides a risk score along with explanations of the detected indicators, helping users understand why an email may be unsafe.

The application also includes a phishing awareness quiz to help users improve their understanding of common email-based threats.

## Features

- **Email Analysis:** Analyse pasted email content or upload `.eml` and `.txt` files.
- **Sender Analysis:** Identify possible mismatches between sender information and display names.
- **Suspicious URL Detection:** Identify potentially suspicious links and URL patterns.
- **Urgency Detection:** Detect language commonly used to create pressure or urgency.
- **Risk Assessment:** Generate a risk score based on detected indicators.
- **Detailed Results:** Display suspicious indicators with supporting evidence and explanations.
- **Awareness Quiz:** Test knowledge of phishing emails through interactive questions.
- **Report Export:** Export analysis results in JSON format.
- **Local Processing:** Analyse email content locally without sending it to an external analysis service.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend and email analysis |
| HTML | Web page structure |
| CSS | Interface styling |
| JavaScript | Frontend functionality and API communication |
| JSON | Data exchange and report export |
| Python unittest | Automated testing |

## Project Structure

```text
PhishShield/
│
├── samples/
│   ├── legitimate_sample.eml
│   ├── suspicious_sample.eml
│   ├── suspicious_sample_2.eml
│   └── missing_headers_sample.txt
│
├── tests/
│   ├── test_analyzer.py
│   └── test_server.py
│
├── app.py
├── analyzer.py
├── index.html
├── requirements.txt
├── README.md
├── TEST_RESULTS.txt
└── .gitignore
```

## Requirements

- Python 3.10 or later
- Visual Studio Code or another code editor
- A modern web browser

## Installation and Setup

**1. Clone the repository**

```bash
git clone https://github.com/YOUR-USERNAME/PhishShield.git
```

**2. Open the project folder**

```bash
cd PhishShield
```

**3. Run the application**

```bash
python app.py
```

The local server starts and automatically opens the application in the default web browser.

If the browser does not open automatically, visit:

```text
http://127.0.0.1:8000
```

## How to Use

1. Open PhishShield AI in your browser.
2. Paste an email or upload a supported `.eml` or `.txt` file.
3. Start the email analysis.
4. Review the risk score and detected indicators.
5. Read the evidence and explanations provided for each warning.
6. Use the awareness quiz to test your knowledge of phishing emails.
7. Export the analysis report in JSON format if required.

## Running Tests

The project includes automated tests for email analysis and server functionality.

Run the tests using:

```bash
python -m unittest discover -s tests -v
```

The tests cover email parsing, indicator detection, input validation, malformed email handling and server responses.

## Sample Emails

The `samples` directory contains example emails used for testing:

- `legitimate_sample.eml` – A legitimate email example.
- `suspicious_sample.eml` – An email containing suspicious indicators.
- `suspicious_sample_2.eml` – Another suspicious email example.
- `missing_headers_sample.txt` – An email example with incomplete header information.

These samples are provided for testing and demonstration purposes.

## Security and Privacy

- Email analysis is performed locally.
- Submitted email content is not stored by the application.
- Suspicious URLs are displayed as text and are not automatically opened or fetched.
- Sample emails are used instead of private or confidential messages.
- The application is intended for awareness and preliminary analysis.

## Limitations

- The detection system uses predefined analysis rules and does not guarantee detection of every phishing email.
- Legitimate emails may sometimes contain suspicious indicators.
- Missing email headers do not automatically indicate phishing.
- The risk score is an assessment indicator, not a confirmed probability of an email being malicious.
- Users should independently verify suspicious messages before taking action.

## Conclusion

PhishShield AI provides a simple way to examine email content, identify suspicious indicators and understand common phishing techniques. It combines email analysis with an awareness quiz to encourage safer email practices.

## Project Information

**Project:** PhishShield – Phishing Email Analysis & Awareness Tool  
**Category:** Cybersecurity  
**Organisation:** COSMOS JEC  
**Project Option:** CS-03
