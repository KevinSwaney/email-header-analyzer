# email-header-analyzer

A small offline tool that parses raw email headers and flags phishing indicators. Paste headers in, get red/yellow/green findings out. Nothing leaves your machine.

This is the Python port of the header analyzer on my [threat-check page](https://kevintswaney.com/threat-check.html) — same checks, usable from the terminal or in scripts.

## What it checks

- **Reply-To / Return-Path mismatch** — replies going somewhere other than the visible sender's domain
- **SPF / DKIM / DMARC** — authentication results from the receiving server
- **Display-name impersonation** — e.g. `"PayPal Support"` writing from a free mailbox
- **Date sanity** — future dates or very old messages resurfacing
- **Received hop count** — unusually short delivery paths

## Usage

```bash
python header_analyzer.py headers.txt
# or
cat headers.txt | python header_analyzer.py
```

**Getting headers:**
- Gmail: open the message, click the three dots, "Show original", copy everything
- Outlook: File > Properties, copy "Internet headers"

## Example output

```
============================================================
EMAIL HEADER ANALYSIS
============================================================
From           "PayPal Support" <random123@gmail.com>
Reply-To       (none)
Return-Path    (none)
Subject        Action required: verify your account
Date           Sat, 11 Oct 2026 09:14:00 -0400
Message-ID     (none)
Received hops  1
------------------------------------------------------------
FINDINGS
------------------------------------------------------------
[ALERT] Display-name impersonation
       The display name says "PayPal Support" but the address is a free mailbox. Real companies do not email from free accounts.

[CAUTION] Unusually short delivery path
       Only 1 mail hop(s) recorded. External mail normally passes through several.
```

## Notes

- No single flag proves phishing. A clean report is not a clean bill of health — when in doubt, verify through a second channel.
- Requires Python 3.6+. No dependencies.

## Author

Kevin Swaney — Principal Cybersecurity Engineer. More at [kevintswaney.com](https://kevintswaney.com).
