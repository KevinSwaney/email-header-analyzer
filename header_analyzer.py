#!/usr/bin/env python3
"""
email-header-analyzer: parse raw email headers and flag phishing indicators.

Reads headers from a file or stdin, extracts the key fields, and reports
red/yellow/green findings for the checks that catch most phishing:

  - Reply-To / Return-Path domain mismatch vs From
  - SPF / DKIM / DMARC authentication results
  - Display-name impersonation (e.g. "PayPal Support" from a free mailbox)
  - Date sanity (future dates, very old messages)
  - Received hop count anomalies

Nothing leaves your machine: this is fully offline analysis.

Usage:
    python header_analyzer.py headers.txt
    cat headers.txt | python header_analyzer.py

In Gmail: open the message, click the three dots, "Show original", copy all.
In Outlook: File > Properties, copy "Internet headers".
"""

import re
import sys
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime


def unfold(raw):
    lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out = []
    for line in lines:
        if line[:1].isspace() and out:
            out[-1] += " " + line.strip()
        else:
            out.append(line)
    return out


def parse_headers(raw):
    headers = {}
    for line in unfold(raw):
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if not key:
            continue
        if key in headers:
            headers[key] += " | " + value
        else:
            headers[key] = value
    return headers


def domain_of(addr):
    m = re.search(r"@([\w.\-]+)", addr or "")
    return m.group(1).lower() if m else ""


def auth_val(authres, name):
    m = re.search(rf"{name}\s*=\s*([a-zA-Z]+)", authres or "", re.I)
    return m.group(1).lower() if m else None


GREEN, YELLOW, RED = "PASS", "CAUTION", "ALERT"


def check(headers, raw):
    findings = []

    def add(level, title, detail):
        findings.append((level, title, detail))

    from_ = headers.get("from", "")
    reply_to = headers.get("reply-to", "")
    ret_path = headers.get("return-path", "")
    authres = (headers.get("authentication-results", "")).split(" | ")[0]
    subject = headers.get("subject", "")
    date = headers.get("date", "")
    msgid = headers.get("message-id", "")
    hops = len(re.findall(r"^received:", raw, re.M | re.I))

    from_dom = domain_of(from_)
    reply_dom = domain_of(reply_to)
    ret_dom = domain_of(ret_path)

    fields = [
        ("From", from_ or "(missing)"),
        ("Reply-To", reply_to or "(none)"),
        ("Return-Path", ret_path or "(none)"),
        ("Subject", subject or "(none)"),
        ("Date", date or "(none)"),
        ("Message-ID", msgid or "(none)"),
        ("Received hops", str(hops)),
    ]

    # Reply-To mismatch
    if reply_to and reply_dom and from_dom and reply_dom != from_dom:
        add(RED, "Reply-To goes to a different domain",
            f"Replies would go to {reply_dom} instead of {from_dom}. "
            "Classic phishing sign: the visible sender is not who gets your reply.")
    elif reply_to:
        add(GREEN, "Reply-To matches sender", "Replies go back to the sender's domain.")

    # Return-Path mismatch
    if ret_path and ret_dom and from_dom and ret_dom != from_dom:
        add(YELLOW, "Return-Path differs from sender",
            f"Bounce address is {ret_dom} while the sender claims {from_dom}. "
            "Legitimate for mailing lists, suspicious otherwise.")

    # SPF / DKIM / DMARC
    spf = auth_val(authres, "spf")
    if spf == "pass":
        add(GREEN, "SPF passed", "The sending server is authorized for this domain.")
    elif spf == "fail":
        add(RED, "SPF failed", "The sending server is NOT authorized to send for this domain. Strong spoofing indicator.")
    elif spf:
        add(YELLOW, f"SPF {spf}", "SPF did not cleanly pass. Treat with caution.")
    else:
        add(YELLOW, "No SPF result found", "No SPF verdict in the headers. Authentication may not have been checked.")

    dkim = auth_val(authres, "dkim")
    if dkim == "pass":
        add(GREEN, "DKIM passed", "The message signature verified: content was not altered in transit.")
    elif dkim == "fail":
        add(RED, "DKIM failed", "The cryptographic signature did not verify. The message may have been tampered with or forged.")
    else:
        add(YELLOW, "No DKIM signature", "The sender did not sign this message. Absence is a weak negative.")

    dmarc = auth_val(authres, "dmarc")
    if dmarc == "pass":
        add(GREEN, "DMARC passed", "Domain alignment verified.")
    elif dmarc == "fail":
        add(RED, "DMARC failed", "The message failed the domain owner's published policy. High spoofing risk.")
    elif dmarc == "none":
        add(YELLOW, "No DMARC policy", "The sender's domain publishes no DMARC policy, so receivers cannot enforce authentication.")

    # Display-name impersonation
    disp = (re.match(r'^"([^"]+)"', from_) or [None, ""])[1]
    freemail = re.search(r"@(gmail|yahoo|hotmail|outlook|aol|protonmail|icloud)\.", from_, re.I)
    if disp and freemail and re.search(r"\b(bank|support|security|service|billing|account|paypal|amazon|apple|microsoft)\b", disp, re.I):
        add(RED, "Display-name impersonation",
            f'The display name says "{disp}" but the address is a free mailbox. '
            "Real companies do not email from free accounts.")

    # Date sanity
    if date:
        try:
            d = parsedate_to_datetime(date)
            now = datetime.now(timezone.utc)
            delta = (now - d).total_seconds()
            if delta < -86400:
                add(YELLOW, "Date is in the future", "The message date is ahead of today, which is unusual.")
            elif delta > 30 * 86400:
                add(YELLOW, "Message is over 30 days old", "Old messages resurfacing can indicate a forwarded or replayed phish.")
        except (ValueError, TypeError):
            add(YELLOW, "Unparseable date", f'Could not parse the Date header: "{date}".')

    # Hop count
    if 0 < hops < 2:
        add(YELLOW, "Unusually short delivery path",
            f"Only {hops} mail hop(s) recorded. External mail normally passes through several.")

    return fields, findings


def main():
    if len(sys.argv) > 1:
        with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
            raw = f.read()
    else:
        raw = sys.stdin.read()

    if not raw.strip():
        print("No input. Provide a headers file or pipe headers via stdin.")
        sys.exit(1)

    headers = parse_headers(raw)
    fields, findings = check(headers, raw)

    print("=" * 60)
    print("EMAIL HEADER ANALYSIS")
    print("=" * 60)
    for name, value in fields:
        print(f"{name:14} {value}")
    print("-" * 60)
    print("FINDINGS")
    print("-" * 60)
    if not findings:
        print("No issues flagged. Stay skeptical anyway.")
    for level, title, detail in findings:
        print(f"[{level}] {title}\n       {detail}\n")


if __name__ == "__main__":
    main()
