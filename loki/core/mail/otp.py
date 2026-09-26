"""
Gmail IMAP OTP reader.
Polls INBOX for newest unseen email and extracts OTP via regex.

Setup:
1. Enable IMAP in Gmail Settings → Forwarding and POP/IMAP
2. Generate App Password: myaccount.google.com/apppasswords
3. Use App Password (NOT your real password) here
"""
from __future__ import annotations
import email
import imaplib
import re
import time

# Common OTP patterns
OTP_PATTERNS = [
    r'\b(\d{6})\b',           # 6-digit OTP (most common)
    r'\b(\d{4})\b',           # 4-digit PIN
    r'\b(\d{8})\b',           # 8-digit OTP
    r'code[:\s]+(\d{4,8})',   # "code: 123456"
    r'OTP[:\s]+(\d{4,8})',    # "OTP: 123456"
    r'verification[:\s]+(\d{4,8})',
    r'(?:is|:)\s*(\d{4,8})',  # "Your code is 123456"
]

IMAP_HOST = "imap.gmail.com"
IMAP_PORT = 993


def _extract_otp(text: str) -> str | None:
    for pattern in OTP_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            return matches[0]
    return None


def _get_email_body(msg: email.message.Message) -> str:
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct in ("text/plain", "text/html"):
                try:
                    body += part.get_payload(decode=True).decode("utf-8", errors="ignore")
                except Exception:
                    pass
    else:
        try:
            body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
        except Exception:
            pass
    return body


def wait_for_otp(
    gmail_user: str,
    app_password: str,
    max_wait: int = 90,
    poll_interval: int = 3,
    subject_filter: str | None = None,
) -> str | None:
    """
    Connect to Gmail via IMAP and wait for OTP email.

    Args:
        gmail_user: Gmail address e.g. user@gmail.com
        app_password: Gmail App Password (NOT your real password)
        max_wait: Max seconds to wait (default 90)
        poll_interval: Seconds between checks (default 3)
        subject_filter: Optional keyword to filter by subject

    Returns:
        OTP string if found, None if timeout
    """
    deadline = time.time() + max_wait

    try:
        mail = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
        mail.login(gmail_user, app_password)
        mail.select("INBOX")
    except imaplib.IMAP4.error as e:
        raise ConnectionError(f"Gmail IMAP login failed: {e}\n"
                              "Make sure you're using an App Password, not your real password.\n"
                              "Generate one at: myaccount.google.com/apppasswords")

    try:
        while time.time() < deadline:
            mail.check()

            # Search for unseen emails
            search_criteria = "UNSEEN"
            if subject_filter:
                search_criteria = f'UNSEEN SUBJECT "{subject_filter}"'

            _, data = mail.search(None, search_criteria)
            if data and data[0]:
                ids = data[0].split()
                # Check newest first
                for msg_id in reversed(ids[-5:]):  # Check last 5 unseen
                    try:
                        _, msg_data = mail.fetch(msg_id, "(RFC822)")
                        msg = email.message_from_bytes(msg_data[0][1])
                        body = _get_email_body(msg)
                        otp = _extract_otp(body)
                        if otp:
                            # Mark as read
                            mail.store(msg_id, "+FLAGS", "\\Seen")
                            return otp
                    except Exception:
                        continue

            time.sleep(poll_interval)

    finally:
        try:
            mail.logout()
        except Exception:
            pass

    return None


def save_gmail_config(user: str, app_password: str, config_path: str = "/tmp/loki_gmail.json") -> None:
    """Save Gmail config for reuse."""
    import json
    from pathlib import Path
    Path(config_path).write_text(json.dumps({
        "user": user,
        "app_password": app_password,
    }))


def load_gmail_config(config_path: str = "/tmp/loki_gmail.json") -> dict | None:
    """Load saved Gmail config."""
    import json
    from pathlib import Path
    p = Path(config_path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None