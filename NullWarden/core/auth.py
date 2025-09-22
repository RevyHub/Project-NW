from __future__ import annotations

import hashlib
import os
import sys
from datetime import datetime
from typing import Literal, Optional


OPERATOR_HASH = "a47cf51747f0edaca5eb0a80c9666391150818c9aca3efb61fa90d8e2d5a4f4c"
BASE_HASH = "1b2212b6183a91097fe78b5a0160e9f1d0377eb8d6eb20a7bf5fd652f6061e5b"
LOG_FILE = "login_attempts.txt"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def log_attempt(success: bool, role: str = "UNKNOWN") -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    device_name = os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or "unknown-host"
    username = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown-user"
    status = "SUCCESS" if success else "FAILED"
    with open(LOG_FILE, "a", encoding="utf-8") as file_handle:
        file_handle.write(f"{timestamp} | {device_name} | {username} | {status} | {role}\n")


def check_password(prompt: str = "Enter password to run the script: ") -> Optional[Literal["Operator", "BaseUser"]]:
    user_input = read_password_masked(prompt)
    entered_hash = _sha256(user_input)
    if entered_hash == OPERATOR_HASH:
        log_attempt(True, "Operator")
        return "Operator"
    if entered_hash == BASE_HASH:
        log_attempt(True, "BaseUser")
        return "BaseUser"
    log_attempt(False, "UNKNOWN")
    return None


def read_password_masked(prompt: str = "Password: ") -> str:
    """Read a password with asterisk masking and backspace support.

    Works on Windows (msvcrt) and Unix (termios/tty).
    """
    if os.name == "nt":
        try:
            import msvcrt
        except Exception:
            return input(prompt)

        sys.stdout.write(prompt)
        sys.stdout.flush()
        chars: list[str] = []
        while True:
            ch = msvcrt.getwch()
            if ch in ("\r", "\n"):
                sys.stdout.write("\n")
                break
            if ch == "\003":  # Ctrl+C
                raise KeyboardInterrupt
            if ch in ("\b", "\x7f"):
                if chars:
                    chars.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
                continue
            # Ignore non-printable control chars
            if ord(ch) < 32:
                continue
            chars.append(ch)
            sys.stdout.write("*")
            sys.stdout.flush()
        return "".join(chars)

    try:
        import termios
        import tty
    except Exception:
        return input(prompt)

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        sys.stdout.write(prompt)
        sys.stdout.flush()
        chars: list[str] = []
        while True:
            ch = sys.stdin.read(1)
            if ch in ("\r", "\n"):
                sys.stdout.write("\n")
                break
            if ch == "\x03":  # Ctrl+C
                raise KeyboardInterrupt
            if ch in ("\x08", "\x7f"):  # Backspace/Delete
                if chars:
                    chars.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
                continue
            if ord(ch) < 32:
                continue
            chars.append(ch)
            sys.stdout.write("*")
            sys.stdout.flush()
        return "".join(chars)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


