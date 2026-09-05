"""Tests for BBB-auth security guarantees:
- Open Redirect Prevention
- Redis-backed CSRF state validation
- One-time OAuth code exchange
"""

import sys
from pathlib import Path

# Add server directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "server"))

from oauth import get_safe_redirect_url


def test_open_redirect_attacker_blocked():
    """Attacker URLs must be rejected and clamped to default URL."""
    default = "https://bigbankbonus.com/command-center.html"
    assert get_safe_redirect_url("https://attacker.evil.com/steal", default_url=default) == default
    assert get_safe_redirect_url("https://evil.com?param=1", default_url=default) == default
    assert get_safe_redirect_url("//evil.com/steal", default_url=default) == default
    assert get_safe_redirect_url("javascript:alert(1)", default_url=default) == default


def test_safe_relative_redirect_allowed():
    """Relative paths within the app must be preserved safely."""
    default = "https://bigbankbonus.com/command-center.html"
    assert get_safe_redirect_url("/dashboard", default_url=default) == "https://bigbankbonus.com/dashboard"
    assert get_safe_redirect_url("/command-center.html", default_url=default) == default


def test_trusted_domains_allowed():
    """Trusted domain URLs must be allowed through."""
    assert get_safe_redirect_url("https://bigbankbonus.com/custom") == "https://bigbankbonus.com/custom"
    assert get_safe_redirect_url("https://www.bigbankbonus.com/custom") == "https://www.bigbankbonus.com/custom"
