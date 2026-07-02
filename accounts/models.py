"""
Custom User model for the Secure Login System.

Extends Django's built-in AbstractUser with:
  - TOTP-based Two-Factor Authentication (2FA) fields
  - Account lockout tracking (brute-force protection)
"""

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
import pyotp


class CustomUser(AbstractUser):
    # -- Two-Factor Authentication --
    is_2fa_enabled = models.BooleanField(default=False)
    totp_secret = models.CharField(max_length=32, blank=True, null=True)

    # -- Brute-force protection --
    failed_login_attempts = models.PositiveIntegerField(default=0)
    locked_until = models.DateTimeField(blank=True, null=True)

    def generate_totp_secret(self):
        """Generate and store a new TOTP secret (called once during 2FA setup)."""
        self.totp_secret = pyotp.random_base32()
        self.save(update_fields=["totp_secret"])
        return self.totp_secret

    def get_totp_uri(self):
        """Return the otpauth:// URI used to build a QR code for authenticator apps."""
        if not self.totp_secret:
            self.generate_totp_secret()
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name=self.email or self.username,
            issuer_name="SecureLoginSystem"
        )

    def verify_totp(self, code: str) -> bool:
        """Verify a 6-digit TOTP code against the stored secret."""
        if not self.totp_secret:
            return False
        totp = pyotp.totp.TOTP(self.totp_secret)
        return totp.verify(code, valid_window=1)   # allow 1 step (30s) clock drift

    # -- Lockout helpers --
    def is_locked_out(self) -> bool:
        if self.locked_until and timezone.now() < self.locked_until:
            return True
        return False

    def register_failed_attempt(self):
        from django.conf import settings
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= settings.MAX_LOGIN_ATTEMPTS:
            self.locked_until = timezone.now() + timezone.timedelta(
                minutes=settings.LOCKOUT_DURATION_MINUTES
            )
        self.save(update_fields=["failed_login_attempts", "locked_until"])

    def reset_failed_attempts(self):
        if self.failed_login_attempts or self.locked_until:
            self.failed_login_attempts = 0
            self.locked_until = None
            self.save(update_fields=["failed_login_attempts", "locked_until"])

    def __str__(self):
        return self.username
