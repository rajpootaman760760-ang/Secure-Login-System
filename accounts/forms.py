"""
Forms for the Secure Login System.

Django forms automatically:
  - Escape output in templates (XSS protection)
  - Use parameterized ORM queries (SQL injection protection)
  - Validate and sanitize input server-side
"""

import re
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError
from .models import CustomUser


class RegistrationForm(UserCreationForm):
    """
    Registration form with extra input validation on top of
    Django's built-in password validators (length, common password,
    similarity to username, fully-numeric check).
    """
    email = forms.EmailField(required=True)

    class Meta:
        model = CustomUser
        fields = ["username", "email", "password1", "password2"]

    def clean_username(self):
        username = self.cleaned_data.get("username")
        # Allow only safe characters — defense in depth against injection-style payloads
        if not re.match(r'^[a-zA-Z0-9_.]+$', username):
            raise ValidationError(
                "Username can only contain letters, numbers, dots, and underscores."
            )
        if len(username) < 3:
            raise ValidationError("Username must be at least 3 characters long.")
        return username

    def clean_email(self):
        email = self.cleaned_data.get("email")
        if CustomUser.objects.filter(email__iexact=email).exists():
            raise ValidationError("An account with this email already exists.")
        return email


class LoginForm(forms.Form):
    """
    Simple login form. Deliberately does NOT use ModelForm to avoid
    leaking which field (username vs password) was wrong — error
    messages are generic to prevent username enumeration attacks.
    """
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)


class TOTPVerifyForm(forms.Form):
    """6-digit one-time code entered during 2FA login/setup."""
    code = forms.CharField(
        max_length=6,
        min_length=6,
        widget=forms.TextInput(attrs={
            "autocomplete": "one-time-code",
            "inputmode": "numeric",
            "pattern": "[0-9]*",
        }),
    )

    def clean_code(self):
        code = self.cleaned_data.get("code")
        if not code.isdigit():
            raise ValidationError("Code must be 6 digits.")
        return code
