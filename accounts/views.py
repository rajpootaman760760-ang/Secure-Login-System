"""
Views for the Secure Login System.

Security measures implemented here:
  - Django ORM only (no raw SQL) -> protected from SQL injection
  - Argon2-hashed passwords via Django's auth system (settings.py)
  - Account lockout after N failed attempts (brute-force protection)
  - Generic error messages on login (prevents username enumeration)
  - django-csrf on every POST form (templates use {% csrf_token %})
  - Session-based auth with HttpOnly, SameSite cookies (settings.py)
  - Optional TOTP-based Two-Factor Authentication
"""

import qrcode
import io
import base64

from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from django.utils import timezone
from django.conf import settings

from .forms import RegistrationForm, LoginForm, TOTPVerifyForm
from .models import CustomUser


# == REGISTRATION ==

def register_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()   # password is hashed automatically (Argon2)
            messages.success(request, "Account created successfully! Please log in.")
            return redirect("login")
    else:
        form = RegistrationForm()

    return render(request, "accounts/register.html", {"form": form})


# == LOGIN (with lockout + optional 2FA) ==

def login_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data["username"]
            password = form.cleaned_data["password"]

            try:
                user_obj = CustomUser.objects.get(username=username)
            except CustomUser.DoesNotExist:
                user_obj = None

            # Lockout check (before revealing anything about credentials)
            if user_obj and user_obj.is_locked_out():
                remaining = (user_obj.locked_until - timezone.now()).seconds // 60 + 1
                messages.error(
                    request,
                    f"Account temporarily locked due to too many failed attempts. "
                    f"Try again in {remaining} minute(s)."
                )
                return render(request, "accounts/login.html", {"form": form})

            # Django's authenticate() uses the ORM internally -> parameterized query,
            # immune to SQL injection regardless of what's typed in username/password.
            user = authenticate(request, username=username, password=password)

            if user is not None:
                user.reset_failed_attempts()

                if user.is_2fa_enabled:
                    # Don't log in yet -- stash user id in session, redirect to 2FA step
                    request.session["pre_2fa_user_id"] = user.id
                    return redirect("verify_2fa")

                auth_login(request, user)
                messages.success(request, f"Welcome back, {user.username}!")
                return redirect("dashboard")
            else:
                if user_obj:
                    user_obj.register_failed_attempt()
                # Generic message regardless of whether username existed
                # (prevents attackers from enumerating valid usernames)
                messages.error(request, "Invalid username or password.")
    else:
        form = LoginForm()

    return render(request, "accounts/login.html", {"form": form})


# == 2FA SETUP (enable TOTP, show QR code) ==

@login_required
def setup_2fa_view(request):
    user = request.user

    if request.method == "POST":
        form = TOTPVerifyForm(request.POST)
        if form.is_valid():
            code = form.cleaned_data["code"]
            if user.verify_totp(code):
                user.is_2fa_enabled = True
                user.save(update_fields=["is_2fa_enabled"])
                messages.success(request, "Two-Factor Authentication enabled successfully!")
                return redirect("dashboard")
            else:
                messages.error(request, "Invalid code. Please try again.")
    else:
        form = TOTPVerifyForm()

    if not user.totp_secret:
        user.generate_totp_secret()

    # Build QR code as a base64 PNG (no temp files needed)
    uri = user.get_totp_uri()
    qr_img = qrcode.make(uri)
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    qr_base64 = base64.b64encode(buf.getvalue()).decode()

    return render(request, "accounts/setup_2fa.html", {
        "form": form,
        "qr_base64": qr_base64,
        "secret": user.totp_secret,
    })


@login_required
def disable_2fa_view(request):
    if request.method == "POST":
        request.user.is_2fa_enabled = False
        request.user.totp_secret = None
        request.user.save(update_fields=["is_2fa_enabled", "totp_secret"])
        messages.info(request, "Two-Factor Authentication has been disabled.")
    return redirect("dashboard")


# == 2FA VERIFY (during login) ==

def verify_2fa_view(request):
    user_id = request.session.get("pre_2fa_user_id")
    if not user_id:
        return redirect("login")

    user = get_object_or_404(CustomUser, id=user_id)

    if request.method == "POST":
        form = TOTPVerifyForm(request.POST)
        if form.is_valid():
            code = form.cleaned_data["code"]
            if user.verify_totp(code):
                del request.session["pre_2fa_user_id"]
                auth_login(request, user)
                messages.success(request, f"Welcome back, {user.username}!")
                return redirect("dashboard")
            else:
                user.register_failed_attempt()
                messages.error(request, "Invalid authentication code.")
    else:
        form = TOTPVerifyForm()

    return render(request, "accounts/verify_2fa.html", {"form": form})


# == DASHBOARD / LOGOUT ==

@login_required
def dashboard_view(request):
    return render(request, "accounts/dashboard.html", {"user": request.user})


@login_required
def logout_view(request):
    auth_logout(request)   # clears session server-side
    messages.info(request, "You have been logged out successfully.")
    return redirect("login")
