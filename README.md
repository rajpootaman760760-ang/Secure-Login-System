# Secure Login System

A secure authentication web app built with Django, featuring hashed passwords,
input validation, session management, and optional Two-Factor Authentication (2FA).

**Author:** Aman Kumar Rajpoot

---

## Features

- **User registration & login** — passwords hashed with **Argon2** (winner of the
  Password Hashing Competition; stronger than bcrypt/MD5/SHA).
- **SQL injection protection** — all database access goes through Django's ORM
  (parameterized queries), never raw SQL string concatenation.
- **Input validation** — server-side validation on username, email, and password
  strength (min. 10 characters, rejects common passwords, rejects passwords
  similar to the username).
- **Session management** — HttpOnly + SameSite cookies, 30-minute idle timeout,
  session ends on browser close, full server-side logout.
- **CSRF protection** — enabled by default on every POST form via Django middleware.
- **Account lockout** — 5 failed login attempts locks the account for 15 minutes
  (brute-force protection).
- **Generic error messages** — login errors never reveal whether the username
  exists, preventing username enumeration attacks.
- **Two-Factor Authentication (2FA)** — optional TOTP-based 2FA (compatible with
  Google Authenticator, Authy, etc.), with QR code setup.

---

## Tech Stack

| Component | Choice |
|---|---|
| Backend | Django 6.0 |
| Password hashing | Argon2 (via `argon2-cffi`) |
| 2FA | TOTP via `pyotp` |
| QR code generation | `qrcode` |
| Database | SQLite (default, swappable) |

---

## Setup Instructions

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run migrations
python manage.py migrate

# 3. (Optional) create an admin account
python manage.py createsuperuser

# 4. Run the development server
python manage.py runserver
```

Visit `http://127.0.0.1:8000/` — you'll be redirected to the login page.

---

## Project Structure

```
secure_login_project/
├── manage.py
├── requirements.txt
├── secure_login_project/        # Project settings
│   ├── settings.py              # Security config (Argon2, sessions, CSRF, lockout)
│   ├── urls.py
│   └── wsgi.py
└── accounts/                     # Main app
    ├── models.py                 # CustomUser (2FA fields, lockout tracking)
    ├── forms.py                  # Registration / login / TOTP forms
    ├── views.py                  # Auth logic (register, login, 2FA, logout)
    ├── urls.py
    ├── admin.py
    └── templates/accounts/       # HTML templates
        ├── base.html
        ├── register.html
        ├── login.html
        ├── verify_2fa.html
        ├── setup_2fa.html
        └── dashboard.html
```

---

## How the Security Features Work

### 1. Password Hashing
Django's `AUTH_PASSWORD_VALIDATORS` + `PASSWORD_HASHERS` (in `settings.py`) ensure
every password is hashed with Argon2 before it touches the database. Raw passwords
are never stored or logged.

### 2. SQL Injection Protection
All queries go through Django's ORM (`CustomUser.objects.get(...)`,
`authenticate(...)`). These compile to parameterized SQL under the hood, so user
input is never concatenated into a query string — classic `' OR '1'='1` payloads
are treated as literal text, not SQL.

### 3. Session Management
- `SESSION_COOKIE_HTTPONLY = True` — JavaScript cannot read the session cookie (XSS mitigation).
- `SESSION_COOKIE_AGE = 1800` — sessions expire after 30 minutes of inactivity.
- Logout calls Django's `logout()`, which destroys the session server-side.

### 4. Account Lockout
Each failed login increments `failed_login_attempts` on the user record. After 5
failures, `locked_until` is set 15 minutes into the future; further login attempts
are blocked until that time passes (`accounts/models.py`).

### 5. Two-Factor Authentication (2FA)
Uses the TOTP (Time-based One-Time Password) standard via `pyotp` — the same
algorithm used by Google Authenticator. A QR code is generated server-side (no
external API calls) so the secret never leaves your server until scanned.

---

## Security Notes for Production

This is a college/educational project. Before deploying for real use:

- Set `DJANGO_DEBUG=False` and configure `DJANGO_SECRET_KEY` via environment variable.
- Switch to PostgreSQL/MySQL instead of SQLite.
- Serve over HTTPS (the settings file auto-enables secure cookies and HSTS when `DEBUG=False`).
- Add rate limiting at the web server/load balancer level in addition to the
  application-level lockout.
- Consider adding email verification on registration.
