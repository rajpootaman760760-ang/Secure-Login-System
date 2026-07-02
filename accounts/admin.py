from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    list_display = ("username", "email", "is_2fa_enabled", "failed_login_attempts", "is_staff")
    fieldsets = UserAdmin.fieldsets + (
        ("Security", {"fields": ("is_2fa_enabled", "totp_secret", "failed_login_attempts", "locked_until")}),
    )
