import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent
DEBUG = os.environ.get("BARECTL_DEBUG", "0") == "1"
SECRET_KEY = os.environ.get("BARECTL_SECRET_KEY", "")
if not SECRET_KEY:
    raise ImproperlyConfigured("Set BARECTL_SECRET_KEY, or use --env-file .env for development.")
if not DEBUG and (len(SECRET_KEY) < 50 or SECRET_KEY.startswith("local-development")):
    raise ImproperlyConfigured(
        "Hosting requires a random BARECTL_SECRET_KEY of at least 50 characters."
    )
ALLOWED_HOSTS = [
    host.strip()
    for host in os.environ.get("BARECTL_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]").split(",")
    if host.strip()
]
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django_tasks_db",
    "dashboard",
    "servers",
    "operations",
    "discovery",
    "bootstrap",
    "sites",
    "databases",
    "tls",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "dashboard.middleware.HtmxAuthenticationMiddleware",
]
ROOT_URLCONF = "config.urls"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]
WSGI_APPLICATION = "config.wsgi.application"
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
        # Transactions take the write lock when they begin, so concurrent requests and the
        # worker wait for each other instead of failing with "database is locked".
        "OPTIONS": {"transaction_mode": "IMMEDIATE"},
    }
}
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"
# docs/frontend-assets.md#development-and-production
VITE_MANIFEST_PATH = BASE_DIR / "static" / "dist" / ".vite" / "manifest.json"
VITE_DEV_SERVER_URL = os.environ.get("BARECTL_VITE_DEV_SERVER_URL", "").strip().rstrip("/")
if VITE_DEV_SERVER_URL and not DEBUG:
    raise ImproperlyConfigured("BARECTL_VITE_DEV_SERVER_URL requires BARECTL_DEBUG=1.")
# docs/ssh-aliases.md#configuration-file
SSH_CONFIG_PATH = os.environ.get("BARECTL_SSH_CONFIG", "").strip() or "~/.ssh/config"
# docs/ssh-connections.md#running-the-worker
TASKS = {"default": {"BACKEND": "django_tasks_db.DatabaseBackend"}}
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    # docs/ssh-connections.md#failures-and-logs
    "handlers": {"discard": {"class": "logging.NullHandler"}},
    "loggers": {
        name: {"handlers": ["discard"], "level": "CRITICAL", "propagate": False}
        for name in ("paramiko", "pyinfra")
    },
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "servers"
LOGOUT_REDIRECT_URL = "login"
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SECURE_SSL_REDIRECT = not DEBUG
SECURE_HSTS_SECONDS = 31536000 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
SECURE_HSTS_PRELOAD = not DEBUG
