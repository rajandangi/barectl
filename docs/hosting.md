# Hosting status

Barectl is designed to be self-hostable, but this initial foundation has not completed production deployment or remote credential testing. The included `runserver` command is for local development.

Settings default to debug off and require a secret key from the environment. A hosted deployment must set a random `BARECTL_SECRET_KEY` of at least 50 characters and explicit `BARECTL_ALLOWED_HOSTS`. HTTPS redirects and secure cookies are enabled when debug is off. `.env.example` is for local use only.

Before a supported hosted release, document and test a WSGI server, static file serving, TLS termination, trusted proxy handling, service supervision, database backups, and a separate job worker. Do not disable HTTPS protection to work around an unconfigured proxy. Set proxy trust only when the deployment strips untrusted forwarded headers.

Run Django's deployment checks with the intended environment:

```bash
uv run python manage.py check --deploy
```

An SSH key on a hosted controller grants the controller access to its target servers. Multi-user authorization, credential lifecycle, audit retention, and login rate limiting require explicit implementation before exposing server operations to a team.
