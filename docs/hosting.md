# Hosting status

Barectl is designed to be self-hostable, but this initial foundation has not completed production deployment or remote credential testing. The included `runserver` command is for local development.

Settings default to debug off and require a secret key from the environment. A hosted deployment must set a random `BARECTL_SECRET_KEY` of at least 50 characters and explicit `BARECTL_ALLOWED_HOSTS`. HTTPS redirects and secure cookies are enabled when debug is off. `.env.example` is for local use only.

Before a supported hosted release, document and test a WSGI server, static file serving, TLS termination, trusted proxy handling, service supervision, database backups, and a separate job worker. Do not disable HTTPS protection to work around an unconfigured proxy. Set proxy trust only when the deployment strips untrusted forwarded headers.

Build the frontend before collecting static files. Django reads the Vite manifest from `static/dist/.vite/manifest.json`, so keep the build output on the host. Do not set `BARECTL_VITE_DEV_SERVER_URL` outside development.

```bash
npm ci
npm run build
uv run python manage.py collectstatic
```

Serve `STATIC_ROOT` at `STATIC_URL`. The collected files include the built interface, its self-hosted fonts and the third-party license notices under `dist/licenses/`. Pages do not request a font CDN or a Vite server at runtime.

Run Django's deployment checks with the intended environment. They fail when the Vite build is missing or the development server setting is present:

```bash
uv run python manage.py check --deploy
```

An SSH key on a hosted controller grants the controller access to its target servers. Multi-user authorization, credential lifecycle, audit retention, and login rate limiting require explicit implementation before exposing server operations to a team.
