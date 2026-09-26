# Version-matched documentation

## Django

Barectl uses Django 6.1.1. Start with these official sources:

- [Django 6.1 documentation](https://docs.djangoproject.com/en/6.1/)
- [Django 6.1 release notes](https://docs.djangoproject.com/en/6.1/releases/6.1/)
- [Django 6.1.1 fixes](https://docs.djangoproject.com/en/6.1/releases/6.1.1/)
- [Deployment checklist](https://docs.djangoproject.com/en/6.1/howto/deployment/checklist/)
- [System checks](https://docs.djangoproject.com/en/6.1/topics/checks/)

Use the relevant versioned page before making a recommendation. Open the actual page; a search excerpt is not sufficient. Use the installed package source if a documented behavior remains unclear, and distinguish an inference from an explicit upstream recommendation.

## Documentation MCP status

On 2026-09-26, no Django-maintained documentation MCP service could be verified from the official documentation and Django project search. The [Django forum discussion](https://forum.djangoproject.com/t/official-mcp-server-for-djangos-documentation/44188) describes a proposal and experimentation, not a confirmed official deployment. This is a bounded finding, not a guarantee that no other work exists.

Do not configure the proposed hostname as a service without verification. Community packages that expose Django applications or interactive shells are a different capability from versioned documentation retrieval. Direct access to the official documentation is the current project approach; no MCP server was installed for this requirement.

## Other tools

For packages outside Django, consult their maintainers' documentation and compatibility declarations. The tooling sources and scope are recorded in `docs/quality.md`. A package can be useful and supported by its maintainers without being endorsed by Django.
