# Site creation preview

This throwaway, in-memory HTML prototype answers whether one Create request, automatic prerequisites, server runtime defaults and optional site overrides provide a useful replacement for the manual hosting setup journey in #320.

Open `site-first.prototype.html` in a browser. It contacts no server, persists no state and captures no password. Use example values. Its supported-version lists are illustrative, not runtime qualification.

The walkthroughs show fresh WordPress creation, changing a default while preserving an existing site's version, retained hosting work after a DNS failure, and a Node override. The model exercised those behaviors through browser interactions. No production provisioning or native recovery was proved.

The owning product design is `docs/site-creation.md`; official sources and native alternatives are in `docs/site-creation-competitor-analysis.md`. Automatic prerequisites, native runtime defaults/switches, Node hosting and secure browser first login require implementation and qualification. The prototype is captured on `upgrade/site-first-preview` and is not part of the design PR or intended for merging into main.
