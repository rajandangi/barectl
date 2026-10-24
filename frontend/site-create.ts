// docs/sites.md#step-1-a-missing-runtime-or-database-engine: name the PHP install step
// before the create form is sent.
type Installable = Record<string, unknown>;

function installableLabels(select: HTMLSelectElement): Installable {
  const raw = select.dataset["installable"];
  if (!raw) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return {};
  }
  return typeof parsed === "object" && parsed !== null ? (parsed as Installable) : {};
}

function updateSubmit(select: HTMLSelectElement): void {
  const form = select.closest("form[data-site-create]");
  if (!(form instanceof HTMLFormElement)) return;
  const button = form.querySelector<HTMLButtonElement>("[data-site-create-submit]");
  if (!button) return;
  const base = button.dataset["siteCreateLabel"] ?? "";
  const label = installableLabels(select)[select.value];
  button.textContent = typeof label === "string" ? `Step 1: install ${label}` : base;
}

function updateAll(): void {
  document.querySelectorAll<HTMLSelectElement>("select[data-site-php]").forEach(updateSubmit);
}

document.addEventListener("change", (event: Event) => {
  const select = event.target;
  if (!(select instanceof HTMLSelectElement) || !select.hasAttribute("data-site-php")) return;
  updateSubmit(select);
});
document.addEventListener("DOMContentLoaded", updateAll);
document.addEventListener("htmx:afterSettle", updateAll);
updateAll();
