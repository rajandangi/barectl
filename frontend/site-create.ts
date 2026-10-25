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

// docs/dashboard-workflows.md: one domain field, Add another domain up to ten.
const MAX_DOMAINS = 10;

function domainInputs(container: HTMLElement): HTMLInputElement[] {
  return Array.from(container.querySelectorAll<HTMLInputElement>('input[name="names"]'));
}

function refreshDomainControls(container: HTMLElement): void {
  const inputs = domainInputs(container);
  inputs.forEach((input, index) => {
    input.required = index === 0;
    input.id = `create-site-domain-${String(index)}`;
    const group = input.closest("[data-site-domain]");
    const remove = group?.querySelector<HTMLButtonElement>("[data-remove-domain]");
    if (remove) remove.hidden = inputs.length === 1;
  });
  const add = document.querySelector<HTMLButtonElement>("[data-add-domain]");
  if (add) add.hidden = inputs.length >= MAX_DOMAINS;
}

function addDomain(): void {
  const container = document.getElementById("create-site-domains");
  const template = document.querySelector<HTMLTemplateElement>("[data-domain-template]");
  if (!(container instanceof HTMLElement) || !template) return;
  if (domainInputs(container).length >= MAX_DOMAINS) return;
  container.append(template.content.cloneNode(true));
  refreshDomainControls(container);
  domainInputs(container).at(-1)?.focus();
}

document.addEventListener("click", (event: Event) => {
  const target = event.target;
  if (!(target instanceof Element)) return;
  if (target.closest("[data-add-domain]")) {
    event.preventDefault();
    addDomain();
    return;
  }
  const remove = target.closest<HTMLButtonElement>("[data-remove-domain]");
  if (!remove) return;
  event.preventDefault();
  remove.closest("[data-site-domain]")?.remove();
  const container = document.getElementById("create-site-domains");
  if (container) refreshDomainControls(container);
});

document.addEventListener("DOMContentLoaded", () => {
  const container = document.getElementById("create-site-domains");
  if (container) refreshDomainControls(container);
});
