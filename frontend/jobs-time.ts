// docs/server-jobs.md: Recent results show times in the viewer's own zone (#291).
// The zone changes the display and range boundaries only; the server keeps UTC.
import htmx from "htmx.org";

const focusKey = "barectl-jobs-focus";

function viewerZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  } catch {
    return "";
  }
}

function jobsPanel(): HTMLElement | null {
  return document.getElementById("jobs-panel");
}

function zoneField(root: ParentNode): HTMLInputElement | null {
  return root.querySelector<HTMLInputElement>('form[data-jobs-filters] input[name="tz"]');
}

function syncZoneField(root: ParentNode = document): void {
  const field = zoneField(root);
  const zone = viewerZone();
  if (field && zone) field.value = zone;
}

function sendViewerZone(): boolean {
  // Only the Jobs page has the panel, and only the first visit lacks the zone.
  if (!jobsPanel()) return false;
  const url = new URL(window.location.href);
  if (url.searchParams.get("tz")) return false;
  const zone = viewerZone();
  if (!zone) return false;
  url.searchParams.set("tz", zone);
  // docs/frontend-assets.md#htmx-4: a targeted swap sends HX-Request-Type partial.
  htmx
    .ajax("GET", url.pathname + url.search, {
      target: "#jobs-panel",
      swap: "outerHTML",
      replace: "true",
    })
    .catch(() => undefined);
  return true;
}

function restoreFocus(): void {
  const id = sessionStorage.getItem(focusKey);
  if (!id) return;
  sessionStorage.removeItem(focusKey);
  const element = document.getElementById(id);
  if (element instanceof HTMLElement) element.focus();
}

function announceCount(): void {
  const status = document.getElementById("jobs-results-status");
  const count = jobsPanel()?.dataset["resultCount"];
  if (!status || count === undefined) return;
  const noun = count === "1" ? "result" : "results";
  status.textContent = `${count} ${noun} in Recent results.`;
}

function applyFilters(event: Event): void {
  const form = event.target;
  if (!(form instanceof HTMLFormElement) || !form.matches("[data-jobs-filters]")) return;
  event.preventDefault();
  const range = form.querySelector<HTMLSelectElement>("select[name='range']");
  const defaultRange = range?.dataset["jobsDefault"] ?? "";
  const params = new URLSearchParams();
  new FormData(form).forEach((value, name) => {
    if (typeof value !== "string" || value === "") return;
    // The default range is omitted, so the ordinary URL stays clean.
    if (name === "range" && value === defaultRange) return;
    params.set(name, value);
  });
  const query = params.toString();
  const url = `${form.action}${query ? `?${query}` : ""}`;
  htmx
    .ajax("GET", url, {
      target: "#jobs-panel",
      swap: "outerHTML",
      push: "true",
    })
    .catch(() => undefined);
}

document.addEventListener("change", (event: Event) => {
  const target = event.target;
  if (!(target instanceof HTMLSelectElement)) return;
  if (!target.closest("form[data-jobs-filters]")) return;
  sessionStorage.setItem(focusKey, target.id);
});

document.addEventListener("submit", applyFilters);

function initializeJobs(): void {
  syncZoneField();
  // A zone exchange replaces the panel, so restore focus after that swap instead.
  if (!sendViewerZone()) restoreFocus();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initializeJobs);
} else {
  initializeJobs();
}

document.addEventListener("htmx:after:settle", () => {
  initializeJobs();
  announceCount();
});
