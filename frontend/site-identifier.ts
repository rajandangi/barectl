// docs/site-conventions.md: the identifier remains an operator choice.
document.addEventListener("input", (event: Event) => {
  const names = event.target;
  if (
    !(names instanceof HTMLTextAreaElement || names instanceof HTMLInputElement) ||
    !names.hasAttribute("data-site-names")
  ) {
    return;
  }
  const form = names.closest("form[data-site-create]");
  const identifier = form?.querySelector<HTMLInputElement>("[data-site-identifier]");
  if (!(form instanceof HTMLFormElement) || !identifier) return;
  const previous = form.dataset["derivedIdentifier"] ?? "";
  if (identifier.value !== previous) return;
  const domain = names.value.trim().split(/\s+/u)[0] ?? "";
  let value =
    domain
      .toLowerCase()
      .replace(/^www\./u, "")
      .split(".")[0] ?? "";
  value = value.replace(/[^a-z0-9]/gu, "").slice(0, 24);
  if (value && !/^[a-z]/u.test(value)) value = `site${value}`.slice(0, 24);
  if (value && value.length < 3) value += "site";
  identifier.value = value;
  form.dataset["derivedIdentifier"] = value;
});
