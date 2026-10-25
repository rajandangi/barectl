// docs/saved-server-connections.md#approved-key-files: show the chosen key's public half.
function showChosenKey(select: HTMLSelectElement): void {
  for (const choice of document.querySelectorAll<HTMLDetailsElement>("details[data-credential-key]")) {
    choice.open = choice.dataset["credentialKey"] === select.value;
  }
}

function sync(select: HTMLSelectElement): void {
  showChosenKey(select);
}

document.addEventListener("change", (event: Event) => {
  const select = event.target;
  if (!(select instanceof HTMLSelectElement) || !select.matches("select[name=credential_reference]")) {
    return;
  }
  sync(select);
});
document.addEventListener("DOMContentLoaded", () => {
  document
    .querySelectorAll<HTMLSelectElement>("select[name=credential_reference]")
    .forEach(sync);
});
