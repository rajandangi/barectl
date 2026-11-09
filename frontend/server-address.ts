async function copyAddress(): Promise<void> {
  const address = document.getElementById("server-address");
  const status = document.getElementById("address-copy-status");
  if (!address || !status) return;
  try {
    await navigator.clipboard.writeText(address.textContent.trim());
    status.textContent = "Address copied.";
  } catch {
    const range = document.createRange();
    range.selectNodeContents(address);
    const selection = window.getSelection();
    selection?.removeAllRanges();
    selection?.addRange(range);
    status.textContent = "Select the address and copy it manually.";
  }
}

document.addEventListener("click", (event: Event) => {
  if (!(event.target instanceof HTMLElement)) return;
  if (!event.target.closest("[data-copy-address]")) return;
  copyAddress().catch(() => undefined);
});
