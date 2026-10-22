// A strong administrator password generated in the browser and shown once. The value goes
// into the confirm screen's confidential input and is never sent back to the controller
// before Apply (docs/wordpress.md; Phase B #380).
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+";

function password(length = 24): string {
  const values = new Uint32Array(length);
  crypto.getRandomValues(values);
  return Array.from(values, (value) => ALPHABET[value % ALPHABET.length] ?? "x").join("");
}

document.addEventListener("click", (event: Event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const button = target.closest<HTMLButtonElement>("[data-secret-generate]");
  if (!button) return;
  const inputID = button.dataset["secretGenerate"] ?? "";
  const input = document.getElementById(inputID);
  if (!(input instanceof HTMLInputElement)) return;
  const generated = password();
  input.value = generated;
  input.type = "text";
  const displayID = button.dataset["secretValue"] ?? "";
  const display = document.getElementById(displayID);
  if (display) display.textContent = `Generated password: ${generated}`;
  input.focus();
  input.select();
});
