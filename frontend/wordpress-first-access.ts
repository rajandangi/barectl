/** docs/adr/0026-encrypt-wordpress-first-access-for-the-requesting-browser.md */
const DATABASE = "barectl-first-access";
const STORE = "keys";
const LIFETIME = 60 * 60 * 1000;
const submitting = new WeakSet<HTMLFormElement>();
const busy = new WeakSet<HTMLFormElement>();

type StoredKey = { privateKey: CryptoKey; expires: number; user: string };

function database(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE, 1);
    request.onupgradeneeded = (): void => {
      request.result.createObjectStore(STORE);
    };
    request.onsuccess = (): void => {
      resolve(request.result);
    };
    request.onerror = (): void => {
      reject(new Error("Browser key storage is unavailable."));
    };
  });
}

async function readKey(digest: string): Promise<StoredKey | undefined> {
  const db = await database();
  try {
    return await new Promise((resolve, reject) => {
      const request = db.transaction(STORE, "readonly").objectStore(STORE).get(digest);
      request.onsuccess = (): void => {
        const value: unknown = request.result;
        if (
          value &&
          typeof value === "object" &&
          "privateKey" in value &&
          value.privateKey instanceof CryptoKey &&
          "expires" in value &&
          typeof value.expires === "number" &&
          "user" in value &&
          typeof value.user === "string"
        ) {
          resolve({ privateKey: value.privateKey, expires: value.expires, user: value.user });
        } else {
          resolve(undefined);
        }
      };
      request.onerror = (): void => {
        reject(new Error("The first-access key could not be read."));
      };
    });
  } finally {
    db.close();
  }
}

async function writeKey(digest: string, key: StoredKey): Promise<void> {
  const db = await database();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = db.transaction(STORE, "readwrite");
      transaction.objectStore(STORE).put(key, digest);
      transaction.oncomplete = (): void => {
        resolve();
      };
      transaction.onerror = (): void => {
        reject(new Error("The browser could not retain its first-access key."));
      };
    });
  } finally {
    db.close();
  }
}

async function removeKey(digest?: string): Promise<void> {
  const db = await database();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = db.transaction(STORE, "readwrite");
      const store = transaction.objectStore(STORE);
      if (digest) store.delete(digest);
      else store.clear();
      transaction.oncomplete = (): void => {
        resolve();
      };
      transaction.onerror = (): void => {
        reject(new Error("The browser key could not be removed."));
      };
    });
  } finally {
    db.close();
  }
}

function base64(bytes: Uint8Array): string {
  return btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""));
}

function decode(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

async function digest(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

function announce(form: HTMLFormElement, message: string): void {
  const status = form.querySelector("[data-first-access-status]");
  if (status instanceof HTMLElement) status.textContent = message;
}

async function prepare(form: HTMLFormElement): Promise<void> {
  const input = form.querySelector('input[name="first_access_spki"]');
  const user = form.dataset["firstAccessUser"];
  if (!(input instanceof HTMLInputElement) || !user)
    throw new Error("First-access form is incomplete.");
  if (input.value) {
    const key = await readKey(await digest(decode(input.value)));
    if (key && key.user === user && key.expires > Date.now()) return;
  }
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    false,
    ["encrypt", "decrypt"],
  );
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  const keyDigest = await digest(spki);
  await writeKey(keyDigest, { privateKey: pair.privateKey, user, expires: Date.now() + LIFETIME });
  input.value = base64(spki);
}

async function reveal(form: HTMLFormElement): Promise<void> {
  const keyDigest = form.dataset["firstAccessDigest"];
  const user = form.dataset["firstAccessUser"];
  if (!keyDigest || !user || !/^[a-f0-9]{64}$/u.test(keyDigest))
    throw new Error("First-access delivery is unavailable.");
  const key = await readKey(keyDigest);
  if (!key || key.user !== user || key.expires <= Date.now()) {
    await removeKey(keyDigest);
    throw new Error(
      "This browser's key is unavailable or expired. Use Reset administrator password.",
    );
  }
  const response = await fetch(form.action, {
    method: "POST",
    body: new FormData(form),
    credentials: "same-origin",
    cache: "no-store",
    headers: { Accept: "application/json" },
  });
  if (!response.ok)
    throw new Error(
      "First access is unavailable. Refresh the site or reset the administrator password.",
    );
  const value: unknown = await response.json();
  if (
    !value ||
    typeof value !== "object" ||
    !("ciphertext" in value) ||
    typeof value.ciphertext !== "string" ||
    value.ciphertext.length !== 684 ||
    !("key_sha256" in value) ||
    value.key_sha256 !== keyDigest
  )
    throw new Error("First-access delivery could not be verified.");
  const passwordBytes = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    key.privateKey,
    decode(value.ciphertext),
  );
  const password = new TextDecoder("utf-8", { fatal: true }).decode(passwordBytes);
  if (!/^[A-Za-z0-9]{32}$/u.test(password))
    throw new Error("The first-access password has an unsupported form.");
  await removeKey(keyDigest);
  const output = form.querySelector("[data-first-access-password]");
  if (!(output instanceof HTMLOutputElement))
    throw new Error("The password display is unavailable.");
  output.value = password;
  output.hidden = false;
  announce(
    form,
    "Copy this password and sign in to WordPress. It will clear from this page in one minute.",
  );
  const submit = form.querySelector('button[type="submit"]');
  if (submit instanceof HTMLButtonElement) submit.disabled = true;
  setTimeout(() => {
    output.value = "";
    output.hidden = true;
  }, 60_000);
}

export function startFirstAccess(): void {
  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (new URL(form.action, document.baseURI).pathname.endsWith("/accounts/logout/")) {
      if (submitting.has(form)) return;
      event.preventDefault();
      if (busy.has(form)) return;
      busy.add(form);
      void removeKey()
        .catch(() => undefined)
        .finally((): void => {
          submitting.add(form);
          busy.delete(form);
          form.requestSubmit();
        });
      return;
    }
    if (form.matches("[data-first-access-create]") && !submitting.has(form)) {
      event.preventDefault();
      if (busy.has(form)) return;
      busy.add(form);
      announce(form, "Preparing secure first access…");
      void prepare(form)
        .then(() => {
          submitting.add(form);
          form.requestSubmit();
        })
        .catch((error: unknown): void => {
          announce(
            form,
            error instanceof Error ? error.message : "Browser first access is unavailable.",
          );
        })
        .finally((): void => {
          busy.delete(form);
        });
    } else if (form.matches("[data-first-access-reveal]")) {
      event.preventDefault();
      if (busy.has(form)) return;
      busy.add(form);
      void reveal(form)
        .catch((error: unknown): void => {
          announce(form, error instanceof Error ? error.message : "First access is unavailable.");
        })
        .finally((): void => {
          busy.delete(form);
        });
    }
  });
}
