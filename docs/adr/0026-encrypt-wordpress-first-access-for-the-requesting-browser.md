# Encrypt WordPress first access for the requesting browser

Status: accepted implementation design for [#320](https://github.com/rajandangi/barectl/issues/320); qualification pending.

## Requirement and alternatives

An explicitly requested WordPress application needs first access through the browser. Requiring SSH to establish the first password prevents the ordinary creation workflow from being usable without infrastructure instructions. Server setup and generic hosting creation do not install WordPress implicitly.

WordPress's password-reset email depends on outbound mail that a fresh server does not necessarily have. A public uninstalled WordPress screen allows another visitor to create the first administrator. Retaining a plaintext password in the controller's task queue or database violates the existing credential boundary. A reset URL carries a bearer secret in a URL and adds referrer and request-log handling. Use established browser and native cryptography to deliver the existing server-generated password to the requesting browser.

## Decision

The authenticated creation page generates a nonexportable RSA-OAEP private key through Web Crypto. Use a 4096-bit RSA modulus, exponent 65537, SHA-256 for OAEP and MGF1, and an empty OAEP label. Only canonical DER SubjectPublicKeyInfo for the public key goes to the controller. The controller validates the key and records its digest with the immutable authorized request, site, requester and native run. The browser retains the private CryptoKey in its origin's IndexedDB for bounded recovery across the creation page's navigation; it expires after one hour and is removed after reveal or logout. No private key is uploaded.

The existing site-user process generates the password and feeds it through WP-CLI's supported standard-input prompt. Before discarding it, that process encrypts the password with the admitted public key through native OpenSSL. Plaintext never enters arguments, environment variables, files, logs, task inputs or controller records. A fixed marker carries only the bounded ciphertext and public key digest in the native unit's retained journal. This permits recovery of the original native outcome after controller loss without rotating the password or replaying schema installation.

The controller retrieves ciphertext only from the admitted unit and invocation, after verifying the application. It retains ciphertext in a separate first-access record scoped to its requester and run, with an expiry and atomic reveal consumption. Only that active authenticated requester with current application permissions can retrieve it through a CSRF-protected POST. The response is never cached and is excluded from ordinary progress, history and audit rendering. The browser decrypts and displays the password locally. The password is not inserted into a URL or sent back to the controller. WordPress's normal HTTPS login accepts it.

If the browser key expired or was lost, report that first access is unavailable. Recovery must use a separate explicit bounded administrator-password reset action, fresh site/account evidence, a new browser public key, the same native lock and outcome reconciliation. An uncertain reset is checked through its original run rather than repeated. No automatic reset or schema retry is authorized by creation.

## Reuse and sources

[WP-CLI core install](https://developer.wordpress.org/cli/commands/core/install/) supplies the existing stdin prompt and administrator creation. [Web Crypto](https://www.w3.org/TR/2017/REC-WebCryptoAPI-20170126/) supplies key generation and RSA-OAEP decryption. [OpenSSL 3.0 pkeyutl](https://docs.openssl.org/3.0/man1/openssl-pkeyutl/) supplies public-key encryption with explicit OAEP and MGF1 digest options. Existing immutable plans, staged native bodies, transient systemd units, retained unit logs and the SSH worker remain the execution and recovery mechanisms. Custom code binds their inputs and outputs to the authorized first-access workflow; it implements no cipher or password generator.

## Qualification

Explicit recovery uses [WP-CLI user update](https://developer.wordpress.org/cli/commands/user/update/) with `--prompt=user_pass` and `--skip-email`. The native review binds the exact administrator identity and existing account digest through passive MariaDB reads. Reset changes only that account's password, then verifies the original run and uses the same encrypted delivery contract. It neither reinstalls core nor relies on mail or reset URLs.

Verify native encryption and browser decryption together, expiry, single reveal, another user/device, revoked permissions, stale identity, controller/SSH loss, lost key, ambiguous native outcome and explicit reset recovery. Scan arguments, environments, native journal, controller records, rendered progress/history, URLs and captured logs for plaintext password or private-key material. Preserve the separate legacy installation and Finish behavior until this new path passes its qualification gates.
