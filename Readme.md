# Passkey PRF Extension Demo

A minimal, self‑contained web application that demonstrates **how to use the WebAuthn PRF (pseudo‑random‑function) extension to derive a deterministic 32‑byte secret from a passkey and an application‑chosen salt**. The goal is strictly educational: the app shows every request, response and cryptographic value involved so developers can see exactly **how the PRF extension produces a stable output that can later feed a KDF to wrap a DEK**.

The existing PoC already supports **register / login with passkeys** (implemented in `passkey.go`). This extension adds two new flows:

1. **Add Secret** – generates a random *secret ID* and *salt* on the server, stores them in‑memory, and shows them on the page.
2. **Get PRF Output** – asks the authenticator to evaluate the PRF extension with that salt; the browser returns a deterministic 32‑byte blob bound to the chosen credential. The app displays the raw bytes so you can verify that repeating the call with the same salt and credential yields the same output.

---

## What We Are Demonstrating

| Topic | Why it matters |
|-------|----------------|
| **WebAuthn PRF extension** | Allows web clients to ask an authenticator to compute an HMAC‑like function keyed by the private credential key. Output never leaves the authenticator unprotected and is calculable only with user presence. |
| **Deterministic key output** | Given *the same credential* and *the same salt*, the PRF returns **exactly the same 32 bytes every time**, making it perfect for envelope‑encryption KEKs. |
| **Salt = domain separation** | The application chooses an arbitrary 32‑byte salt (random). Different salts produce different outputs, allowing multiple independent keys from one credential. |
| **Transparent step‑by‑step UX** | Each stage (generated salt, JS request JSON, authenticator response, PRF result) is printed to the screen so learners can follow the flow. |

We deliberately ignore broader production concerns (password fallback, KDF choice, storage format, revocation, etc.) to keep the PoC laser‑focused on **"passkey → PRF → deterministic secret"**.

---

## High‑Level Flow

1. **Register** (ready‑made): user creates a passkey for `localhost` demo site.
2. **Add Secret**
   1. Browser calls `POST /api/secret/add`.
   2. Server generates:
      * `secretID` – 16 random bytes (base64url‑encoded).
      * `salt` – 32 random bytes (base64url‑encoded).
   3. Server stores them under the current user in an in‑memory map and returns JSON `{secretID, salt}`.
3. **Get PRF Output**
   1. Browser calls `POST /api/prf/assertionOptions` with `{secretID}`.
   2. Server builds a standard WebAuthn **assertion options** object, plus:
      ```json
      "extensions": {
        "prf": {
          "eval": [{
            "id": "<base64url secretID>",
            "salt": "<base64url salt>"
          }]
        }
      }
      ```
   3. Browser runs `navigator.credentials.get({publicKey: options})`.
   4. Authenticator verifies user presence, computes `HMAC_SHA256(privateKey, H("WebAuthn PRF" || salt))`, returns **32‑byte result** in `clientExtensionResults.prf.results[0]`.
   5. JS prints that result in hex & base64; POSTs it to `POST /api/secret/storeResult` so server can keep it (optional).
4. Repeat **Get PRF** with the same `secretID` – you’ll see the exact same output bit‑for‑bit, proving determinism.

---

## Running the Demo

```bash
# Requires Go 1.22+
$ git clone https://example.com/webauthn‑prf‑demo
$ cd webauthn‑prf‑demo
$ go run .
# Open http://localhost:8083 in Chrome ≥119 or Edge ≥119 (PRF enabled)
```
> ⚠️ As of April 2025 the PRF extension is supported in Chromium‑based browsers with platform authenticators and recent external security keys (YubiKey Bio 5C NFC, Titan M, etc.). Safari/Firefox may require nightly builds.

---

## File/Directory Overview

```
│  passkey.go          # existing register/login logic
│  secret.go           # new in‑memory model for Secret {ID, Salt, PRFOutput}
│  static/
│    index.html        # one‑page UI with new buttons and log panel
│    app.js            # JS helpers: base64url ⇄ ArrayBuffer, WebAuthn calls, pretty‑print
└── README.md          # this file
```

---

## Glossary

- **secretID** – opaque 16‑byte identifier for one logical “secret”. Used as the `id` field in the PRF extension so the authenticator can map multiple salts.
- **salt** – 32‑byte random value chosen by the server; unique per secret, guarantees domain separation.
- **PRF output** – 32‑byte deterministic result, cryptographically bound to `(credential ID, salt)`.

---


