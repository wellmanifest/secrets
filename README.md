# wellmanifest/secrets

Normative Wellmanifest domain pack for **encrypted secret storage**, **credential envelopes**,
**origin-bound access policies**, and **bounded secret leases**.

Status: `0.1.0-dev` — normative vocabulary, schemas, envelope cryptography, and conformance test suite.

## HOME vs ADOPT (boundary matrix)

- `HOME` wellmanifest · `shape` domain_pack
- Cross-refs (ADOPT, do not duplicate):
  - `wellmanifest/auth-lifecycle` — AuthN profile vocabularies (`otp-email`, `access-api`, `session-continue`)
  - `wellmanifest/authority-lifecycle` — AuthZ machine authority grants and delegation leases
  - `wellmanifest/account-runtime` — isolated tool runtimes operating without raw credential transfers
  - `wellmanifest/poa` — plan / grant / receipt execution boundaries

### Boundary Matrix

| Concern | HOME | Notes |
| :--- | :--- | :--- |
| **Encrypted envelope format & KDF specifications** | **this pack** | AES-256-GCM authenticated envelopes, scrypt/SHA-256 KDF |
| **Origin & scope binding rules** | **this pack** | RFC 3986 scheme+host origin validation, typed operation/target scopes |
| **Persistence & file security rules** | **this pack** | POSIX `0600` permissions, atomic rename writing |
| **Bounded lease contract** | **this pack** | Short-lived TTL secret leases (`wellmanifest.secrets/lease/v1`) |
| AuthN profile ids & binding receipts | `auth-lifecycle` | ADOPT |
| AuthZ machine grants / revocations | `authority-lifecycle` | ADOPT |
| Tool runtimes with secret-free receipts | `account-runtime` | Tool runtimes receive bounded leases, never raw credentials |
| Node.js Vault runtime | `subactor/credential-vault` | Concrete implementation of encrypted vault |
| Python Vault client | `subactor_credential_vault` | Concrete bounded lease client in Python |
| Cluster mesh vault | `paxlet-com/taskand` | `proc://taskand.dev/vault/secrets/v1` |
| Coordinator / Desktop automation | `willops` / `willman` | Secret storage adapter for wFirma, bank APIs, cloud credentials |

---

## Core Principles

1. **Envelope Authenticity (`SECRET-STORE-001`)**: All at-rest credentials MUST be stored in authenticated symmetric envelopes (`aes-256-gcm`) containing ciphertext, IV (12 bytes), and authentication tag (16 bytes). Unauthenticated modes (such as ECB/CBC without HMAC) are strictly prohibited.
2. **Strict POSIX Permissions (`SECRET-STORE-002`)**: Local secret files MUST have permissions `0600` (`rw-------`). Parent directories MUST be restricted to `0700`.
3. **Atomic Persistence (`SECRET-STORE-003`)**: Updates to secret stores MUST be written to an adjacent temporary file (`.tmp`) and atomically renamed (`rename(2)`), preventing race conditions or corrupted partial writes.
4. **Origin-Bound Access (`SECRET-STORE-004`)**: Secrets are strictly bound to their target network origin (e.g. `https://wfirma.pl`, `https://api2.wfirma.pl`). Origins MUST NOT include credentials, queries, or relative paths.
5. **No Secret In Leak Points (`SECRET-STORE-005`)**: Plaintext secrets MUST NEVER appear in URLs, error messages, logging streams, terminal output, git commits, or serialized execution receipts.
6. **Bounded Leasing over Permanent Access (`SECRET-STORE-006`)**: Agents and workers access credentials via short-lived leases (e.g. 15–300s) minted against verified grant and purpose contexts.

---

## Artifacts

- **Specification**: [`docs/SPEC.md`](docs/SPEC.md)
- **Architecture & Comparison**: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- **Adoption Guide**: [`docs/ADOPTION_GUIDE.md`](docs/ADOPTION_GUIDE.md)
- **Schemas**:
  - [`schemas/credential-envelope.schema.json`](schemas/credential-envelope.schema.json)
  - [`schemas/vault-manifest.schema.json`](schemas/vault-manifest.schema.json)
  - [`schemas/secret-lease.schema.json`](schemas/secret-lease.schema.json)
- **Conformance Test Suite**: [`standard/conformance.py`](standard/conformance.py)

---

## Conformance Verification

Verify full compliance without third-party dependencies:

```bash
python3 standard/conformance.py --all
```

Checks schema integrity, digest validity, cryptographic envelope constraints, origin binding enforcement, and fail-closed error behaviors.

## License

Licensed under Apache-2.0.
