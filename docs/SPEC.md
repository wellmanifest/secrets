# Wellmanifest Secrets Specification (`wellmanifest/secrets`)

Version: `0.1.0-dev`  
Domain: `secrets-credential-vault`  
Standard Status: Normative Specification

---

## 1. Scope and Purpose

This specification governs the secure storage, cryptographic envelope format,
origin-bound access authorization, and lifecycle leasing of machine and user
credentials across all Wellmanifest-governed repositories.

Implementations conforming to this standard guarantee:
- Confidentiality and integrity of at-rest credentials;
- Fail-closed denial of unauthorized origins and operations;
- Elimination of plaintext credentials in logs, URLs, errors, and VCS;
- Bounded, auditable runtime leases.

---

## 2. Cryptographic Envelopes

### 2.1 Algorithm Requirement (`SECRET-CRYPT-001`)
All symmetric credential payloads MUST be encrypted using **AES-256-GCM**
(Galois/Counter Mode).
- **Key Length**: 256 bits (32 bytes).
- **Initialization Vector (IV)**: MUST be exactly 96 bits (12 bytes), generated
  from a cryptographically secure pseudorandom number generator (CSPRNG).
  An IV MUST NEVER be reused with the same key.
- **Authentication Tag**: MUST be exactly 128 bits (16 bytes).

Unauthenticated modes (such as ECB or unverified CBC) MUST NOT be used.

### 2.2 Key Derivation Function (`SECRET-CRYPT-002`)
When deriving the 256-bit encryption key from a user passphrase or cluster secret:
1. **Primary KDF**: `scrypt` with parameters:
   - $N = 16384$ ($2^{14}$)
   - $r = 8$
   - $p = 1$
   - Output key length: 32 bytes
   - Salt: CSPRNG minimum 16 bytes.
2. **Deterministic Service Key Fallback**: SHA-256 digest of a high-entropy
   machine secret (minimum 256-bit entropy).

---

## 3. Storage and Persistence

### 3.1 POSIX Permissions (`SECRET-STORE-001`)
Local files holding credential envelopes or vault stores:
- File permissions MUST be strictly **`0600`** (`rw-------`, owner only).
- Enclosing directories MUST be restricted to **`0700`** (`rwx------`).
- Verification MUST occur prior to reading or writing. Files with group or
  other read/write permissions MUST be rejected with error `SECRET_STORE_PERMISSIONS_INVALID`.

### 3.2 Atomic Persistence (`SECRET-STORE-002`)
All writes to vault stores MUST follow atomic write procedures:
1. Write JSON data to a sibling file: `${filename}.${pid}.${uuid}.tmp` with mode `0600`.
2. Flush and sync to disk.
3. Perform atomic replacement via POSIX `rename(2)`.
4. Enforce `chmod 0600` on the final path.

---

## 4. Origin & Scope Binding

### 4.1 Origin Normalization (`SECRET-ORIGIN-001`)
Credentials MUST be bound to a normalized RFC 3986 network origin:
- Allowed schemes: `https:`, `http:` (loopback only), `imaps:`, `smtps:`,
  `postgres:`, `postgresql:`.
- Origins MUST consist only of `scheme://host[:port]`.
- Origins MUST NOT contain username, password, URL path, query string, or hash fragments.
- Path traversal, wildcard origins (`*`), or scheme-less origins MUST be rejected with
  `SECRET_ORIGIN_INVALID`.

### 4.2 Scope Authorization (`SECRET-SCOPE-001`)
Every entry defines:
- `operations`: e.g. `["accounting.read", "accounting.write"]`
- `targets`: e.g. `["provider:wfirma", "database:kpir"]`

A lease request for an operation or target outside the declared set MUST be
rejected with `SECRET_SCOPE_DENIED`.

---

## 5. Execution Boundary & Bounded Leasing

### 5.1 Runtime Leases (`SECRET-LEASE-001`)
Consumers MUST NOT bulk-export or cache plaintext secrets across task boundaries.
When an agent or tool requires a secret:
1. A lease request is submitted with:
   - `entry_id`: target entry
   - `origin`: matching origin
   - `field`: requested secret field
   - `actor`: execution identity (e.g. `service:willman-coordinator`)
   - `purpose`: matching declared operation
   - `ticket_id`: optional active ticket context
2. The vault verifies origin and scope, decrypts only the requested field,
   and returns a short-lived lease with a defined TTL (typically 15 to 300 seconds).
3. The returned lease secret object MUST mask its representation:
   `LeaseSecret(value='****', lease_id='...', expires_in_seconds=60)`.

### 5.2 Masking and Leak Prevention (`SECRET-LEAK-001`)
1. All public list operations MUST return masked values: `"••••••••"`.
2. URLs, log outputs, CLI status messages, and error traces MUST NEVER embed
   passwords, API tokens, or bearer headers.

---

## 6. Error Taxonomy

Conforming implementations MUST use stable error codes:

| Error Code | HTTP Status | Meaning |
| :--- | :--- | :--- |
| `SECRET_STORE_UNAVAILABLE` | 503 | Store file does not exist or cannot be read |
| `SECRET_STORE_PERMISSIONS_INVALID` | 500 | Permissions are broader than mode 0600 |
| `SECRET_ENVELOPE_INVALID` | 422 | Envelope JSON, IV, tag, or ciphertext corrupted |
| `SECRET_CIPHER_UNSUPPORTED` | 400 | Encryption algorithm is not aes-256-gcm |
| `SECRET_ORIGIN_INVALID` | 400 | Origin contains invalid scheme, credentials, or path |
| `SECRET_ORIGIN_MISMATCH` | 403 | Requested origin does not match stored origin |
| `SECRET_SCOPE_DENIED` | 403 | Requested operation or target is not in entry scope |
| `SECRET_ENTRY_NOT_FOUND` | 404 | entry_id does not exist |
| `SECRET_LEASE_EXPIRED` | 410 | Lease TTL has lapsed |
