# Wellmanifest Secrets Adoption & Migration Guide

This guide details how to adopt `wellmanifest/secrets` across all repositories
identified during ecosystem dependency auditing.

---

## 1. `paxlet-com/willman` and `willops` (Accounting & Desktop Automation)

### Current State
- Plain JSON file: `~/.config/wfirma/credentials.json` with permissions `0600`.
- Environment variable overrides: `WFIRMA_ACCESS_KEY`, `WFIRMA_SECRET_KEY`.

### Target Architecture
1. **Envelope Storage**:
   Migrate `~/.config/wfirma/credentials.json` to an authenticated envelope:
   ```json
   {
     "schema": "wellmanifest.secrets/envelope/v1",
     "version": 1,
     "algorithm": "aes-256-gcm",
     "kdf": {
       "type": "scrypt",
       "salt": "..."
     },
     "iv": "...",
     "tag": "...",
     "ciphertext": "..."
   }
   ```
2. **Master Key**:
   - Primary: `WILLMAN_VAULT_KEY` or `TASKAND_VAULT_KEY` environment variable.
   - Fallback: Machine-derived machine-id key or system keyring.
   - Compatibility Mode: If plaintext JSON is present and no vault key is set, log a deprecation warning and load as unencrypted fallback (ensuring zero disruption to live operations).

---

## 2. `paxlet-com/willmux` (Multi-Node Terminal & GUI Orchestrator)

### Current State
- `agent/willmux_agent/core.py`: `self.vault: dict[str, dict] = {}` (in-memory only).
- When environments (`env_id`) are created, secrets are placed in memory without encryption or origin binding.

### Target Architecture
1. Replace `dict` storage with an envelope-backed store or bounded client.
2. Bind secrets per environment origin (e.g. `ssh://192.168.188.201`, `http://127.0.0.1:8781`).
3. Ensure secrets injected into remote nodes (e.g. Minis or Lenovo clones) are transmitted in encrypted envelopes rather than raw command args.

---

## 3. `paxlet-com/taskand` (Agent Mesh & Task Hub)

### Current State
- `taskand/vault/secrets.json` uses AES-256-GCM and scrypt (`generated/registry/core/taskand.dev/v1/vault.mjs`).
- Variable: `TASKAND_VAULT_KEY`.

### Alignment Steps
1. Align envelope schema to `"wellmanifest.secrets/envelope/v1"`.
2. Add explicit `origin` and `scope` metadata to entries.
3. Validate permissions `0600` in `openSecret()`.

---

## 4. `subactor/credential-vault` & `subactor_credential_vault`

### Status
`subactor/credential-vault` serves as the reference runtime implementation.
It already satisfies:
- AES-256-GCM authenticated envelopes;
- Atomic persistence with mode 0600;
- Origin-bound reads and scope validation;
- Python client `from subactor_credential_vault import VaultLeaseClient`.

### Next Step
Pin compatibility with `wellmanifest.secrets/envelope/v1` in `package.json` and Python metadata.

---

## 5. `subactor/supervisor` (Daemon & Service Mesh)

### Status
Uses dual backend:
- `BrowserAgentVaultClient` (connecting to `subactor/credential-vault` on port 8130).
- HashiCorp Vault KV v2 adapter (`src/secrets/vault.js`).

### Next Step
Standardize lease receipt logging according to `schemas/secret-lease.schema.json`.
