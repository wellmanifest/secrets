# Ticket 001: Bootstrap wellmanifest/secrets domain pack

## Intent

Establish `wellmanifest/secrets` as the normative Wellmanifest standard for
encrypted credential envelopes, origin-bound secret storage, and bounded leases.
This provides the authoritative standard to unify secret management across:
- `paxlet-com/willman` and `willops` (accounting API keys, banking credentials)
- `paxlet-com/willmux` (environment secret injection)
- `paxlet-com/taskand` (mesh cluster secret storage)
- `subactor/credential-vault` and `subactor_credential_vault` (runtime implementation)
- `subactor/supervisor` (service leases)

## Acceptance criteria

- [x] AC-01: Standard pack repository structure established with `HOME wellmanifest` and `shape domain_pack`.
- [x] AC-02: Cryptographic envelope schema (`schemas/credential-envelope.schema.json`) requiring authenticated AES-256-GCM.
- [x] AC-03: Storage manifest schema (`schemas/vault-manifest.schema.json`) enforcing normalized RFC 3986 network origins and typed scopes.
- [x] AC-04: Bounded secret lease schema (`schemas/secret-lease.schema.json`).
- [x] AC-05: Normative specification (`docs/SPEC.md`), architecture comparison (`docs/ARCHITECTURE.md`), and adoption guide (`docs/ADOPTION_GUIDE.md`).
- [x] AC-06: Zero-dependency conformance checker (`standard/conformance.py --all`) validating documents and valid/invalid fixtures fail-closed.
- [x] AC-07: Registered in `wellmanifest/repos.manifest`.
