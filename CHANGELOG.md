# Changelog (wellmanifest/secrets)

## [0.1.0-dev] - 2026-10-04

### Added
- Initial domain pack bootstrap (`ticket-001`).
- Cryptographic envelope schema (`schemas/credential-envelope.schema.json`) requiring AES-256-GCM.
- Vault manifest schema (`schemas/vault-manifest.schema.json`) with RFC 3986 origin validation and scope control.
- Secret lease schema (`schemas/secret-lease.schema.json`) for short-lived runtime access.
- Normative specification (`docs/SPEC.md`), architecture comparison (`docs/ARCHITECTURE.md`), and adoption guide (`docs/ADOPTION_GUIDE.md`).
- Self-contained conformance verification suite (`standard/conformance.py`).
