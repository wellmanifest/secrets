# Subactor & AI agent instructions (wellmanifest/secrets)

HOME vs ADOPT: this pack is `HOME wellmanifest`, `shape domain_pack`
(normative secret storage, credential envelope, and bounded lease standard).
It does **not** HOME runtime services, host servers, or physical secret material.
Runtimes (such as `@subactor/credential-vault`, `taskand/vault`, `willman_ops/vault`)
ADOPT this standard for envelope serialization, origin constraints, and lease protocols.

Closed vocabulary:
- `HOME` wellmanifest|subactor|semcod;
- `SHAPE` domain_pack|runtime_service|both;
- `ADOPT` wellmanifest/new-project, wellmanifest/authority-lifecycle, wellmanifest/account-runtime.

Fail-closed rules:
1. Never commit plaintext secrets, private keys, or credentials to git or documentation.
2. Enforce mode 0600 on all persistent secret files.
3. Validate origin and scope before minting or returning secret leases.
4. Run `python3 standard/conformance.py --all` before claiming conformance.
