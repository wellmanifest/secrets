# GEMINI.md

This file is the Gemini / Antigravity entry point for `wellmanifest/secrets`.
The normative instructions are in [AGENTS.md](AGENTS.md).

This domain pack follows the `wellmanifest/new-project` policy-as-code standard.
Fail-closed:
1. Adhere to the boundary matrix in [README.md](README.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
2. Validate envelope cryptography against [schemas/credential-envelope.schema.json](schemas/credential-envelope.schema.json).
3. Ensure conformance checks pass: `python3 standard/conformance.py --all`.
