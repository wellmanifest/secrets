#!/usr/bin/env python3
"""Dependency-free conformance checker for wellmanifest/secrets v0.1.0-dev."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.parse

ROOT = Path(__file__).resolve().parent
PACK = ROOT.parent

REQUIRED_DOCS = (
    PACK / "README.md",
    PACK / "AGENTS.md",
    PACK / "GEMINI.md",
    PACK / "VERSION",
    PACK / "dsl-manifest.json",
    PACK / "docs/SPEC.md",
    PACK / "docs/ARCHITECTURE.md",
    PACK / "docs/ADOPTION_GUIDE.md",
    PACK / "schemas/credential-envelope.schema.json",
    PACK / "schemas/vault-manifest.schema.json",
    PACK / "schemas/secret-lease.schema.json",
)

ALLOWED_SCHEMES = frozenset({"https", "http", "imaps", "smtps", "postgres", "postgresql"})
ALLOWED_CIPHERS = frozenset({"aes-256-gcm"})
ALLOWED_FIELDS = frozenset({
    "api_key", "secret_key", "access_token", "username", "password", "app_key", "totp_seed"
})

VALID_FIXTURES = (
    ROOT / "fixtures/valid/envelope-wfirma.json",
    ROOT / "fixtures/valid/vault-manifest.json",
    ROOT / "fixtures/valid/lease-wfirma.json",
)

INVALID_FIXTURES = {
    ROOT / "fixtures/invalid/envelope-missing-tag.json": "SECRET_ENVELOPE_INVALID",
    ROOT / "fixtures/invalid/envelope-insecure-cipher.json": "SECRET_CIPHER_UNSUPPORTED",
    ROOT / "fixtures/invalid/manifest-invalid-origin.json": "SECRET_ORIGIN_INVALID",
    ROOT / "fixtures/invalid/manifest-wildcard-origin.json": "SECRET_ORIGIN_INVALID",
}

IDENTIFIER_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,159}$")
SCOPE_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9._*:/-]{0,199}$")


class ConformanceError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        raise ConformanceError("SECRET_ENVELOPE_INVALID", f"Invalid JSON in {path.name}: {error}") from error
    if not isinstance(data, dict):
        raise ConformanceError("SECRET_ENVELOPE_INVALID", f"Expected JSON object in {path.name}")
    return data


def validate_origin(origin: str) -> str:
    if not origin or "*" in origin:
        raise ConformanceError("SECRET_ORIGIN_INVALID", f"Wildcard or empty origin not allowed: {origin!r}")
    try:
        parsed = urllib.parse.urlsplit(origin)
    except Exception as error:
        raise ConformanceError("SECRET_ORIGIN_INVALID", f"Failed to parse origin URI: {origin!r}") from error

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ConformanceError("SECRET_ORIGIN_INVALID", f"Unsupported scheme in origin: {parsed.scheme!r}")
    if not parsed.netloc:
        raise ConformanceError("SECRET_ORIGIN_INVALID", f"Origin missing host/netloc: {origin!r}")
    if parsed.username or parsed.password:
        raise ConformanceError("SECRET_ORIGIN_INVALID", "Origin MUST NOT contain user credentials")
    if parsed.query or parsed.fragment:
        raise ConformanceError("SECRET_ORIGIN_INVALID", "Origin MUST NOT contain query or fragment")
    if parsed.path and parsed.path != "/":
        raise ConformanceError("SECRET_ORIGIN_INVALID", f"Origin MUST NOT contain URL path: {parsed.path!r}")
    return f"{parsed.scheme}://{parsed.netloc}"


def validate_envelope(doc: dict) -> None:
    if doc.get("schema") != "wellmanifest.secrets/envelope/v1":
        raise ConformanceError("SECRET_ENVELOPE_INVALID", f"Invalid envelope schema: {doc.get('schema')}")
    if doc.get("version") != 1:
        raise ConformanceError("SECRET_ENVELOPE_INVALID", f"Unsupported version: {doc.get('version')}")

    algorithm = doc.get("algorithm")
    if algorithm not in ALLOWED_CIPHERS:
        raise ConformanceError("SECRET_CIPHER_UNSUPPORTED", f"Disallowed cipher: {algorithm!r}")

    for field in ("iv", "tag", "ciphertext"):
        val = doc.get(field)
        if not val or not isinstance(val, str):
            raise ConformanceError("SECRET_ENVELOPE_INVALID", f"Envelope missing required field: {field}")


def validate_manifest(doc: dict) -> None:
    if doc.get("schema") != "wellmanifest.secrets/vault-manifest/v1":
        raise ConformanceError("SECRET_ENVELOPE_INVALID", f"Invalid manifest schema: {doc.get('schema')}")
    if doc.get("version") != 1:
        raise ConformanceError("SECRET_ENVELOPE_INVALID", f"Unsupported manifest version: {doc.get('version')}")

    entries = doc.get("entries")
    if not isinstance(entries, list):
        raise ConformanceError("SECRET_ENVELOPE_INVALID", "Manifest entries must be an array")

    for entry in entries:
        if not isinstance(entry, dict):
            raise ConformanceError("SECRET_ENVELOPE_INVALID", "Entry must be an object")
        entry_id = entry.get("id", "")
        if not IDENTIFIER_RE.match(entry_id):
            raise ConformanceError("SECRET_ENVELOPE_INVALID", f"Invalid entry id: {entry_id!r}")

        validate_origin(str(entry.get("origin") or ""))

        scope = entry.get("scope") or {}
        ops = scope.get("operations")
        targets = scope.get("targets")
        if not isinstance(ops, list) or not ops or not isinstance(targets, list) or not targets:
            raise ConformanceError("SECRET_SCOPE_DENIED", "Scope requires operations and targets")
        for op in ops:
            if not SCOPE_TOKEN_RE.match(str(op)):
                raise ConformanceError("SECRET_SCOPE_DENIED", f"Invalid operation token: {op!r}")
        for target in targets:
            if not SCOPE_TOKEN_RE.match(str(target)):
                raise ConformanceError("SECRET_SCOPE_DENIED", f"Invalid target token: {target!r}")

        envelope = entry.get("envelope")
        if not isinstance(envelope, dict):
            raise ConformanceError("SECRET_ENVELOPE_INVALID", "Entry missing envelope object")
        validate_envelope(envelope)


def validate_lease(doc: dict) -> None:
    if doc.get("schema") != "wellmanifest.secrets/lease/v1":
        raise ConformanceError("SECRET_ENVELOPE_INVALID", f"Invalid lease schema: {doc.get('schema')}")
    field = doc.get("field")
    if field not in ALLOWED_FIELDS:
        raise ConformanceError("SECRET_ENVELOPE_INVALID", f"Disallowed field: {field!r}")
    validate_origin(str(doc.get("origin") or ""))
    ttl = doc.get("expires_in_seconds")
    if not isinstance(ttl, int) or ttl < 5 or ttl > 86400:
        raise ConformanceError("SECRET_ENVELOPE_INVALID", f"Invalid TTL: {ttl}")


def validate_document(doc: dict) -> None:
    schema = doc.get("schema")
    if schema == "wellmanifest.secrets/envelope/v1":
        validate_envelope(doc)
    elif schema == "wellmanifest.secrets/vault-manifest/v1":
        validate_manifest(doc)
    elif schema == "wellmanifest.secrets/lease/v1":
        validate_lease(doc)
    else:
        raise ConformanceError("SECRET_ENVELOPE_INVALID", f"Unknown schema {schema!r}")


def check_docs() -> None:
    missing = [str(p.relative_to(PACK)) for p in REQUIRED_DOCS if not p.is_file()]
    if missing:
        raise ConformanceError("MISSING_DOCS", f"Missing required specification files: {missing}")
    print(f"✓ All {len(REQUIRED_DOCS)} required documents and schemas present.")


def check_fixtures() -> None:
    # 1. Valid fixtures must pass
    for path in VALID_FIXTURES:
        if not path.is_file():
            raise ConformanceError("MISSING_FIXTURE", f"Valid fixture missing: {path.name}")
        doc = load_json(path)
        validate_document(doc)
        print(f"✓ Valid fixture passed: {path.name}")

    # 2. Invalid fixtures must fail closed with expected codes
    for path, expected_code in INVALID_FIXTURES.items():
        if not path.is_file():
            raise ConformanceError("MISSING_FIXTURE", f"Invalid fixture missing: {path.name}")
        doc = load_json(path)
        try:
            validate_document(doc)
            raise AssertionError(f"Invalid fixture {path.name} unexpectedly passed!")
        except ConformanceError as exc:
            if exc.code != expected_code:
                raise ConformanceError(
                    "UNEXPECTED_ERROR_CODE",
                    f"Fixture {path.name} raised {exc.code} but expected {expected_code}"
                ) from exc
            print(f"✓ Invalid fixture rejected as expected ({exc.code}): {path.name}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Wellmanifest Secrets Conformance Checker")
    parser.add_argument("--all", action="store_true", help="Run all conformance checks")
    args = parser.parse_args()

    print("=== Wellmanifest Secrets Conformance Suite ===")
    try:
        check_docs()
        check_fixtures()
        print("\nAll conformance tests PASSED. Status: COMPLIANT.")
        return 0
    except ConformanceError as exc:
        print(f"\nFAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
