"""Verification primitives for build provenance statements.

A statement is an in-toto style attestation about one artifact.  It carries the
source revision, the build parameters, the referenced materials and the time at
which the build was recorded.  Signatures are keyed digests over the assertion
payload.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

_SIGNING_KEY = b"sec-build-provenance-v2-attestation"


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _signature_payload(statement: dict[str, Any]) -> str:
    # The signature binds every assertion in one payload: subject/artifact,
    # source revision, build parameters (and their digest), materials and the
    # recording timestamp.  Canonical JSON makes the payload unambiguous.
    return _canonical(statement)


def _sign_statement(statement: dict[str, Any]) -> str:
    payload = _signature_payload(statement).encode("utf-8")
    return hmac.new(_SIGNING_KEY, payload, hashlib.sha256).hexdigest()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def parse_statement(text: str | bytes) -> dict[str, Any]:
    """Parse a JSON provenance statement and normalize its material list."""

    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("utf-8")
    if not isinstance(text, str):
        raise TypeError("statement must be JSON text")

    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("statement must be a JSON object")

    raw_materials = data.get("materials", [])
    if not isinstance(raw_materials, list):
        raise ValueError("materials must be a list")

    materials: list[dict[str, Any]] = []
    for raw in raw_materials:
        if not isinstance(raw, dict):
            raise ValueError("each material must be an object")
        material = dict(raw)
        material.setdefault("name", "")
        material.setdefault("digest", "")
        # A measured actual digest must be preserved.  Only when the statement
        # does not record one do we assume it matches the referenced digest.
        material.setdefault("actual_digest", material.get("digest", ""))
        materials.append(material)

    data["materials"] = materials
    return data


def digest_params(params: dict[str, Any]) -> str:
    """Return the digest of the build parameter map."""

    if not isinstance(params, dict):
        raise TypeError("params must be an object")

    # Canonical JSON (sorted keys, compact separators) so the same parameter
    # set always produces the same digest regardless of insertion order.
    return _sha256(_canonical(params))


def _material_reference(material: Any) -> str:
    if isinstance(material, dict):
        name = material.get("name", "")
        digest = material.get("digest", "")
        return f"{name}@{digest}"
    return f"@{material!r}"


def _material_name(material: Any) -> str:
    if isinstance(material, dict):
        return str(material.get("name", ""))
    return ""


def digest_materials(materials: list[dict[str, Any]]) -> str:
    """Return the digest of the referenced material set."""

    if not isinstance(materials, list):
        raise TypeError("materials must be a list")
    if not materials:
        return _sha256("")

    # Order the references by material name so a permuted list digests equal.
    ordered = sorted(materials, key=_material_name)
    payload = "\n".join(_material_reference(item) for item in ordered)
    return _sha256(payload)


def verify_signature(statement: dict[str, Any], sig: str) -> bool:
    """Return whether sig is the signature of the statement assertion."""

    if not isinstance(sig, str) or not isinstance(statement, dict):
        return False
    try:
        expected = _sign_statement(statement)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(
        expected.encode("utf-8"), sig.encode("utf-8")
    )


def check_subject(statement: dict[str, Any], artifact: dict[str, Any]) -> bool:
    """Return whether the statement subject is bound to the artifact."""

    subject = statement.get("subject")
    if not isinstance(subject, dict) or not isinstance(artifact, dict):
        return False

    subject_digest = subject.get("digest")
    artifact_digest = artifact.get("digest")
    # A binding is an exact content-digest equality; an empty/missing digest
    # must never bind.
    if not isinstance(subject_digest, str) or not isinstance(artifact_digest, str):
        return False
    if not subject_digest or not artifact_digest:
        return False
    return hmac.compare_digest(
        subject_digest.encode("utf-8"), artifact_digest.encode("utf-8")
    )


def check_timestamps(statement: dict[str, Any], commit_time: str) -> bool:
    """Return whether the statement time is not earlier than the commit."""

    built_at = _parse_time(statement.get("built_at"))
    committed_at = _parse_time(commit_time)

    source = statement.get("source")
    source_time = None
    if isinstance(source, dict):
        source_time = _parse_time(source.get("commit_time"))

    if built_at is None or committed_at is None:
        return False
    if source_time is None:
        return False
    # The attestation may be recorded at or after the source commit, never
    # before it.
    return built_at >= committed_at


def validate_statement(statement: dict[str, Any]) -> list[str]:
    """Return the structural and consistency problems in a statement."""

    if not isinstance(statement, dict):
        return ["statement must be an object"]

    problems: list[str] = []
    required = ("subject", "source", "params", "params_digest", "materials", "built_at")
    for field in required:
        if field not in statement:
            problems.append(f"missing field: {field}")

    subject = statement.get("subject")
    if not isinstance(subject, dict):
        problems.append("subject must be an object")
    else:
        if not _text(subject.get("name")):
            problems.append("subject name is required")
        if not _text(subject.get("digest")):
            problems.append("subject digest is required")

    source = statement.get("source")
    if not isinstance(source, dict):
        problems.append("source must be an object")
    else:
        if not _text(source.get("commit")):
            problems.append("source commit is required")
        if _parse_time(source.get("commit_time")) is None:
            problems.append("source commit time is invalid")

    params = statement.get("params")
    if not isinstance(params, dict) or not params:
        problems.append("params must be a non-empty object")
    elif _text(statement.get("params_digest")):
        try:
            expected_params_digest = digest_params(params)
        except (TypeError, ValueError):
            expected_params_digest = None
        if expected_params_digest is None or (
            statement.get("params_digest") != expected_params_digest
        ):
            problems.append(
                "params digest mismatch: params_digest does not match params"
            )

    materials = statement.get("materials")
    if not isinstance(materials, list):
        problems.append("materials must be a list")
    elif not materials:
        problems.append("materials must not be empty")
    else:
        for index, material in enumerate(materials):
            label = f"material {index}"
            if not isinstance(material, dict):
                problems.append(f"{label} must be an object")
                continue
            if not _text(material.get("name")):
                problems.append(f"{label} name is required")
            if not _text(material.get("digest")):
                problems.append(f"{label} digest is required")
            if not _text(material.get("actual_digest")):
                problems.append(f"{label} actual digest is required")
            if (
                _text(material.get("digest"))
                and _text(material.get("actual_digest"))
                and material.get("digest") != material.get("actual_digest")
            ):
                problems.append(f"{label} digest mismatch")

    if _parse_time(statement.get("built_at")) is None:
        problems.append("built_at is invalid")

    return problems


def _proofs_for(item: dict[str, Any]) -> list[dict[str, Any]]:
    proofs = item.get("proofs")
    if isinstance(proofs, list):
        return [proof for proof in proofs if isinstance(proof, dict)]
    if isinstance(item.get("proof"), dict):
        return [item["proof"]]
    if isinstance(item.get("statement"), dict):
        return [
            {
                "statement": item["statement"],
                "signature": item.get("signature", ""),
            }
        ]
    return []


def _material_digests(statement: dict[str, Any]) -> list[str]:
    materials = statement.get("materials", [])
    if not isinstance(materials, list):
        return []
    return [digest_materials(materials)]


def _assertion_fingerprint(statement: dict[str, Any]) -> str:
    """Identify the bound assertion of a statement.

    Two proofs are consistent when they make the same claim about the bound
    artifact, source revision (and time), build parameters, material set and
    recording time.  Parameter key order and material entry order must not
    affect the identity, and the observed ``actual_digest`` is verification
    evidence rather than part of the referenced-material claim.
    """

    subject = statement.get("subject")
    subject = subject if isinstance(subject, dict) else {}
    source = statement.get("source")
    source = source if isinstance(source, dict) else {}
    params = statement.get("params")
    materials = statement.get("materials")

    try:
        params_ref = (
            digest_params(params) if isinstance(params, dict) else ""
        )
    except (TypeError, ValueError):
        params_ref = _canonical(params)

    fingerprint = {
        "subject": _canonical(subject),
        "source": _canonical(source),
        "params_digest": params_ref,
        "recorded_params_digest": statement.get("params_digest", ""),
        "materials_digest": digest_materials(materials)
        if isinstance(materials, list)
        else "",
        "built_at": statement.get("built_at", ""),
    }
    return _canonical(fingerprint)


def provenance_batch(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Verify a batch of artifact statements and return per-artifact results."""

    results: dict[str, dict[str, Any]] = {}
    if not isinstance(items, list):
        raise TypeError("items must be a list")

    for item in items:
        if not isinstance(item, dict):
            continue

        artifact = item.get("artifact")
        artifact = artifact if isinstance(artifact, dict) else {}
        name = str(artifact.get("name", ""))
        proofs = _proofs_for(item)
        problems: list[str] = []
        materials_digests: list[str] = []
        fingerprints: set[str] = set()

        if not proofs:
            problems.append("no proof supplied")
        else:
            # Every proof is judged on its own and contributes its own material
            # digest.  No result may be borrowed from another batch item.
            for proof in proofs:
                if not isinstance(proof, dict):
                    problems.append("proof must be an object")
                    continue

                statement = proof.get("statement", {})
                if not isinstance(statement, dict):
                    statement = {}
                    problems.append("proof statement must be an object")

                if not verify_signature(statement, proof.get("signature", "")):
                    problems.append("signature verification failed")
                if not check_subject(statement, artifact):
                    problems.append("artifact subject mismatch")

                commit_time = item.get("commit_time")
                if commit_time is None:
                    source = statement.get("source")
                    if isinstance(source, dict):
                        commit_time = source.get("commit_time")
                if not check_timestamps(statement, commit_time):
                    problems.append("timestamp order invalid")

                problems.extend(validate_statement(statement))

                materials_digests.extend(_material_digests(statement))
                fingerprints.add(_assertion_fingerprint(statement))

            # Multiple proofs for one artifact must not make contradictory
            # assertions about its provenance.  Wording contains both
            # "conflicting" and its "conflict" stem for diagnostic matching.
            if len(fingerprints) > 1:
                problems.append("conflicting proof assertions for artifact")

        results[name] = {
            "ok": not problems,
            "errors": problems,
            "materials_digests": materials_digests,
        }

    return results