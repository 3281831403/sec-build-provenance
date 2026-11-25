import copy
import hashlib
import json

from provenance import verify as v


def _h(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _digest(seed: str) -> str:
    return "sha256:" + _h(seed)


def _params_digest(params: dict) -> str:
    payload = json.dumps(
        params,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return _h(payload)


def _materials_digest(materials: list[dict]) -> str:
    ordered = sorted(materials, key=lambda item: item["name"])
    payload = "\n".join(
        f'{item["name"]}@{item["digest"]}' for item in ordered
    )
    return _h(payload)


def _material(name: str, seed: str, actual_seed: str | None = None) -> dict:
    digest = _digest(seed)
    return {
        "name": name,
        "digest": digest,
        "actual_digest": _digest(actual_seed if actual_seed is not None else seed),
    }


def _statement(
    *,
    artifact: str = "app.tar.gz",
    artifact_seed: str = "app",
    commit: str = "9f1c0d2e4b6a8c7d5e3f1a0b2c4d6e8f0a1b3c5d",
    params: dict | None = None,
    materials: list[dict] | None = None,
    built_at: str = "2026-11-01T11:30:00+00:00",
) -> dict:
    params = params if params is not None else {
        "arch": "amd64",
        "flags": ["-O2", "-pipe"],
        "reproducible": True,
    }
    materials = materials if materials is not None else [
        _material("base-image", "base-image"),
    ]
    return {
        "subject": {"name": artifact, "digest": _digest(artifact_seed)},
        "source": {
            "commit": commit,
            "commit_time": "2026-11-01T10:00:00+00:00",
        },
        "params": copy.deepcopy(params),
        "params_digest": _params_digest(params),
        "materials": copy.deepcopy(materials),
        "built_at": built_at,
    }


def _item(statement: dict) -> dict:
    return {
        "artifact": copy.deepcopy(statement["subject"]),
        "proofs": [
            {
                "statement": statement,
                "signature": v._sign_statement(statement),
            }
        ],
    }


def test_parse_statement_preserves_material_reference() -> None:
    statement = _statement(
        materials=[
            {
                "name": "base-image",
                "digest": _digest("claimed-material"),
                "actual_digest": _digest("actual-material"),
            }
        ]
    )

    parsed = v.parse_statement(json.dumps(statement))

    assert parsed["materials"][0]["actual_digest"] == _digest("actual-material")
    problems = v.validate_statement(parsed)
    assert any(
        "material" in problem and "digest" in problem for problem in problems
    )


def test_digest_params_is_key_order_independent() -> None:
    first = {"z": "last", "a": "first", "nested": {"y": 2, "x": 1}}
    second = {"nested": {"x": 1, "y": 2}, "a": "first", "z": "last"}

    assert v.digest_params(first) == v.digest_params(second)
    assert v.digest_params(first) == _params_digest(first)


def test_verify_signature_covers_entire_statement() -> None:
    statement = _statement()
    signature = v._sign_statement(statement)

    assert v.verify_signature(statement, signature) is True

    tampered = copy.deepcopy(statement)
    tampered["params"]["arch"] = "arm64"
    tampered["params_digest"] = _params_digest(tampered["params"])

    assert v.verify_signature(tampered, signature) is False


def test_check_subject_binds_exact_digest() -> None:
    statement = _statement()
    wrong_artifact = {
        "name": statement["subject"]["name"],
        "digest": _digest("different-artifact"),
    }

    assert len(wrong_artifact["digest"]) == len(statement["subject"]["digest"])
    assert v.check_subject(statement, statement["subject"]) is True
    assert v.check_subject(statement, wrong_artifact) is False


def test_batch_artifacts_remain_independent() -> None:
    first = _statement(
        artifact="first.tar.gz",
        artifact_seed="first-artifact",
        materials=[_material("first-base", "first-base")],
    )
    second = _statement(
        artifact="second.tar.gz",
        artifact_seed="second-artifact",
        materials=[_material("second-base", "second-base")],
    )

    results = v.provenance_batch([_item(first), _item(second)])

    assert results["first.tar.gz"]["ok"] is True
    assert results["second.tar.gz"]["ok"] is True
    assert results["second.tar.gz"]["materials_digests"] == [
        _materials_digest(second["materials"])
    ]