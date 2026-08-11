import pytest
from main import evaluate_release_gate


def get_base_preview_payload():
    return {
        "target": "preview",
        "event": "pull_request",
        "ref": "refs/heads/feature-branch",
        "workflow": {
            "trigger": "pull_request",
            "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "actions": [{"owner": "actions", "name": "checkout", "ref": "v4"}],
        },
        "image": {
            "multiStage": True,
            "runsAsRoot": False,
            "secretMode": "none",
            "criticalVulnerabilities": 0,
            "digestPinned": True,
        },
    }


def get_base_production_payload():
    return {
        "target": "production",
        "event": "push",
        "ref": "refs/heads/main",
        "workflow": {
            "trigger": "push",
            "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "environmentApproval": True,
            "actions": [
                {"owner": "actions", "name": "checkout", "ref": "v4"},
                {
                    "owner": "docker",
                    "name": "setup-buildx-action",
                    "ref": "b8c2b588063427725e40a02093a365e4fbc670ca",
                },
            ],
        },
        "image": {
            "multiStage": True,
            "runsAsRoot": False,
            "secretMode": "buildkit",
            "criticalVulnerabilities": 0,
            "digestPinned": True,
        },
    }


def test_safe_preview_payload():
    res = evaluate_release_gate(get_base_preview_payload())
    assert res["decision"] == "promote"
    assert res["violations"] == []


def test_safe_production_payload():
    res = evaluate_release_gate(get_base_production_payload())
    assert res["decision"] == "promote"
    assert res["violations"] == []


def test_excess_permission():
    payload = get_base_preview_payload()
    payload["workflow"]["permissions"] = {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
        "actions": "write",
    }
    res = evaluate_release_gate(payload)
    assert res["decision"] == "block"
    assert "EXCESS_PERMISSION" in res["violations"]

    payload["workflow"]["permissions"] = {"contents": "write", "packages": "write", "id-token": "none"}
    res = evaluate_release_gate(payload)
    assert "EXCESS_PERMISSION" in res["violations"]


def test_unsafe_pr_trigger():
    payload = get_base_preview_payload()
    payload["workflow"]["trigger"] = "pull_request_target"
    res = evaluate_release_gate(payload)
    assert res["decision"] == "block"
    assert "UNSAFE_PR_TRIGGER" in res["violations"]


def test_tests_incomplete():
    payload = get_base_preview_payload()
    payload["workflow"]["testsPassed"] = False
    res = evaluate_release_gate(payload)
    assert res["decision"] == "block"
    assert "TESTS_INCOMPLETE" in res["violations"]

    payload = get_base_preview_payload()
    payload["workflow"]["failFast"] = True
    res = evaluate_release_gate(payload)
    assert "TESTS_INCOMPLETE" in res["violations"]


def test_mutable_action():
    # Third party with tag
    payload = get_base_preview_payload()
    payload["workflow"]["actions"].append({"owner": "myorg", "name": "myaction", "ref": "v1.0.0"})
    res = evaluate_release_gate(payload)
    assert res["decision"] == "block"
    assert "MUTABLE_ACTION" in res["violations"]

    # actions owner with branch
    payload = get_base_preview_payload()
    payload["workflow"]["actions"] = [{"owner": "actions", "name": "checkout", "ref": "main"}]
    res = evaluate_release_gate(payload)
    assert "MUTABLE_ACTION" in res["violations"]


def test_single_stage_image():
    payload = get_base_preview_payload()
    payload["image"]["multiStage"] = False
    res = evaluate_release_gate(payload)
    assert res["decision"] == "block"
    assert "SINGLE_STAGE_IMAGE" in res["violations"]


def test_root_runtime():
    payload = get_base_preview_payload()
    payload["image"]["runsAsRoot"] = True
    res = evaluate_release_gate(payload)
    assert res["decision"] == "block"
    assert "ROOT_RUNTIME" in res["violations"]


def test_secret_in_layer():
    payload = get_base_preview_payload()
    payload["image"]["secretMode"] = "arg"
    res = evaluate_release_gate(payload)
    assert res["decision"] == "block"
    assert "SECRET_IN_LAYER" in res["violations"]


def test_critical_cve():
    payload = get_base_preview_payload()
    payload["image"]["criticalVulnerabilities"] = 2
    res = evaluate_release_gate(payload)
    assert res["decision"] == "block"
    assert "CRITICAL_CVE" in res["violations"]


def test_unpinned_image():
    payload = get_base_preview_payload()
    payload["image"]["digestPinned"] = False
    res = evaluate_release_gate(payload)
    assert res["decision"] == "block"
    assert "UNPINNED_IMAGE" in res["violations"]


def test_invalid_production_ref():
    payload = get_base_production_payload()
    payload["ref"] = "refs/heads/feature"
    res = evaluate_release_gate(payload)
    assert res["decision"] == "block"
    assert "INVALID_PRODUCTION_REF" in res["violations"]


def test_approval_required():
    payload = get_base_production_payload()
    payload["workflow"]["environmentApproval"] = False
    res = evaluate_release_gate(payload)
    assert res["decision"] == "block"
    assert "APPROVAL_REQUIRED" in res["violations"]


def test_combined_failures():
    payload = get_base_production_payload()
    payload["workflow"]["permissions"] = {"contents": "write", "packages": "write", "id-token": "none"}
    payload["image"]["runsAsRoot"] = True
    payload["image"]["criticalVulnerabilities"] = 1
    res = evaluate_release_gate(payload)
    assert res["decision"] == "block"
    assert set(res["violations"]) == {"EXCESS_PERMISSION", "ROOT_RUNTIME", "CRITICAL_CVE"}
