import re
from typing import Any, Dict, List
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(title="TDS GA7 Release Gate Policy Service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def evaluate_release_gate(payload: Dict[str, Any]) -> Dict[str, Any]:
    violations: List[str] = []

    target = payload.get("target")
    event = payload.get("event")
    ref = payload.get("ref")
    workflow = payload.get("workflow", {}) or {}
    image = payload.get("image", {}) or {}

    # 1. EXCESS_PERMISSION
    # Permissions must be exactly least privilege for a release: contents: read, packages: write, and id-token: none. No additional scopes may be present.
    permissions = workflow.get("permissions")
    if not isinstance(permissions, dict):
        violations.append("EXCESS_PERMISSION")
    else:
        expected_keys = {"contents", "packages", "id-token"}
        if set(permissions.keys()) != expected_keys:
            violations.append("EXCESS_PERMISSION")
        elif (
            permissions.get("contents") != "read"
            or permissions.get("packages") != "write"
            or permissions.get("id-token") != "none"
        ):
            violations.append("EXCESS_PERMISSION")

    # 2. UNSAFE_PR_TRIGGER
    # A pull request must use pull_request, never pull_request_target.
    trigger = workflow.get("trigger")
    if trigger == "pull_request_target" or (event == "pull_request" and trigger != "pull_request"):
        violations.append("UNSAFE_PR_TRIGGER")

    # 3. TESTS_INCOMPLETE
    # Tests must pass, the whole matrix must finish, and failFast must be false.
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # 4. MUTABLE_ACTION
    # Actions owned by actions may use a version tag. Every third-party action must be pinned to a full 40-character lowercase hexadecimal commit SHA.
    actions = workflow.get("actions", [])
    if isinstance(actions, list):
        for action in actions:
            if not isinstance(action, dict):
                violations.append("MUTABLE_ACTION")
                break
            owner = action.get("owner")
            act_ref = action.get("ref", "")
            if not isinstance(act_ref, str):
                violations.append("MUTABLE_ACTION")
                break

            is_sha = bool(re.match(r"^[0-9a-f]{40}$", act_ref))

            if owner == "actions":
                # Must be commit SHA or version tag (e.g., v4, v4.1, v4.1.0, 1.0.0)
                is_version_tag = bool(re.match(r"^v?\d+(\.\d+)*(-[a-zA-Z0-9.]+)?$", act_ref))
                if not (is_sha or is_version_tag):
                    violations.append("MUTABLE_ACTION")
                    break
            else:
                # Third-party action must be pinned to 40-character lowercase hex SHA
                if not is_sha:
                    violations.append("MUTABLE_ACTION")
                    break

    # 5. SINGLE_STAGE_IMAGE
    # The image must be multi-stage
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # 6. ROOT_RUNTIME
    # run as non-root
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    # 7. SECRET_IN_LAYER
    # use either no build secret or a BuildKit secret mount
    secret_mode = image.get("secretMode")
    if secret_mode not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    # 8. CRITICAL_CVE
    # have zero critical vulnerabilities
    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    # 9. UNPINNED_IMAGE
    # be referenced by digest
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # Production specific checks:
    if target == "production":
        # 10. INVALID_PRODUCTION_REF
        # Production additionally requires a push on refs/heads/main
        if event != "push" or ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        # 11. APPROVAL_REQUIRED
        # and an environmentApproval: true field on workflow.
        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    decision = "promote" if len(violations) == 0 else "block"
    return {"decision": decision, "violations": violations}


@app.post("/release-gate")
@app.post("/")
async def handle_release_gate(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={"decision": "block", "violations": ["INVALID_JSON"]},
        )

    result = evaluate_release_gate(payload)
    return JSONResponse(status_code=200, content=result)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8014)
