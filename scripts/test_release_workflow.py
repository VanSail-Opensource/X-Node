"""Hosted regressions for release authority, isolation and publication ordering."""

import ast
import copy
import json
from pathlib import Path
import re
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
GUARD = ("github.repository_id == '1416770902' && github.ref == 'refs/heads/main'"
         " && github.event_name == 'workflow_dispatch'")
KEY = "${{ secrets.RELEASE_MINISIGN_SECRET_KEY }}"
PUBLIC_KEY = "RWQ6HaDFAVc2u+yR4zuGuTn+wHojhxW7s7DxO1W22yj5r5yYwZgPt3qL"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def audit_actions(workflows):
    for workflow in workflows.values():
        permissions = workflow.get("permissions", {})
        require(isinstance(permissions, dict) and permissions and
                all(value == "read" for value in permissions.values()), "read-only workflow default")
        for job in workflow["jobs"].values():
            if "write" in job.get("permissions", {}).values():
                guard = job.get("if", "")
                main = "github.ref == 'refs/heads/main'" in guard
                bot = all(value in guard for value in (
                    "github.actor == 'dependabot[bot]'", "github.event.pull_request.user.login == 'dependabot[bot]'",
                    "github.event.pull_request.head.repo.id == 1416770902", "github.event.pull_request.base.ref == 'main'"))
                require("github.repository_id == '1416770902'" in guard and "||" not in guard
                        and (main or bot), "write job requires canonical branch trust")
            for step in [job, *job.get("steps", [])]:
                if "uses" not in step:
                    continue
                action = step["uses"]
                require(action.startswith("./") or re.fullmatch(r"[\w./-]+@[a-f0-9]{40}", action), "immutable Action")
                if action.startswith("actions/checkout@"):
                    require(step.get("with", {}).get("persist-credentials") == "false", "checkout credentials")


def audit_release(workflow):
    require(set(workflow["on"]) == {"workflow_dispatch"}, "manual release admission only")
    inputs = workflow["on"]["workflow_dispatch"]["inputs"]
    require(set(inputs) == {"version", "quality_run_id"} and all(
        value.get("required") == "true" and value.get("type") == "string" and "default" not in value
        for value in inputs.values()), "exact explicit release inputs")
    require(workflow["permissions"] == {"contents": "read", "actions": "read"}, "release default permissions")
    jobs = workflow["jobs"]
    require(set(jobs) == {"build", "sign", "publish"}, "separate release jobs")
    require(jobs["sign"].get("needs") == "build" and jobs["publish"].get("needs") == ["build", "sign"], "job dependencies")
    require(jobs["sign"].get("environment") == "release" and all(
        "environment" not in jobs[name] for name in ("build", "publish")), "isolated signing environment")
    require(jobs["publish"].get("permissions") == {"contents": "write", "actions": "read"}, "publisher permissions")
    serialized = json.dumps(workflow)
    require(serialized.count("secrets.") == 1 and serialized.count(KEY) == 1, "one signing-secret scope")
    for name, job in jobs.items():
        require(job["if"] == GUARD, "canonical repository, main and dispatch guard")
        if name != "publish":
            require(job.get("permissions", workflow["permissions"]) == workflow["permissions"], "no build/sign writes")
        steps = job["steps"]
        provenance = [i for i, step in enumerate(steps) if step.get("id") == "provenance"]
        require(len(provenance) == 1 and "PY_RELEASE_PROVENANCE" in steps[provenance[0]].get("run", ""), "real inline provenance")
        require(steps[provenance[0]]["run"] == jobs["build"]["steps"][0]["run"], "canonical provenance across jobs")
        proofs = [i for i, step in enumerate(steps) if step.get("run") == steps[provenance[0]]["run"]]
        require(len(proofs) == {"build": 1, "sign": 2, "publish": 3}[name], "fresh provenance at authority boundaries")
        if name != "build":
            require(all(steps[i].get("env", {}).get("EXPECTED_SOURCE_SHA") ==
                        "${{ needs.build.outputs.source_sha }}" for i in proofs), "same approved source across jobs")
        verify = [i for i, step in enumerate(steps) if "PY_RELEASE_BUNDLE" in step.get("run", "")]
        require(len(verify) == (1 if name == "build" else 2), "complete bundle verification stages")
        for index, step in enumerate(steps):
            action, run = step.get("uses", ""), step.get("run", "")
            require("${{ inputs." not in run and "${{ github.event." not in run, "no shell input interpolation")
            if action or "make build" in run or "gh release " in run or KEY in json.dumps(step):
                require(index > provenance[0], "provenance before sensitive operations")
            if name != "build":
                require(not action or action.startswith(("actions/download-artifact@", "actions/upload-artifact@")), "isolated artifact-only Actions")
                require(not re.search(r"(?m)^\s*(?:go|make|npm|node|bash|sh|source|eval|curl|wget|git)\s", run)
                        and not re.search(r"python\d?\s+[^\n]*(?:scripts/|\./cmd/)", run), "no checked-out source execution")
            if action.startswith("actions/download-artifact@"):
                require(set(step.get("with", {})) == {"name", "path"}
                        and "${{ github.run_id }}" in step["with"]["name"], "current-run artifacts only")
            if index in verify:
                require(run == next(s["run"] for s in jobs["build"]["steps"] if "PY_RELEASE_BUNDLE" in s.get("run", "")), "canonical verifier across jobs")
                require(PUBLIC_KEY in run and all(binary in run for binary in (
                    "x-node-linux-amd64", "x-node-linux-arm64", "xnodectl-linux-amd64", "xnodectl-linux-arm64")), "pinned all-architecture validation")
        if name == "build":
            checkout = [step for step in steps if step.get("uses", "").startswith("actions/checkout@")]
            require(len(checkout) == 1 and checkout[0].get("with", {}).get("ref") ==
                    "${{ steps.provenance.outputs.source_sha }}", "checkout approved immutable source")
            require(job.get("outputs", {}).get("source_sha") == "${{ steps.provenance.outputs.source_sha }}", "approved source output")
        elif name == "sign":
            signing = [i for i, step in enumerate(steps) if KEY in json.dumps(step)]
            require(len(signing) == 1 and verify[0] < signing[0] < verify[1], "pre/post signing verification")
            require(proofs[-1] == signing[0] - 1, "provenance immediately before key use")
            secret = steps[signing[0]]
            require(secret.get("env") == {"RELEASE_KEY": KEY} and "/usr/bin/minisign -S " in secret["run"]
                    and "/usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C" in secret["run"]
                    and 'version:$RELEASE_VERSION' in secret["run"] and "unset RELEASE_KEY" in secret["run"], "distribution signer only")
            require(any("apt-get install" in step.get("run", "") and "minisign" in step["run"]
                        for step in steps[:signing[0]]), "install signer before secret exposure")
            require(steps[verify[1]].get("env", {}).get("VERIFY_SIGNED") == "1", "verify newly signed bundle")
        else:
            indices = [[i for i, step in enumerate(steps) if command in step.get("run", "")]
                       for command in ("gh release create ", "gh release download ", "gh release edit ")]
            require(all(len(value) == 1 for value in indices), "single draft/publication sequence")
            create, download, publish = (value[0] for value in indices)
            require(verify[0] < create < download < verify[1] < publish, "verify uploaded bytes before publication")
            require(proofs[-2] == create - 1 and proofs[-1] == publish - 1, "fresh draft and publication provenance")
            require(re.search(r"--draft(?:=true)?(?:\s|$)", steps[create]["run"])
                    and "--verify-tag" in steps[create]["run"] and "--draft=false" in steps[publish]["run"], "draft release gate")
            require(all("--latest=false" in steps[i]["run"] for i in (create, publish)),
                    "publication must not trigger automatic agent rollout")
            require(all(steps[i].get("env", {}).get("VERIFY_SIGNED") == "1" for i in verify)
                    and "published-release" in steps[verify[1]].get("env", {}).get("BUNDLE_DIR", ""), "uploaded signed bytes")


def audit_verifier_environment(tree):
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
             and node.func.value.id == "subprocess" and node.func.attr == "run"]
    require(len(calls) == 1, "one fixed verifier subprocess")
    environment = [keyword.value for keyword in calls[0].keywords if keyword.arg == "env"]
    require(len(environment) == 1 and ast.literal_eval(environment[0]) ==
            {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}, "verifier inherits no job credentials")


class ReleaseWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.workflows = {path.name: yaml.load(path.read_text(), Loader=yaml.BaseLoader)
                          for path in (ROOT / ".github/workflows").glob("*.y*ml")}
        self.workflow = self.workflows["release.yml"]

    def test_release_authority_isolation_and_publication_order(self):
        audit_release(self.workflow)
        audit_actions(self.workflows)
        run = self.workflow["jobs"]["build"]["steps"][0]["run"]
        source = run.split("<<'PY_RELEASE_PROVENANCE'\n", 1)[1].split("\nPY_RELEASE_PROVENANCE", 1)[0] + "\n"
        self.assertEqual(source, (ROOT / "scripts/release_provenance.py").read_text())

    def test_verifier_cannot_inherit_credentials(self):
        tree = ast.parse((ROOT / "scripts/release_bundle.py").read_text())
        audit_verifier_environment(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "env":
                node.value.keys.append(ast.Constant("GH_TOKEN"))
                node.value.values.append(ast.Constant("forbidden"))
        with self.assertRaises(ValueError):
            audit_verifier_environment(tree)

    def test_release_boundary_mutations_are_rejected(self):
        def signer(workflow):
            return next(step for step in workflow["jobs"]["sign"]["steps"] if KEY in json.dumps(step))
        mutations = {
            "tag trigger": lambda w: w["on"].update(push={"tags": ["v*"]}),
            "secret in build": lambda w: w["jobs"]["build"].update(env={"KEY": KEY}),
            "tag checkout": lambda w: next(s for s in w["jobs"]["build"]["steps"] if s.get("uses", "").startswith("actions/checkout@"))["with"].update(ref="${{ inputs.version }}"),
            "signer Go code": lambda w: signer(w).update(run="go run ./cmd/release-sign"),
            "signer cache": lambda w: w["jobs"]["sign"]["steps"].append({"uses": "actions/cache@" + "a" * 40}),
            "publish early": lambda w: w["jobs"]["publish"]["steps"].insert(0, w["jobs"]["publish"]["steps"].pop()),
            "premature rollout": lambda w: w["jobs"]["publish"]["steps"][-1].update(run='gh release edit "$RELEASE_VERSION" --draft=false --latest'),
            "missing final provenance": lambda w: w["jobs"]["publish"]["steps"].pop(-2),
            "publisher environment": lambda w: w["jobs"]["publish"].update(environment="release"),
            "signer permissions": lambda w: w["jobs"]["sign"].update(permissions={"contents": "write"}),
            "guard bypass": lambda w: w["jobs"]["sign"].update({"if": GUARD + " || true"}),
            "shell interpolation": lambda w: signer(w).update(run=signer(w)["run"] + "\necho ${{ inputs.version }}"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                workflow = copy.deepcopy(self.workflow)
                mutate(workflow)
                with self.assertRaises(ValueError):
                    audit_release(workflow)

    def test_mutable_actions_credentials_and_write_defaults_are_rejected(self):
        for change in ("action", "credentials", "permissions", "branch"):
            with self.subTest(change=change):
                workflows = copy.deepcopy(self.workflows)
                workflow = workflows["release.yml"]
                step = next(s for s in workflow["jobs"]["build"]["steps"] if "uses" in s)
                if change == "action":
                    step["uses"] = "actions/checkout@main"
                elif change == "credentials":
                    step["with"]["persist-credentials"] = "true"
                elif change == "permissions":
                    workflow["permissions"]["contents"] = "write"
                else:
                    workflow["jobs"]["publish"]["if"] = "github.repository_id == '1416770902'"
                with self.assertRaises(ValueError):
                    audit_actions(workflows)


if __name__ == "__main__":
    unittest.main()
