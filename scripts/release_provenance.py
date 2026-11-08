#!/usr/bin/env python3
"""Read-only, canonical-main release provenance gate; stdout contains only a SHA."""

import json
import os
import re
import sys
import urllib.request

REPOSITORY = "VanSail-Opensource/X-Node"
REPOSITORY_ID = 1416770902
WORKFLOW_ID = 383872953
WORKFLOW_PATH = ".github/workflows/ci.yml"
JOBS = frozenset(("Tests and schemas", "Debian binary amd64", "Debian binary arm64",
                  "Vulnerability scan", "Host debian / nftables-on", "Host debian / nftables-off"))
ROOT = "/repos/" + REPOSITORY
TAG_POLICY = "Immutable release tags"
SHA = re.compile(r"[0-9a-f]{40}", re.ASCII)


class ProvenanceError(ValueError):
    """Metadata does not prove the required release provenance."""


def require(condition):
    if not condition:
        raise ProvenanceError("release provenance rejected")


def validate_context(version, run_id, context):
    require(isinstance(version, str) and len(version) <= 64
            and re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version))
    require(isinstance(run_id, str) and re.fullmatch(r"[1-9][0-9]{0,19}", run_id))
    require(context.get("GITHUB_REPOSITORY") == REPOSITORY
            and context.get("GITHUB_REPOSITORY_ID") == str(REPOSITORY_ID)
            and context.get("GITHUB_REF") == "refs/heads/main"
            and context.get("GITHUB_EVENT_NAME") == "workflow_dispatch")
    return version, int(run_id)


def _canonical(repository):
    require(repository["id"] == REPOSITORY_ID and repository["full_name"] == REPOSITORY)


def _tag_sha(reference, objects, version):
    require(reference["ref"] == "refs/tags/" + version and len(objects) <= 5)
    obj = reference["object"]
    for tag in objects:
        require(obj["type"] == "tag" and SHA.fullmatch(obj["sha"]) and tag["sha"] == obj["sha"])
        obj = tag["object"]
    require(obj["type"] == "commit" and SHA.fullmatch(obj["sha"]))
    return obj["sha"]


def validate_provenance(metadata):
    """Validate fetched snapshots without I/O; malformed or incomplete metadata rejects."""
    try:
        return _validate(metadata)
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        raise ProvenanceError("release provenance rejected") from None


def _validate(m):
    version, run_id = validate_context(m["version"], m["run_id"], m["context"])
    _canonical(m["repository"])
    workflow, run = m["workflow"], m["run"]
    require(workflow["id"] == WORKFLOW_ID and workflow["path"] == WORKFLOW_PATH
            and workflow["name"] == "Quality" and workflow["state"] == "active")
    sha = _tag_sha(m["tag_ref"], m["tag_objects"], version)
    require(m["tag_ref_after"]["ref"] == m["tag_ref"]["ref"]
            and m["tag_ref_after"]["object"] == m["tag_ref"]["object"])
    _canonical(run["repository"])
    _canonical(run["head_repository"])
    expected = {"id": run_id, "workflow_id": WORKFLOW_ID, "path": WORKFLOW_PATH,
                "name": "Quality", "event": "push", "head_branch": "main",
                "head_sha": sha, "status": "completed", "conclusion": "success"}
    require(all(run[key] == value and m["run_after"][key] == value for key, value in expected.items()))
    attempt = run["run_attempt"]
    require(type(attempt) is int and 0 < attempt <= 100000
            and type(m["run_after"]["run_attempt"]) is int and m["run_after"]["run_attempt"] == attempt)
    _canonical(m["run_after"]["repository"])
    _canonical(m["run_after"]["head_repository"])
    jobs = m["jobs"]
    require(type(m["jobs_total"]) is int and m["jobs_total"] == len(jobs) == len(JOBS)
            and {job["name"] for job in jobs} == JOBS)
    require(len({job["id"] for job in jobs}) == len(jobs))
    for job in jobs:
        require(type(job["id"]) is int and job["id"] > 0 and job["run_id"] == run_id
                and job["head_sha"] == sha and type(job.get("run_attempt", attempt)) is int
                and job.get("run_attempt", attempt) == attempt
                and job["status"] == "completed" and job["conclusion"] == "success")
    main, comparison = m["main"], m["comparison"]
    require(main["name"] == "main" and main["protected"] is True and SHA.fullmatch(main["commit"]["sha"]))
    checks = main["protection"]["required_status_checks"]
    require(checks["enforcement_level"] in ("non_admins", "all")
            and len(checks["checks"]) == len(JOBS)
            and {check["context"] for check in checks["checks"]} == JOBS
            and all(check["app_id"] == 15368 for check in checks["checks"]))
    require(comparison["status"] in ("ahead", "identical")
            and comparison["base_commit"]["sha"] == sha and comparison["merge_base_commit"]["sha"] == sha)
    require(len(m["rulesets"]) == 1)
    ruleset = m["rulesets"][0]
    require(ruleset["name"] == TAG_POLICY and ruleset["target"] == "tag"
            and ruleset["source_type"] == "Repository" and ruleset["source"] == REPOSITORY
            and ruleset["enforcement"] == "active" and ruleset.get("bypass_actors", []) == []
            and ruleset["conditions"]["ref_name"] == {"include": ["refs/tags/v*"], "exclude": []}
            and len(ruleset["rules"]) == 2 and {rule["type"] for rule in ruleset["rules"]} == {"update", "deletion"})
    return sha


def _pages(api, path, key=None):
    result, total = [], None
    for page in range(1, 11):
        data = api(path + ("&" if "?" in path else "?") + f"per_page=100&page={page}")
        items = data[key] if key else data
        require(isinstance(items, list) and len(items) <= 100)
        if key:
            count = data["total_count"]
            require(type(count) is int and 0 <= count <= 1000 and (total is None or total == count))
            total = count
        result.extend(items)
        if len(items) < 100 or (key and len(result) >= total):
            require(not key or len(result) == total)
            return result, total
    raise ProvenanceError("release provenance rejected")


def fetch_metadata(api, version, run_id, context):
    """Fetch bounded snapshots; api accepts only fixed-origin repository API paths."""
    version, number = validate_context(version, run_id, context)
    m = {"version": version, "run_id": run_id, "context": context}
    for key, path in (("repository", ""), ("workflow", f"/actions/workflows/{WORKFLOW_ID}"),
                      ("run", f"/actions/runs/{number}"), ("main", "/branches/main"),
                      ("tag_ref", "/git/ref/tags/" + version)):
        m[key] = api(ROOT + path)
    obj, tags = m["tag_ref"]["object"], []
    while obj["type"] == "tag":
        require(len(tags) < 5 and SHA.fullmatch(obj["sha"]))
        tags.append(api(ROOT + "/git/tags/" + obj["sha"]))
        obj = tags[-1]["object"]
    m["tag_objects"] = tags
    sha, main_sha = _tag_sha(m["tag_ref"], tags, version), m["main"]["commit"]["sha"]
    require(SHA.fullmatch(main_sha))
    m["comparison"] = api(ROOT + f"/compare/{sha}...{main_sha}")
    attempt = m["run"]["run_attempt"]
    require(type(attempt) is int and 0 < attempt <= 100000)
    m["jobs"], m["jobs_total"] = _pages(api, ROOT + f"/actions/runs/{number}/attempts/{attempt}/jobs", "jobs")
    summaries, _ = _pages(api, ROOT + "/rulesets?includes_parents=false")
    managed = [rule for rule in summaries if rule["name"] == TAG_POLICY]
    require(len(managed) == 1)
    rule = managed[0]
    require(type(rule["id"]) is int and rule["id"] > 0)
    m["rulesets"] = [api(ROOT + "/rulesets/" + str(rule["id"]))]
    require(m["rulesets"][0]["id"] == rule["id"])
    m["tag_ref_after"] = api(ROOT + "/git/ref/tags/" + version)
    m["run_after"] = api(ROOT + f"/actions/runs/{number}")
    return m


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        raise ProvenanceError("release provenance rejected")


def main():
    try:
        require(len(sys.argv) == 3 and bool(os.environ.get("GH_TOKEN")))
        opener = urllib.request.build_opener(_NoRedirect())
        budget = 8 << 20

        def api(path):
            nonlocal budget
            require((path == ROOT or path.startswith(ROOT + "/")) and "\r" not in path and "\n" not in path)
            request = urllib.request.Request("https://api.github.com" + path, headers={
                "Authorization": "Bearer " + os.environ["GH_TOKEN"], "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "X-Node-release-provenance"})
            with opener.open(request, timeout=20) as response:
                require(response.status == 200)
                raw = response.read(min(2 << 20, budget) + 1)
            budget -= len(raw)
            require(len(raw) <= 2 << 20 and budget >= 0)
            return json.loads(raw)

        print(validate_provenance(fetch_metadata(api, sys.argv[1], sys.argv[2], os.environ)))
        return 0
    except Exception:
        print("release provenance rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
