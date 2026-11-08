import copy
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import release_provenance as provenance

COMMIT, MAIN = "a" * 40, "b" * 40
VERSION, RUN = "v2.0.20", "12345"


def fixture():
    context = {"GITHUB_REPOSITORY": provenance.REPOSITORY,
               "GITHUB_REPOSITORY_ID": str(provenance.REPOSITORY_ID),
               "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch"}
    repository = {"id": provenance.REPOSITORY_ID, "full_name": provenance.REPOSITORY}
    run = {"id": int(RUN), "workflow_id": provenance.WORKFLOW_ID, "path": provenance.WORKFLOW_PATH,
           "name": "Quality", "event": "push", "head_branch": "main", "head_sha": COMMIT,
           "status": "completed", "conclusion": "success", "run_attempt": 1,
           "repository": repository, "head_repository": copy.deepcopy(repository)}
    reference = {"ref": "refs/tags/" + VERSION, "object": {"type": "commit", "sha": COMMIT}}
    return {"version": VERSION, "run_id": RUN, "context": context, "repository": repository,
            "workflow": {"id": provenance.WORKFLOW_ID, "path": provenance.WORKFLOW_PATH,
                         "name": "Quality", "state": "active"},
            "run": run, "run_after": copy.deepcopy(run), "tag_ref": reference,
            "tag_ref_after": copy.deepcopy(reference), "tag_objects": [],
            "jobs_total": 6, "jobs": [
                {"id": index + 1, "name": name, "run_id": int(RUN), "run_attempt": 1,
                 "head_sha": COMMIT, "status": "completed", "conclusion": "success"}
                for index, name in enumerate(sorted(provenance.JOBS))],
            "main": {"name": "main", "protected": True, "commit": {"sha": MAIN}, "protection": {
                "required_status_checks": {"enforcement_level": "non_admins", "checks": [
                    {"context": name, "app_id": 15368} for name in sorted(provenance.JOBS)]}}},
            "comparison": {"status": "ahead", "base_commit": {"sha": COMMIT},
                           "merge_base_commit": {"sha": COMMIT}},
            "rulesets": [{"id": 1, "name": provenance.TAG_POLICY, "target": "tag",
                          "source_type": "Repository", "source": provenance.REPOSITORY,
                          "enforcement": "active", "bypass_actors": [],
                          "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
                          "rules": [{"type": "update"}, {"type": "deletion"}]}]}


def change(metadata, path, value):
    target = metadata
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value


class ReleaseProvenanceTest(unittest.TestCase):
    def test_canonical_push_and_read_only_policy_visibility(self):
        metadata = fixture()
        self.assertEqual(provenance.validate_provenance(metadata), COMMIT)
        for job in metadata["jobs"]:
            del job["run_attempt"]
        self.assertEqual(provenance.validate_provenance(metadata), COMMIT)
        del metadata["rulesets"][0]["bypass_actors"]
        self.assertEqual(provenance.validate_provenance(metadata), COMMIT)
        metadata["comparison"]["status"] = "identical"
        metadata["main"]["commit"]["sha"] = COMMIT
        self.assertEqual(provenance.validate_provenance(metadata), COMMIT)

    def test_provenance_rejects_wrong_or_incomplete_evidence(self):
        cases = [
            (("repository", "id"), 42), (("repository", "full_name"), "foreign/X-Node"),
            (("run", "head_repository", "id"), 42), (("run", "repository", "id"), 42),
            (("workflow", "id"), 42), (("workflow", "path"), ".github/workflows/other.yml"),
            (("workflow", "state"), "disabled_manually"), (("run", "workflow_id"), 42),
            (("run", "path"), ".github/workflows/other.yml"), (("run", "event"), "pull_request"),
            (("run", "event"), "workflow_dispatch"), (("run", "head_branch"), "feature"),
            (("run", "head_sha"), MAIN), (("run", "conclusion"), "failure"),
            (("run", "status"), "in_progress"), (("run_after", "run_attempt"), 2),
            (("run_after", "head_repository", "id"), 42), (("run_after", "status"), "queued"),
            (("jobs", 0, "conclusion"), "skipped"), (("jobs", 0, "conclusion"), "failure"),
            (("jobs", 0, "status"), "in_progress"), (("jobs", 0, "head_sha"), MAIN),
            (("jobs", 0, "run_id"), 99), (("jobs", 0, "run_attempt"), 2),
            (("jobs", 0, "id"), 2), (("jobs_total",), 7), (("jobs_total",), 6.0),
            (("jobs", 0, "run_attempt"), True), (("run_after", "run_attempt"), True),
            (("main", "protected"), False), (("main", "commit", "sha"), "bad"),
            (("main", "protection", "required_status_checks", "enforcement_level"), "off"),
            (("main", "protection", "required_status_checks", "checks", 0, "app_id"), -1),
            (("main", "protection", "required_status_checks", "checks", 0, "context"), "Unknown"),
            (("comparison", "status"), "behind"), (("comparison", "status"), "diverged"),
            (("comparison", "merge_base_commit", "sha"), MAIN),
            (("tag_ref_after", "object", "sha"), MAIN),
            (("tag_ref", "ref"), "refs/tags/v0.0.0"),
            (("rulesets", 0, "bypass_actors"), [{"actor_id": 1}]),
            (("rulesets", 0, "enforcement"), "evaluate"),
            (("rulesets", 0, "source"), "foreign/X-Node"),
            (("rulesets", 0, "conditions", "ref_name", "exclude"), ["refs/tags/v2*"]),
            (("rulesets", 0, "rules"), [{"type": "update"}]),
            (("main", "protection", "required_status_checks", "checks"), []),
            (("jobs",), []), (("rulesets",), []), (("run", "head_repository"), None),
        ]
        for path, value in cases:
            with self.subTest(path=path, value=value):
                metadata = fixture()
                change(metadata, path, value)
                with self.assertRaises(provenance.ProvenanceError):
                    provenance.validate_provenance(metadata)
        for key in fixture():
            metadata = fixture()
            del metadata[key]
            with self.subTest(missing=key), self.assertRaises(provenance.ProvenanceError):
                provenance.validate_provenance(metadata)

    def test_context_and_inputs(self):
        context = fixture()["context"]
        for version in ("v1.2.3-rc1", "v01.2.3", "1.2.3", "v1.2.3\n", "v1.2.3/other", ""):
            with self.subTest(version=version), self.assertRaises(provenance.ProvenanceError):
                provenance.validate_context(version, RUN, context)
        for run in ("", "0", "-1", "1.0", "123\n", "1/attempts/1", "1" * 21):
            with self.subTest(run=run), self.assertRaises(provenance.ProvenanceError):
                provenance.validate_context(VERSION, run, context)
        for key in context:
            changed = dict(context, **{key: "foreign"})
            with self.subTest(context=key), self.assertRaises(provenance.ProvenanceError):
                provenance.validate_context(VERSION, RUN, changed)

    def test_annotated_tags_are_bounded_and_content_addressed(self):
        metadata = fixture()
        for depth in range(1, 6):
            previous = copy.deepcopy(metadata["tag_ref"]["object"])
            sha = str(depth) * 40
            metadata["tag_objects"].insert(0, {"sha": sha, "object": previous})
            metadata["tag_ref"]["object"] = {"type": "tag", "sha": sha}
            metadata["tag_ref_after"] = copy.deepcopy(metadata["tag_ref"])
            self.assertEqual(provenance.validate_provenance(metadata), COMMIT)
        metadata["tag_objects"].append({"sha": "6" * 40, "object": {"type": "commit", "sha": COMMIT}})
        with self.assertRaises(provenance.ProvenanceError):
            provenance.validate_provenance(metadata)
        metadata = fixture()
        metadata["tag_ref"]["object"]["type"] = "tree"
        with self.assertRaises(provenance.ProvenanceError):
            provenance.validate_provenance(metadata)

    def test_pages_collect_hidden_results_and_detect_count_drift(self):
        calls = []

        def api(path):
            calls.append(path)
            return {"total_count": 101, "jobs": list(range(100)) if path.endswith("page=1") else ["failed"]}

        jobs, total = provenance._pages(api, "/jobs?filter=latest", "jobs")
        self.assertEqual((len(jobs), total, jobs[-1], len(calls)), (101, 101, "failed", 2))
        with self.assertRaises(provenance.ProvenanceError):
            provenance._pages(lambda _: {"total_count": 101, "jobs": []}, "/jobs", "jobs")
        with self.assertRaises(provenance.ProvenanceError):
            provenance._pages(lambda _: {"total_count": 1001, "jobs": []}, "/jobs", "jobs")
        pages = iter(({"total_count": 101, "jobs": list(range(100))},
                      {"total_count": 102, "jobs": ["extra", "failed"]}))
        with self.assertRaises(provenance.ProvenanceError):
            provenance._pages(lambda _: next(pages), "/jobs", "jobs")

    def test_fetch_uses_pinned_attempt_and_rechecks_mutable_metadata(self):
        metadata, calls = fixture(), []
        endpoints = {"": "repository", f"/actions/workflows/{provenance.WORKFLOW_ID}": "workflow",
                     f"/actions/runs/{RUN}": "run", "/branches/main": "main",
                     "/git/ref/tags/" + VERSION: "tag_ref", "/rulesets/1": "ruleset",
                     f"/compare/{COMMIT}...{MAIN}": "comparison"}

        def api(path):
            calls.append(path)
            path = path.removeprefix(provenance.ROOT)
            if path.startswith(f"/actions/runs/{RUN}/attempts/1/jobs?"):
                return {"total_count": 6, "jobs": metadata["jobs"]}
            if path.startswith("/rulesets?"):
                return [{"id": 1, "name": provenance.TAG_POLICY}]
            key = endpoints[path]
            return copy.deepcopy(metadata["rulesets"][0] if key == "ruleset" else metadata[key])

        fetched = provenance.fetch_metadata(api, VERSION, RUN, metadata["context"])
        self.assertEqual(provenance.validate_provenance(fetched), COMMIT)
        self.assertEqual(calls.count(provenance.ROOT + "/git/ref/tags/" + VERSION), 2)
        self.assertEqual(calls.count(provenance.ROOT + "/actions/runs/" + RUN), 2)

    def test_redirects_never_forward_authorization(self):
        with self.assertRaises(provenance.ProvenanceError):
            provenance._NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://other.example/")

    def test_cli_failure_does_not_disclose_token_or_remote_error(self):
        output, errors = io.StringIO(), io.StringIO()
        context = dict(fixture()["context"], GH_TOKEN="sensitive-token")
        opener = mock.Mock()
        opener.open.side_effect = RuntimeError("sensitive-token https://private.example/error")
        with mock.patch.dict(provenance.os.environ, context, clear=True), \
                mock.patch.object(provenance.sys, "argv", ["release_provenance.py", VERSION, RUN]), \
                mock.patch.object(provenance.urllib.request, "build_opener", return_value=opener), \
                redirect_stdout(output), redirect_stderr(errors):
            self.assertEqual(provenance.main(), 1)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), "release provenance rejected\n")


if __name__ == "__main__":
    unittest.main()
