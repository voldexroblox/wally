#!/usr/bin/env python3
"""Security tests for unpinned GitHub Actions that receive this repository's token.

The tests fail while a workflow runs an action at a branch or tag with the
repository token, and they pass once every external action is pinned to a
full commit SHA and the test-merge job's token is limited to contents: write.

Run:
    python3 tests/workflow_action_pin_test.py
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
PLACEHOLDER_TOKEN = "PLACEHOLDER_GITHUB_TOKEN"
FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
TOKEN_EXPRESSION = re.compile(r"secrets\.GITHUB_TOKEN|github\.token")
LABEL_CONTAINS = re.compile(
    r"^contains\(github\.event\.pull_request\.labels\.\*\.name,\s*'([^']*)'\)$"
)


class WorkflowLoader(yaml.SafeLoader):
    """Load workflow YAML without turning the key `on` into a boolean."""


def _drop_bool_resolver() -> None:
    for first, resolvers in list(WorkflowLoader.yaml_implicit_resolvers.items()):
        WorkflowLoader.yaml_implicit_resolvers[first] = [
            (tag, pattern)
            for tag, pattern in resolvers
            if tag != "tag:yaml.org,2002:bool"
        ]


_drop_bool_resolver()


def load_workflow(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        document = yaml.load(handle, Loader=WorkflowLoader)
    if not isinstance(document, dict):
        raise AssertionError(f"{path} did not parse as a workflow mapping")
    return document


def workflow_files() -> list[Path]:
    return sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))


def parse_uses(uses: str) -> tuple[str, str, str]:
    """Split owner/repo[/path]@ref the way the runner's workflow converter does.

    actions/runner v2.338.2
    src/Sdk/WorkflowParser/Conversion/WorkflowTemplateConverter.cs:1771-1781
    splits the uses string on '@' and requires exactly two segments.
    """
    if uses.startswith("./") or uses.startswith(".\\") or uses.startswith("docker://"):
        raise ValueError(uses)
    segments = uses.split("@")
    if len(segments) != 2 or not segments[0] or not segments[1]:
        raise AssertionError(f"uses is not owner/repo@ref: {uses}")
    path_segments = [part for part in re.split(r"[/\\]", segments[0]) if part]
    if len(path_segments) < 2:
        raise AssertionError(f"uses is missing owner/repo: {uses}")
    return path_segments[0], path_segments[1], segments[1]


def is_local_uses(uses: str) -> bool:
    return uses.startswith("./") or uses.startswith(".\\")


def external_action_steps() -> list[dict]:
    found = []
    for path in workflow_files():
        document = load_workflow(path)
        jobs = document.get("jobs") or {}
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            for index, step in enumerate(job.get("steps") or []):
                uses = step.get("uses")
                if not isinstance(uses, str) or is_local_uses(uses):
                    continue
                owner, repo, ref = parse_uses(uses)
                found.append(
                    {
                        "path": path,
                        "job": job_name,
                        "index": index,
                        "step": step,
                        "uses": uses,
                        "owner": owner,
                        "repo": repo,
                        "ref": ref,
                    }
                )
    return found


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def resolve_ref(repo: Path, ref: str) -> str:
    """Resolve the ref string the runner sends to the action download service.

    A 40-character commit SHA names that commit. Any other ref is the branch
    or tag tip at the moment of resolution. The runner does not substitute a
    previously reviewed SHA: ActionManager sends repositoryReference.Ref
    (actions/runner v2.338.2 src/Runner.Worker/ActionManager.cs:1037-1040)
    and downloads the ResolvedSha returned for that ref
    (ActionManager.cs:1188-1212). GitHub documents that a tag or branch
    resolves to whatever commit it points at when the workflow runs
    (github/docs 23ddf903 content/actions/concepts/security/workflow-dependency-lockfiles.md:13-16).
    """
    if FULL_SHA.fullmatch(ref):
        return ref.lower()
    return git(repo, "rev-parse", "--verify", ref)


def init_action_repo(ref: str) -> Path:
    repo = Path(tempfile.mkdtemp(prefix="action-ref-"))
    git(repo, "init", "-q", "-b", "master")
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "user.name", "Test")
    (repo / "action.yml").write_text("name: reviewed\n", encoding="utf-8")
    git(repo, "add", "action.yml")
    git(repo, "commit", "-q", "-m", "reviewed")
    if ref not in {"master", "HEAD"}:
        git(repo, "tag", "-f", ref)
    return repo


def attacker_moves_refs(repo: Path) -> None:
    """Move every branch and tag, which is what a push to the action repo does."""
    (repo / "action.yml").write_text(
        "name: attacker\ninputs:\n  github_token:\n    default: ${{ github.token }}\n",
        encoding="utf-8",
    )
    git(repo, "add", "action.yml")
    git(repo, "commit", "-q", "-m", "attacker")
    for tag in git(repo, "tag").splitlines():
        if tag:
            git(repo, "tag", "-f", tag)
    current = git(repo, "branch", "--show-current")
    for branch in git(repo, "for-each-ref", "--format=%(refname:short)", "refs/heads").splitlines():
        if branch and branch != current:
            git(repo, "branch", "-f", branch, "HEAD")


def expression_supplies_token(value: object) -> bool:
    if isinstance(value, str):
        return TOKEN_EXPRESSION.search(value) is not None
    if isinstance(value, dict):
        return any(expression_supplies_token(item) for item in value.values())
    if isinstance(value, list):
        return any(expression_supplies_token(item) for item in value)
    return False


def step_passes_token_explicitly(step: dict) -> bool:
    """True when the workflow expression evaluates to the job's repository token.

    The runner copies step env into the action process environment
    (actions/runner v2.338.2 src/Runner.Worker/ActionRunner.cs:249-251 and
    NodeScriptActionHandler.cs:166-170) and copies `with` inputs to INPUT_*
    variables (src/Runner.Worker/Handlers/Handler.cs:175-187).
    """
    return expression_supplies_token(step.get("with")) or expression_supplies_token(
        step.get("env")
    )


def apply_manifest_defaults(step: dict, manifest_inputs: dict[str, str]) -> dict[str, str]:
    """Fill inputs the workflow omitted from action.yml defaults.

    actions/runner v2.338.2 src/Runner.Worker/ActionRunner.cs:206-217 evaluates
    each default the caller did not set. `${{ github.token }}` is the job token
    placed in the github context (ExecutionContext.cs:1025-1030).
    """
    supplied = {str(key).lower(): str(value) for key, value in (step.get("with") or {}).items()}
    resolved: dict[str, str] = {}
    for name, default in manifest_inputs.items():
        if name.lower() in supplied:
            value = supplied[name.lower()]
        else:
            value = default
        if TOKEN_EXPRESSION.search(value):
            value = PLACEHOLDER_TOKEN
        resolved[name] = value
    for name, value in supplied.items():
        resolved.setdefault(name, PLACEHOLDER_TOKEN if TOKEN_EXPRESSION.search(value) else value)
    return resolved


def input_environment(step: dict) -> dict[str, str]:
    """Map the workflow `with` block to the INPUT_* environment the action reads."""
    environment = {}
    for key, value in (step.get("with") or {}).items():
        text = str(value)
        if TOKEN_EXPRESSION.search(text):
            text = PLACEHOLDER_TOKEN
        environment[f"INPUT_{str(key).replace(' ', '_').upper()}"] = text
    for key, value in (step.get("env") or {}).items():
        text = str(value)
        if TOKEN_EXPRESSION.search(text):
            text = PLACEHOLDER_TOKEN
        environment[str(key)] = text
    return environment


def presence(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    return value


class RecordedRequest:
    def __init__(self, method: str, path: str, authorization: str | None, body: bytes) -> None:
        self.method = method
        self.path = path
        self.authorization = authorization
        self.body = body


class ApiStub(BaseHTTPRequestHandler):
    """Stand-in for the GitHub REST routes Octokit 4.14.0 calls.

    octokit.rb v4.14.0 lib/octokit/client/commits.rb:197-219:
      compare -> GET repos/{repo}/compare/{base}...{head}
      merge   -> POST repos/{repo}/merges with base and head
    lib/octokit/connection.rb:111-112 sets Authorization to `token <access_token>`
    when the client was constructed with access_token.
    """

    requests: list[RecordedRequest] = []

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or "0")
        return self.rfile.read(length) if length else b""

    def _record(self, body: bytes) -> None:
        type(self).requests.append(
            RecordedRequest(
                self.command,
                self.path.split("?", 1)[0],
                self.headers.get("Authorization"),
                body,
            )
        )

    def _reply(self, status: int, payload: dict) -> None:
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        self._record(b"")
        self._reply(200, {"status": "ahead"})

    def do_POST(self) -> None:  # noqa: N802
        body = self._read_body()
        self._record(body)
        self._reply(201, {"sha": "merged"})

    def log_message(self, format: str, *args: object) -> None:
        return


def start_api_stub() -> tuple[ThreadingHTTPServer, str]:
    ApiStub.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), ApiStub)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server.serve_thread = thread  # type: ignore[attr-defined]
    host, port = server.server_address
    return server, f"http://{host}:{port}"


def run_merge_branch_action(environment: dict[str, str], api_url: str) -> list[RecordedRequest]:
    """Run the control flow of devmasx/merge-branch lib/index.rb at dd60e3efede0.

    The action's Dockerfile CMD is `ruby /action/lib/index.rb`. Ruby is not
    installed here, so this follows that file and MergeBrachService in order:
    read the event, resolve the head, take INPUT_GITHUB_TOKEN or GITHUB_TOKEN,
    validate inputs, and on a matching labeled event call compare then merge.
    """
    event = json.loads(Path(environment["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    head = (
        presence(environment.get("INPUT_HEAD_TO_MERGE"))
        or presence(environment.get("INPUT_FROM_BRANCH"))
        or presence(environment.get("GITHUB_SHA"))
    )
    repository = environment.get("GITHUB_REPOSITORY")
    token = presence(environment.get("INPUT_GITHUB_TOKEN")) or presence(
        environment.get("GITHUB_TOKEN")
    )
    action_type = presence(environment.get("INPUT_TYPE")) or "labeled"
    label_name = environment.get("INPUT_LABEL_NAME")
    target_branch = environment.get("INPUT_TARGET_BRANCH")

    if action_type not in {"labeled", "now"}:
        raise RuntimeError("Error: Invalid type")
    if not target_branch:
        raise RuntimeError("Error: Empty target branch")
    if action_type == "labeled" and not label_name:
        raise RuntimeError(" Error: Empty target label name")

    labeled_ok = (
        action_type == "labeled"
        and (event or {}).get("action") == "labeled"
        and ((event or {}).get("label") or {}).get("name") == label_name
    )
    valid = True if action_type == "now" else labeled_ok
    if not valid:
        return []

    def request(method: str, path: str, payload: dict | None) -> dict:
        data = None if payload is None else json.dumps(payload).encode()
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"token {token}"
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            f"{api_url}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode())

    comparison = request(
        "GET",
        f"/repos/{repository}/compare/{target_branch}...{head}",
        None,
    )
    disable = presence(environment.get("INPUT_DISABLE_FASTFORWARDS"))
    if (
        comparison.get("status") == "identical"
        and disable
        and environment.get("INPUT_DISABLE_FASTFORWARDS") == "true"
    ):
        return ApiStub.requests
    message = environment.get("INPUT_MESSAGE")
    body = {"base": target_branch, "head": head}
    if message:
        body["commit_message"] = message
    request("POST", f"/repos/{repository}/merges", body)
    return ApiStub.requests


def wildcard_names(event: dict) -> list[str]:
    """Evaluate github.event.pull_request.labels.*.name.

    actions/runner v2.338.2 src/Sdk/Expressions/Sdk/Operators/Index.cs:223-228
    turns `.*` on an array into the array elements, and the following `.name`
    reads that property from each object (Index.cs:146-149).
    """
    pull_request = (event.get("pull_request") or {}) if isinstance(event, dict) else {}
    labels = pull_request.get("labels") or []
    names = []
    if not isinstance(labels, list):
        return names
    for label in labels:
        if isinstance(label, dict) and "name" in label:
            names.append(str(label["name"]))
    return names


def contains_label(names: list[str], expected: str) -> bool:
    """contains() on an array uses case-insensitive equality.

    actions/runner v2.338.2 src/Sdk/Expressions/Sdk/Functions/Contains.cs:28-40
    and EvaluationResult.cs:259-262 (OrdinalIgnoreCase). An empty array is false
    (Contains.cs:30).
    """
    if not names:
        return False
    return any(name.casefold() == expected.casefold() for name in names)


def job_runs_for_event(job: dict, event: dict) -> bool:
    """A missing job `if` defaults to success. ConvertToIfCondition returns null
    for an empty condition (WorkflowTemplateConverter.cs:1799-1801)."""
    condition = job.get("if")
    if condition is None:
        return True
    text = str(condition).strip()
    match = LABEL_CONTAINS.fullmatch(text)
    if not match:
        raise AssertionError(f"unsupported job if expression: {text}")
    return contains_label(wildcard_names(event), match.group(1))


def effective_permissions(document: dict, job: dict) -> object:
    """Job permissions replace the workflow permissions for that job.

    github/docs 23ddf903 workflow-syntax.md:366. When any scope is set, scopes
    that are omitted become none (data/reusables/actions/github-token-available-permissions.md).
    """
    if "permissions" in job:
        return job.get("permissions")
    return document.get("permissions")


def labeled_event() -> dict:
    return {
        "action": "labeled",
        "label": {"name": "merged to test"},
        "pull_request": {
            "labels": [{"name": "merged to test"}],
            "head": {"ref": "feature", "sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        },
    }


class UnpinnedActionTokenTests(unittest.TestCase):
    def test_label_selects_merge_job_and_action_posts_token(self) -> None:
        """The labeled event reaches the merge action, which posts the workflow token.

        This is the path the workflow runs today. Pinning the action does not
        remove the token input, so this stays true after the fix.
        """
        document = load_workflow(WORKFLOWS / "test-merge.yml")
        job = document["jobs"]["merge-branch"]
        self.assertTrue(job_runs_for_event(job, labeled_event()))

        merge_step = next(step for step in job["steps"] if str(step.get("uses", "")).startswith("devmasx/merge-branch@"))
        environment = input_environment(merge_step)
        environment["GITHUB_REPOSITORY"] = "voldexroblox/wally"
        environment["GITHUB_SHA"] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        event_dir = tempfile.mkdtemp(prefix="event-")
        event_path = Path(event_dir) / "event.json"
        event_path.write_text(json.dumps(labeled_event()), encoding="utf-8")
        environment["GITHUB_EVENT_PATH"] = str(event_path)
        server, api_url = start_api_stub()
        try:
            requests = run_merge_branch_action(environment, api_url)
        finally:
            server.shutdown()
            server.server_close()
            server.serve_thread.join(timeout=2)  # type: ignore[attr-defined]
            shutil.rmtree(event_dir)

        merges = [item for item in requests if item.method == "POST" and item.path.endswith("/merges")]
        self.assertEqual(len(merges), 1)
        self.assertEqual(merges[0].authorization, f"token {PLACEHOLDER_TOKEN}")
        self.assertEqual(
            json.loads(merges[0].body.decode()),
            {"base": "test", "head": environment["GITHUB_SHA"]},
        )
        compares = [item for item in requests if item.method == "GET" and "/compare/" in item.path]
        self.assertEqual(len(compares), 1)
        self.assertEqual(compares[0].authorization, f"token {PLACEHOLDER_TOKEN}")

    def test_unlabeled_event_does_not_run_merge_job(self) -> None:
        document = load_workflow(WORKFLOWS / "test-merge.yml")
        job = document["jobs"]["merge-branch"]
        event = labeled_event()
        event["action"] = "opened"
        event["label"] = {"name": "bug"}
        event["pull_request"]["labels"] = [{"name": "bug"}]
        self.assertFalse(job_runs_for_event(job, event))

    def test_executed_action_ref_cannot_move_after_review(self) -> None:
        """The ref in `uses` is resolved again when the job runs.

        Looking the branch up, recording the SHA, and then checking out the
        branch name a second time still follows the attacker commit. Only a
        full commit SHA stays on the reviewed commit.
        """
        self.maxDiff = None
        movable = []
        for step in external_action_steps():
            repo = init_action_repo(step["ref"])
            try:
                reviewed = resolve_ref(repo, step["ref"])
                attacker_moves_refs(repo)
                executed = resolve_ref(repo, step["ref"])
            finally:
                shutil.rmtree(repo)
            if reviewed != executed:
                manifest_inputs = {}
                if not step_passes_token_explicitly(step["step"]):
                    # The commit that moved into the ref can set an input default.
                    # The runner evaluates that default with github.token.
                    manifest_inputs = {"github_token": "${{ github.token }}"}
                resolved_inputs = apply_manifest_defaults(step["step"], manifest_inputs)
                token_values = [
                    value
                    for value in list(resolved_inputs.values()) + list(input_environment(step["step"]).values())
                    if value == PLACEHOLDER_TOKEN
                ]
                movable.append(f"{step['path'].relative_to(ROOT)} {step['uses']} token_inputs={len(token_values)}")
        self.assertEqual(
            movable,
            [],
            "actions resolved from a moving ref receive the repository token",
        )

    def test_full_sha_stays_on_the_reviewed_commit_when_branches_move(self) -> None:
        """A full SHA is the commit the runner downloads, not the branch tip."""
        pinned = "0123456789abcdef0123456789abcdef01234567"
        repo = init_action_repo("master")
        try:
            reviewed = resolve_ref(repo, pinned)
            attacker_moves_refs(repo)
            executed = resolve_ref(repo, pinned)
        finally:
            shutil.rmtree(repo)
        self.assertEqual(reviewed, executed)
        self.assertEqual(executed, pinned)

    def test_test_merge_permissions_are_contents_write_only(self) -> None:
        """The merge job must declare contents: write and no other scope.

        Omitted scopes are none once any scope is set. The implicit repository
        default is not an explicit minimum.
        """
        document = load_workflow(WORKFLOWS / "test-merge.yml")
        job = document["jobs"]["merge-branch"]
        permissions = effective_permissions(document, job)
        self.assertIsInstance(permissions, dict, "test-merge must set permissions")
        self.assertEqual(permissions.get("contents"), "write")
        extras = {key: value for key, value in permissions.items() if key != "contents"}
        self.assertEqual(extras, {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
