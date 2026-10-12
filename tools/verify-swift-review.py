#!/usr/bin/env python3
"""Zero-provider acceptance on disposable customer repositories. Pass a built acp executable."""
import json
import os
from pathlib import Path
import socket
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

binary = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix="acp-swift-review-", dir="/private/tmp") as root:
    root = Path(root)
    runtime = root / "runtime"
    runtime.mkdir()
    shutil.copy2(binary, runtime / "acp")
    shutil.copy2(binary.parent / "acp-swift-checks", runtime / "acp-swift-checks")
    binary = runtime / "acp"
    repo, state = root / "customer", root / "state"
    repo.mkdir(); state.mkdir()
    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.STDOUT)
    git("init", "-q")
    git("config", "user.name", "Review fixture")
    git("config", "user.email", "fixture@example.invalid")
    (repo / ".gitignore").write_text(".acp/\n")
    (repo / "Model.swift").write_text("import Foundation\nstruct Model: Identifiable { var id: UUID { UUID() } }\n")
    (repo / "Stable.swift").write_text("import Foundation\nstruct Stable: Identifiable { let id = UUID() }\n")
    git("add", "."); git("commit", "-qm", "Customer baseline")
    head = git("rev-parse", "HEAD")
    index = (repo / ".git/index").read_bytes()
    env = dict(os.environ, ACP_STATE_DIR=str(state))
    with (root / "daemon.log").open("wb") as log:
        process = subprocess.Popen([str(binary), "serve", "--no-mcp", "--repo", str(repo)], env=env, stdout=log, stderr=log)
        try:
            for _ in range(100):
                if (state / "acp.sock").exists(): break
                if process.poll() is not None: raise RuntimeError((root / "daemon.log").read_text())
                time.sleep(.1)
            def call(method, params):
                with socket.socket(socket.AF_UNIX) as sock:
                    sock.settimeout(15); sock.connect(str(state / "acp.sock"))
                    sock.sendall((json.dumps(dict(jsonrpc="2.0", id=1, method=method, params=params)) + "\n").encode())
                    with sock.makefile("rb") as stream: result = json.loads(stream.readline())
                    if "error" in result: raise RuntimeError(result["error"])
                    return result["result"]
            def run(scope, revision=None):
                request = dict(id=str(uuid.uuid4()), scope=scope, baseRef="HEAD", revision=revision)
                started = call("checks.start", request)
                assert call("checks.start", request)["id"] == started["id"], "duplicate created review"
                for _ in range(900):
                    rows = call("checks.list", {})["reviews"]
                    done = next(r for r in rows if r["id"] == started["id"])
                    if done["status"] != "running": break
                    time.sleep(.1)
                assert done["status"] in ("completed", "partial"), done
                return done, call("checks.result", dict(id=done["id"], offset=0))
            assert call("checks.catalog", {})["available"]
            whole, report = run("project")
            assert whole["fileCount"] == 2 and whole["findingCount"] == 1, report
            finding = report["findings"][0]
            source = call("checks.source", dict(id=whole["id"], file=finding["file"], line=finding["line"]))
            assert "UUID()" in "\n".join(line["text"] for line in source["lines"])
            fix = call("checks.prepareFix", dict(id=whole["id"], indices=[0]))
            assert "Model.swift" in fix["prompt"] and fix["manifestHash"] == report["manifestHash"]
            empty, _ = run("changes")
            assert empty["fileCount"] == 0 and empty["findingCount"] == 0
            (repo / "Model.swift").write_text("import Foundation\nstruct Model: Identifiable { let id = UUID() }\n")
            try:
                call("checks.prepareFix", dict(id=whole["id"], indices=[0]))
                raise AssertionError("stale source accepted for repair")
            except RuntimeError as error: assert "Source changed" in str(error)
            changed, _ = run("changes")
            assert changed["fileCount"] == 1 and changed["findingCount"] == 0
            (repo / "Broken.swift").write_text("struct Broken {")
            partial, partial_report = run("project")
            assert partial["status"] == "partial" and "Broken.swift" in partial_report["parseErrors"]
            old_source = call("checks.source", dict(id=whole["id"], file=finding["file"], line=finding["line"]))
            assert old_source == source, "history read mutable checkout"
            assert git("rev-parse", "HEAD") == head
            assert (repo / ".git/index").read_bytes() == index
            (repo / "Broken.swift").unlink()
            git("add", "Model.swift"); git("commit", "-qm", "Stable identity")
            revision_request = dict(id=str(uuid.uuid4()), scope="revision", baseRef="HEAD~1", revision="HEAD")
            revision_started = call("checks.start", revision_request)
            for _ in range(900):
                done = next(r for r in call("checks.list", {})["reviews"] if r["id"] == revision_started["id"])
                if done["status"] != "running": break
                time.sleep(.1)
            assert done["status"] == "completed" and done["fileCount"] == 1 and done["findingCount"] == 0, done
            head = git("rev-parse", "HEAD"); index = (repo / ".git/index").read_bytes()
            cancel_request = dict(id=str(uuid.uuid4()), scope="project", baseRef="HEAD", revision=None)
            call("checks.start", cancel_request); call("checks.cancel", dict(id=cancel_request["id"]))
            for _ in range(900):
                cancelled = next(r for r in call("checks.list", {})["reviews"] if r["id"] == cancel_request["id"])
                if cancelled["status"] != "running": break
                time.sleep(.1)
            assert cancelled["status"] == "cancelled", cancelled
            artifact = state / "checks" / whole["id"] / "report.json"
            original = artifact.read_bytes(); artifact.write_bytes(original + b" ")
            try:
                call("checks.result", dict(id=whole["id"], offset=0))
                raise AssertionError("tampered report was accepted")
            except RuntimeError as error: assert "hash" in str(error)
            artifact.write_bytes(original)
            assert git("rev-parse", "HEAD") == head
            assert (repo / ".git/index").read_bytes() == index
            status = call("get_status", {})
            assert not status.get("agents") and not status.get("gates"), status
            assert not list((state / "runs").glob("*/events.jsonl")), "review created provider runs"
            helper = runtime / "acp-swift-checks"
            helper.rename(runtime / "unavailable-helper")
            assert not call("checks.catalog", {})["available"]
            missing_request = dict(id=str(uuid.uuid4()), scope="project", baseRef="HEAD", revision=None)
            call("checks.start", missing_request)
            for _ in range(100):
                missing = next(r for r in call("checks.list", {})["reviews"] if r["id"] == missing_request["id"])
                if missing["status"] != "running": break
                time.sleep(.1)
            assert missing["status"] == "failed" and "not installed" in missing["detail"], missing
            (runtime / "unavailable-helper").rename(helper)
            for method, params in [("checks.start", dict(missing_request, scope="unknown")), ("checks.source", dict(id=whole["id"], file="../../secret", line=1))]:
                try:
                    call(method, params)
                    raise AssertionError("invalid input accepted")
                except RuntimeError: pass
            process.terminate(); process.wait(timeout=15)
            # A running record without a completion models a process stop during analysis.
            interrupted = dict(whole, id=str(uuid.uuid4()), status="running", reportHash=None, fileCount=0, findingCount=0)
            interrupted["request"] = dict(whole["request"], id=interrupted["id"])
            folder = state / "checks" / interrupted["id"]; folder.mkdir()
            (folder / "events.jsonl").write_text(json.dumps(interrupted) + "\n")
            process = subprocess.Popen([str(binary), "serve", "--no-mcp", "--repo", str(repo)], env=env, stdout=log, stderr=log)
            for _ in range(100):
                if (state / "acp.sock").exists():
                    try:
                        if len(call("checks.list", {})["reviews"]) == 8: break
                    except (OSError, RuntimeError): pass
                time.sleep(.1)
            assert call("checks.result", dict(id=whole["id"], offset=0))["summary"]["id"] == whole["id"]
            rows = call("checks.list", {})["reviews"]
            assert next(r for r in rows if r["id"] == interrupted["id"])["status"] == "interrupted"
            assert call("checks.start", interrupted["request"])["status"] == "interrupted"
            print("PASS: customer project/changes/revision/partial reviews; captured source; idempotency; cancellation; stale-fix and tamper refusal; missing-helper/invalid-input refusal; interrupted restart; unchanged HEAD/index; zero provider runs")
        finally:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=15)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
