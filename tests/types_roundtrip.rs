//! T08: `Event` serde round-trip, checked-in wire fixtures and forward compatibility
//! (`reports/03-design.md` § Test Strategy, row `core/types.rs`).
//!
//! Three properties, over all 25 `EventPayload` variants (`EVENT_KINDS`):
//!
//! 1. **Tag** — each variant serializes with the exact `kind` string the design fixes.
//! 2. **Drift** — each serialized event equals a *hand-written* fixture in `EVENT_FIXTURES`. The
//!    fixtures are the wire contract: nothing but this file's JSON pins `flatten` + internal
//!    tagging + every camelCase field name. Comparison is between parsed `serde_json::Value`s
//!    rather than raw strings: `serde_json::Map` is a `BTreeMap` here, so both sides are key-sorted
//!    and the comparison is byte-equal on a normalized document while staying immune to the
//!    declaration-order/alphabetical difference between a struct and a parsed object.
//! 3. **Forward compatibility** — an event carrying a key this build has never heard of still
//!    deserializes, because `Event`/`EventPayload` deliberately carry no `deny_unknown_fields`.
//!
//! `Task`, `Gate`, `AgentHandle` and `Attempt` round-trip once each: they are the records the
//! registry persists, and a field-naming typo in one of them would otherwise surface only at
//! replay time.

use std::path::PathBuf;
use std::str::FromStr;

use agent_control_plane::core::plan::{Plan, PlanItem, PlanItemKind, PlanItemStatus};
use agent_control_plane::core::types::{
    Actor, AgentHandle, AgentId, AgentStatus, Attempt, AttemptError, AttemptId, AttemptKind,
    AttemptStatus, CancelBy, CommitTarget, CostSource, DelegatedTarget, ErrorCode, Event,
    EventBase, EventPayload, False, Gate, GateId, GateKind, GateStatus, LineageId, LoopBranch,
    LoopState, MessageRole, Origin, PolicyViolation, ProviderName, ReviewFinding, RoleName, RunId,
    RunStatus, SchemaName, Severity, Task, TokenUsage, Verdict, VerifyStatus, ViolationKind,
    EVENT_KINDS,
};
use serde_json::{json, Value};

const RUN_ID: &str = "11111111-1111-4111-8111-111111111111";
const AGENT_ID: &str = "22222222-2222-4222-8222-222222222222";
const ATTEMPT_ID: &str = "33333333-3333-4333-8333-333333333333";
const GATE_ID: &str = "44444444-4444-4444-8444-444444444444";
const LINEAGE_ID: &str = "55555555-5555-4555-8555-555555555555";
const REVIEWER_ATTEMPT_ID: &str = "66666666-6666-4666-8666-666666666666";
const SESSION_ID: &str = "aaaaaaaa-1111-4a11-8a11-aaaaaaaaaaaa";
/// The run a `run.delegated` fixture points at — distinct from `RUN_ID` (the envelope's own run,
/// the lead) on purpose: a transposition of the two must not round-trip invisibly.
const DELEGATED_RUN_ID: &str = "88888888-8888-4888-8888-888888888888";

const TS: &str = "2026-08-22T22:00:00.000Z";
const PRE_SHA: &str = "1f0c0d1e2a3b4c5d6e7f8091a2b3c4d5e6f70819";
const POST_SHA: &str = "2b1d0e2f3a4b5c6d7e8f90a1b2c3d4e5f6071829";
const INTEGRATE_SHA: &str = "3c2e1f304a5b6c7d8e9f0a1b2c3d4e5f60718293";
/// sha256 of the frozen diff — what the reviewer must echo back (Rev 25), 64 hex.
const DIFF_HASH: &str = "7d6d0f2c1b3a49586776859493a2b1c0dfeeddccbbaa99887766554433221100";

const REPO_ROOT: &str = "/Users/dev/repo";
const STATE_DIR: &str = "/Users/dev/.acp/0f1e2d3c4b5a6978";
const WORKTREE: &str = "/Users/dev/repo/.acp/worktrees/run-1/agent-1";
const ATTEMPT_DIR: &str = "/Users/dev/.acp/0f1e2d3c4b5a6978/attempts/3333";
const RESULT_PATH: &str = "/Users/dev/.acp/0f1e2d3c4b5a6978/attempts/3333/result.txt";
const DIFF_PATH: &str = "/Users/dev/.acp/0f1e2d3c4b5a6978/runs/1111/diffs/3333.patch";
const GATE_PAYLOAD_PATH: &str =
    "/Users/dev/.acp/0f1e2d3c4b5a6978/runs/1111/gates/4444.payload.json";

/// The wire form of one event per `EVENT_KINDS` entry, in that order, `seq` = index + 1.
///
/// Hand-written on purpose: generating it from the types would make it agree with them by
/// construction and guard nothing. Every optional field appears explicitly as `null` — the design
/// puts no `skip_serializing_if` on the union, so a reader may rely on the key being present.
const EVENT_FIXTURES: &str = r#"[
  {
    "seq": 1, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "run.created",
    "repoRoot": "/Users/dev/repo",
    "stateDir": "/Users/dev/.acp/0f1e2d3c4b5a6978",
    "baseRef": "main",
    "baseSha": "1f0c0d1e2a3b4c5d6e7f8091a2b3c4d5e6f70819",
    "task": {
      "id": "T08",
      "title": "tests/types_roundtrip.rs",
      "description": "Event serde round-trip + forward-compat",
      "files": ["tests/types_roundtrip.rs"],
      "acceptance": ["cargo test --test types_roundtrip exits 0"]
    },
    "version": 1,
    "lead": "claude",
    "teamName": null
  },
  {
    "seq": 2, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "run.status",
    "status": "running",
    "reason": null
  },
  {
    "seq": 3, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "loop.state",
    "state": "building",
    "builderAgentId": "22222222-2222-4222-8222-222222222222",
    "attemptNo": 1,
    "strikes": 0
  },
  {
    "seq": 4, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "worktree.created",
    "agentId": "22222222-2222-4222-8222-222222222222",
    "lineageId": "55555555-5555-4555-8555-555555555555",
    "path": "/Users/dev/repo/.acp/worktrees/run-1/agent-1",
    "branch": "acp/run-1/agent-1",
    "baseSha": "1f0c0d1e2a3b4c5d6e7f8091a2b3c4d5e6f70819"
  },
  {
    "seq": 5, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "worktree.retired",
    "path": "/Users/dev/repo/.acp/worktrees/run-1/agent-1",
    "reason": "lineage closed after two strikes",
    "resumable": false
  },
  {
    "seq": 6, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "agent.created",
    "agentId": "22222222-2222-4222-8222-222222222222",
    "role": "builder",
    "provider": "claude",
    "model": "claude-sonnet-4-5",
    "lineageId": "55555555-5555-4555-8555-555555555555",
    "depth": 1,
    "parentAgentId": null,
    "origin": "lead",
    "writes": true,
    "cwd": "/Users/dev/repo/.acp/worktrees/run-1/agent-1",
    "worktree": "/Users/dev/repo/.acp/worktrees/run-1/agent-1"
  },
  {
    "seq": 7, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "agent.session",
    "agentId": "22222222-2222-4222-8222-222222222222",
    "attemptId": "33333333-3333-4333-8333-333333333333",
    "sessionId": "aaaaaaaa-1111-4a11-8a11-aaaaaaaaaaaa",
    "srcLine": 1
  },
  {
    "seq": 8, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "agent.status",
    "agentId": "22222222-2222-4222-8222-222222222222",
    "status": "running",
    "reason": null
  },
  {
    "seq": 9, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "attempt.started",
    "attemptId": "33333333-3333-4333-8333-333333333333",
    "agentId": "22222222-2222-4222-8222-222222222222",
    "kind2": "fresh",
    "dir": "/Users/dev/.acp/0f1e2d3c4b5a6978/attempts/3333",
    "argv": ["claude", "-p", "Implement T08"],
    "cwd": "/Users/dev/repo/.acp/worktrees/run-1/agent-1",
    "pid": 41234,
    "pgid": 41234,
    "startTime": "Sat Aug 22 22:00:00 2026",
    "preSha": "1f0c0d1e2a3b4c5d6e7f8091a2b3c4d5e6f70819",
    "timeoutSec": 900,
    "spawnBudgetUsd": 1.5
  },
  {
    "seq": 10, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "agent.progress",
    "attemptId": "33333333-3333-4333-8333-333333333333",
    "srcLine": 12,
    "phase": "tool_use",
    "note": "Edit"
  },
  {
    "seq": 11, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "attempt.usage",
    "attemptId": "33333333-3333-4333-8333-333333333333",
    "srcLine": 30,
    "costUsd": 0.0262357,
    "tokens": { "input": 42, "cachedInput": 32147, "output": 1083, "reasoning": null },
    "source": "provider"
  },
  {
    "seq": 12, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "attempt.result",
    "attemptId": "33333333-3333-4333-8333-333333333333",
    "srcLine": 31,
    "resultPath": "/Users/dev/.acp/0f1e2d3c4b5a6978/attempts/3333/result.txt",
    "schema": "build-result",
    "structuredValid": true,
    "structured": {
      "status": "succeeded",
      "filesChanged": ["src/adder.ts"],
      "summary": "Added src/adder.ts exporting add(a, b)."
    }
  },
  {
    "seq": 13, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "attempt.cancel_requested",
    "attemptId": "33333333-3333-4333-8333-333333333333",
    "by": "timeout"
  },
  {
    "seq": 14, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "attempt.finished",
    "attemptId": "33333333-3333-4333-8333-333333333333",
    "status": "succeeded",
    "exitCode": 0,
    "signal": null,
    "postSha": "2b1d0e2f3a4b5c6d7e8f90a1b2c3d4e5f6071829",
    "durationMs": 15753,
    "error": null
  },
  {
    "seq": 15, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "policy.violation",
    "attemptId": "33333333-3333-4333-8333-333333333333",
    "agentId": "22222222-2222-4222-8222-222222222222",
    "violation": {
      "kind": "worker_committed",
      "detail": "the worker ran git commit",
      "files": ["src/adder.ts"],
      "preSha": "1f0c0d1e2a3b4c5d6e7f8091a2b3c4d5e6f70819",
      "postSha": "2b1d0e2f3a4b5c6d7e8f90a1b2c3d4e5f6071829"
    }
  },
  {
    "seq": 16, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "diff.frozen",
    "attemptId": "33333333-3333-4333-8333-333333333333",
    "diffPath": "/Users/dev/.acp/0f1e2d3c4b5a6978/runs/1111/diffs/3333.patch",
    "diffHash": "7d6d0f2c1b3a49586776859493a2b1c0dfeeddccbbaa99887766554433221100",
    "files": ["src/adder.ts"],
    "added": 12,
    "deleted": 3
  },
  {
    "seq": 17, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "review.verdict",
    "attemptId": "66666666-6666-4666-8666-666666666666",
    "builderAttemptId": "33333333-3333-4333-8333-333333333333",
    "verdict": "FAIL",
    "findings": [
      {
        "severity": "blocking",
        "file": "src/adder.ts",
        "line": 2,
        "problem": "add() returns a - b, so every caller gets the wrong value.",
        "fix": "Return a + b."
      },
      {
        "severity": "suggestion",
        "file": "src/adder.ts",
        "line": null,
        "problem": "No unit test covers the new export.",
        "fix": null
      }
    ],
    "diffHash": "7d6d0f2c1b3a49586776859493a2b1c0dfeeddccbbaa99887766554433221100"
  },
  {
    "seq": 18, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "lineage.strike",
    "lineageId": "55555555-5555-4555-8555-555555555555",
    "agentId": "22222222-2222-4222-8222-222222222222",
    "reason": "invalid_output: the final message was not a build-result document",
    "strikes": 1
  },
  {
    "seq": 19, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "lineage.closed",
    "lineageId": "55555555-5555-4555-8555-555555555555",
    "reason": "two strikes: replacing the builder in a new worktree"
  },
  {
    "seq": 20, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "gate.created",
    "gateId": "44444444-4444-4444-8444-444444444444",
    "gkind": "integrate",
    "summary": "Integrate T08 - 1 file changed",
    "payloadPath": "/Users/dev/.acp/0f1e2d3c4b5a6978/runs/1111/gates/4444.payload.json",
    "requestedBy": "control-plane"
  },
  {
    "seq": 21, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "gate.resolving",
    "gateId": "44444444-4444-4444-8444-444444444444",
    "approve": true,
    "feedback": null,
    "by": "acp-mac",
    "commit": {
      "worktree": "/Users/dev/repo/.acp/worktrees/run-1/agent-1",
      "subject": "acp: Integrate T08 - 1 file changed",
      "files": ["src/adder.ts"],
      "diffHash": "7d6d0f2c1b3a49586776859493a2b1c0dfeeddccbbaa99887766554433221100",
      "preSha": "1f0c0d1e2a3b4c5d6e7f8091a2b3c4d5e6f70819",
      "diffPath": "/Users/dev/.acp/0f1e2d3c4b5a6978/runs/1111/diffs/3333.patch"
    }
  },
  {
    "seq": 22, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "gate.resolved",
    "gateId": "44444444-4444-4444-8444-444444444444",
    "status": "approved",
    "sha": "3c2e1f304a5b6c7d8e9f0a1b2c3d4e5f60718293",
    "feedback": null
  },
  {
    "seq": 23, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "integrate.committed",
    "gateId": "44444444-4444-4444-8444-444444444444",
    "worktree": "/Users/dev/repo/.acp/worktrees/run-1/agent-1",
    "sha": "3c2e1f304a5b6c7d8e9f0a1b2c3d4e5f60718293",
    "subject": "T08 tests/types_roundtrip.rs",
    "files": ["tests/types_roundtrip.rs"]
  },
  {
    "seq": 24, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "loop.dispatched",
    "attemptId": "33333333-3333-4333-8333-333333333333",
    "branch": "review"
  },
  {
    "seq": 25, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "agent.message",
    "attemptId": "33333333-3333-4333-8333-333333333333",
    "srcLine": 19,
    "role": "assistant",
    "text": "I inspected the repository and found the failing boundary."
  },
  {
    "seq": 26, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "verify.report",
    "attemptId": "77777777-7777-4777-8777-777777777777",
    "builderAttemptId": "33333333-3333-4333-8333-333333333333",
    "status": "fail",
    "summary": "cargo test: 1 of 12 failing",
    "failures": ["types::round_trip"]
  },
  {
    "seq": 27, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "plan.created",
    "plan": {
      "version": 1, "name": "two steps",
      "items": [
        { "id": "schema", "kind": "work",
          "task": { "id": "T08", "title": "tests/types_roundtrip.rs",
                    "description": "Event serde round-trip + forward-compat",
                    "files": ["tests/types_roundtrip.rs"],
                    "acceptance": ["cargo test --test types_roundtrip exits 0"] },
          "review": true },
        { "id": "sign", "kind": "human", "summary": "look before landing", "after": ["schema"] }
      ]
    }
  },
  {
    "seq": 28, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "plan.item",
    "itemId": "schema",
    "status": "started",
    "itemRunId": "11111111-1111-4111-8111-111111111111"
  },
  {
    "seq": 29, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "run.delegated",
    "delegatedRunId": "88888888-8888-4888-8888-888888888888",
    "role": "builder",
    "target": "worker"
  },
  {
    "seq": 30, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "audit.prepared",
    "snapshot": {
      "version": 1, "selection": {"baseRef": "main", "target": {"kind": "revision", "revision": "HEAD"}},
      "baseSha": "1f0c0d1e2a3b4c5d6e7f8091a2b3c4d5e6f70819",
      "treeSha": "2b1d0e2f3a4b5c6d7e8f90a1b2c3d4e5f6071829",
      "worktree": "/Users/dev/repo/.acp/worktrees/run-1/agent-1",
      "diffPath": "/Users/dev/.acp/0f1e2d3c4b5a6978/runs/1111/diffs/3333.patch",
      "diffHash": "7d6d0f2c1b3a49586776859493a2b1c0dfeeddccbbaa99887766554433221100",
      "files": ["src/adder.ts"], "manifestPath": "/state/tracked-files.json",
      "manifestHash": "7d6d0f2c1b3a49586776859493a2b1c0dfeeddccbbaa99887766554433221100",
      "sourceHash": "7d6d0f2c1b3a49586776859493a2b1c0dfeeddccbbaa99887766554433221100"
    }
  },
  {
    "seq": 31, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind": "audit.checked", "check": {
      "attemptId": "33333333-3333-4333-8333-333333333333", "role": "verifier",
      "diffHash": "7d6d0f2c1b3a49586776859493a2b1c0dfeeddccbbaa99887766554433221100",
      "outcome": "nothing_to_run", "summary": "No test command"
    }
  },
  {
    "seq": 32, "ts": "2026-08-22T22:00:00.000Z", "runId": "11111111-1111-4111-8111-111111111111",
    "kind":"security.verdict", "attemptId":"33333333-3333-4333-8333-333333333333",
    "builderAttemptId":"33333333-3333-4333-8333-333333333333", "verdict":"PASS", "findings":[],
    "diffHash":"7d6d0f2c1b3a49586776859493a2b1c0dfeeddccbbaa99887766554433221100"
  },
  {
    "seq":33, "ts":"2026-08-22T22:00:00.000Z", "runId":"11111111-1111-4111-8111-111111111111",
    "kind":"run.recovered", "recovery": {
      "request": { "runId":"11111111-1111-4111-8111-111111111111",
        "sourceAgentId":"22222222-2222-4222-8222-222222222222", "expectedSeq":32,
        "requestId":"99999999-9999-4999-8999-999999999999",
        "builder":{"provider":"codex","model":"gpt-5.5"}, "feedback":"Continue this draft" },
      "agentId":"88888888-8888-4888-8888-888888888888", "by":"acp-mac",
      "gateIds":["44444444-4444-4444-8444-444444444444"]
    }
  }
]"#;

const VERIFIER_ATTEMPT_ID: &str = "77777777-7777-4777-8777-777777777777";

fn verifier_attempt_id() -> AttemptId {
    AttemptId::from_str(VERIFIER_ATTEMPT_ID).expect("parse verifier attempt id")
}

fn run_id() -> RunId {
    RunId::from_str(RUN_ID).expect("parse run id")
}

fn delegated_run_id() -> RunId {
    RunId::from_str(DELEGATED_RUN_ID).expect("parse delegated run id")
}

fn agent_id() -> AgentId {
    AgentId::from_str(AGENT_ID).expect("parse agent id")
}

fn attempt_id() -> AttemptId {
    AttemptId::from_str(ATTEMPT_ID).expect("parse attempt id")
}

fn reviewer_attempt_id() -> AttemptId {
    AttemptId::from_str(REVIEWER_ATTEMPT_ID).expect("parse reviewer attempt id")
}

fn gate_id() -> GateId {
    GateId::from_str(GATE_ID).expect("parse gate id")
}

/// The commit target `gate.resolving` records and `Gate.commit` projects.
fn commit_target() -> CommitTarget {
    CommitTarget {
        worktree: PathBuf::from(WORKTREE),
        subject: "acp: Integrate T08 - 1 file changed".into(),
        files: vec!["src/adder.ts".into()],
        diff_hash: Some(DIFF_HASH.into()),
        pre_sha: Some(PRE_SHA.into()),
        diff_path: Some(PathBuf::from(DIFF_PATH)),
    }
}

fn lineage_id() -> LineageId {
    LineageId::from_str(LINEAGE_ID).expect("parse lineage id")
}

fn task() -> Task {
    Task {
        id: "T08".into(),
        title: "tests/types_roundtrip.rs".into(),
        description: "Event serde round-trip + forward-compat".into(),
        files: vec!["tests/types_roundtrip.rs".into()],
        acceptance: vec!["cargo test --test types_roundtrip exits 0".into()],
    }
}

fn tokens() -> TokenUsage {
    TokenUsage {
        input: 42,
        cached_input: 32_147,
        output: 1_083,
        reasoning: None,
    }
}

fn structured_build_result() -> Value {
    json!({
        "status": "succeeded",
        "filesChanged": ["src/adder.ts"],
        "summary": "Added src/adder.ts exporting add(a, b)."
    })
}

/// One instance of every `EventPayload` variant, in `EVENT_KINDS` order, paired index-for-index
/// with `EVENT_FIXTURES`.
fn payloads() -> Vec<EventPayload> {
    vec![
        EventPayload::RunCreated {
            execution: None,
            repo_root: PathBuf::from(REPO_ROOT),
            state_dir: PathBuf::from(STATE_DIR),
            base_ref: "main".into(),
            base_sha: PRE_SHA.into(),
            task: task(),
            version: 1,
            lead: Some("claude".into()),
            team_name: None,
            steps: None,
        },
        EventPayload::RunStatus_ {
            status: RunStatus::Running,
            reason: None,
        },
        EventPayload::LoopStateChanged {
            state: LoopState::Building,
            builder_agent_id: Some(agent_id()),
            attempt_no: 1,
            strikes: 0,
        },
        EventPayload::WorktreeCreated {
            agent_id: agent_id(),
            lineage_id: lineage_id(),
            path: PathBuf::from(WORKTREE),
            branch: "acp/run-1/agent-1".into(),
            base_sha: PRE_SHA.into(),
        },
        EventPayload::WorktreeRetired {
            path: PathBuf::from(WORKTREE),
            reason: "lineage closed after two strikes".into(),
            resumable: False,
        },
        EventPayload::AgentCreated {
            agent_id: agent_id(),
            role: RoleName::Builder,
            provider: ProviderName::Claude,
            model: "claude-sonnet-4-5".into(),
            lineage_id: Some(lineage_id()),
            depth: 1,
            parent_agent_id: None,
            origin: Origin::Lead,
            writes: true,
            cwd: PathBuf::from(WORKTREE),
            worktree: Some(PathBuf::from(WORKTREE)),
        },
        EventPayload::AgentSession {
            agent_id: agent_id(),
            attempt_id: attempt_id(),
            session_id: SESSION_ID.into(),
            src_line: 1,
        },
        EventPayload::AgentStatusChanged {
            agent_id: agent_id(),
            status: AgentStatus::Running,
            reason: None,
        },
        EventPayload::AttemptStarted {
            attempt_id: attempt_id(),
            agent_id: agent_id(),
            attempt_kind: AttemptKind::Fresh,
            dir: PathBuf::from(ATTEMPT_DIR),
            argv: vec!["claude".into(), "-p".into(), "Implement T08".into()],
            cwd: PathBuf::from(WORKTREE),
            pid: 41_234,
            pgid: 41_234,
            start_time: "Sat Aug 22 22:00:00 2026".into(),
            pre_sha: PRE_SHA.into(),
            timeout_sec: 900,
            spawn_budget_usd: 1.5,
        },
        EventPayload::AgentProgress {
            attempt_id: attempt_id(),
            src_line: 12,
            phase: "tool_use".into(),
            note: Some("Edit".into()),
        },
        EventPayload::AttemptUsage {
            attempt_id: attempt_id(),
            src_line: 30,
            cost_usd: 0.026_235_7,
            tokens: tokens(),
            source: CostSource::Provider,
        },
        EventPayload::AttemptResult {
            attempt_id: attempt_id(),
            src_line: 31,
            result_path: PathBuf::from(RESULT_PATH),
            schema: "build-result".into(),
            structured_valid: true,
            structured: Some(structured_build_result()),
        },
        EventPayload::AttemptCancelRequested {
            attempt_id: attempt_id(),
            by: CancelBy::Timeout,
        },
        EventPayload::AttemptFinished {
            attempt_id: attempt_id(),
            status: AttemptStatus::Succeeded,
            exit_code: Some(0),
            signal: None,
            post_sha: Some(POST_SHA.into()),
            duration_ms: 15_753,
            error: None,
        },
        EventPayload::PolicyViolated {
            attempt_id: Some(attempt_id()),
            agent_id: Some(agent_id()),
            violation: PolicyViolation {
                kind: ViolationKind::WorkerCommitted,
                detail: "the worker ran git commit".into(),
                files: Some(vec!["src/adder.ts".into()]),
                pre_sha: Some(PRE_SHA.into()),
                post_sha: Some(POST_SHA.into()),
            },
        },
        EventPayload::DiffFrozen {
            attempt_id: attempt_id(),
            diff_path: PathBuf::from(DIFF_PATH),
            diff_hash: DIFF_HASH.into(),
            files: vec!["src/adder.ts".into()],
            added: 12,
            deleted: 3,
        },
        EventPayload::ReviewVerdict {
            attempt_id: reviewer_attempt_id(),
            builder_attempt_id: attempt_id(),
            verdict: Verdict::Fail,
            findings: vec![
                ReviewFinding {
                    severity: Severity::Blocking,
                    file: Some("src/adder.ts".into()),
                    line: Some(2),
                    problem: "add() returns a - b, so every caller gets the wrong value.".into(),
                    fix: Some("Return a + b.".into()),
                },
                ReviewFinding {
                    severity: Severity::Suggestion,
                    file: Some("src/adder.ts".into()),
                    line: None,
                    problem: "No unit test covers the new export.".into(),
                    fix: None,
                },
            ],
            diff_hash: Some(DIFF_HASH.into()),
        },
        EventPayload::LineageStrike {
            lineage_id: lineage_id(),
            agent_id: agent_id(),
            reason: "invalid_output: the final message was not a build-result document".into(),
            strikes: 1,
        },
        EventPayload::LineageClosed {
            lineage_id: lineage_id(),
            reason: "two strikes: replacing the builder in a new worktree".into(),
        },
        EventPayload::GateCreated {
            gate_id: gate_id(),
            gate_kind: GateKind::Integrate,
            summary: "Integrate T08 - 1 file changed".into(),
            payload_path: PathBuf::from(GATE_PAYLOAD_PATH),
            requested_by: Origin::ControlPlane,
        },
        EventPayload::GateResolving {
            gate_id: gate_id(),
            approve: true,
            feedback: None,
            by: Actor::Socket {
                client_name: "acp-mac".into(),
            },
            commit: Some(commit_target()),
        },
        EventPayload::GateResolved {
            gate_id: gate_id(),
            status: GateStatus::Approved,
            sha: Some(INTEGRATE_SHA.into()),
            feedback: None,
        },
        EventPayload::IntegrateCommitted {
            gate_id: gate_id(),
            worktree: PathBuf::from(WORKTREE),
            sha: INTEGRATE_SHA.into(),
            subject: "T08 tests/types_roundtrip.rs".into(),
            files: vec!["tests/types_roundtrip.rs".into()],
        },
        EventPayload::LoopDispatched {
            attempt_id: attempt_id(),
            branch: LoopBranch::Review,
        },
        EventPayload::AgentMessage {
            attempt_id: attempt_id(),
            src_line: 19,
            role: MessageRole::Assistant,
            text: "I inspected the repository and found the failing boundary.".into(),
            part: None,
        },
        EventPayload::VerifyReport {
            attempt_id: verifier_attempt_id(),
            builder_attempt_id: attempt_id(),
            status: VerifyStatus::Fail,
            summary: "cargo test: 1 of 12 failing".into(),
            failures: vec!["types::round_trip".into()],
        },
        EventPayload::PlanCreated {
            plan: Plan {
                version: 1,
                name: "two steps".into(),
                items: vec![
                    PlanItem {
                        id: "schema".into(),
                        kind: PlanItemKind::Work,
                        task: Some(task()),
                        summary: None,
                        after: vec![],
                        verify: None,
                        review: Some(true),
                    },
                    PlanItem {
                        id: "sign".into(),
                        kind: PlanItemKind::Human,
                        task: None,
                        summary: Some("look before landing".into()),
                        after: vec!["schema".into()],
                        verify: None,
                        review: None,
                    },
                ],
            },
        },
        EventPayload::PlanItem {
            item_id: "schema".into(),
            status: PlanItemStatus::Started,
            run_id: Some(run_id()),
            gate_id: None,
        },
        EventPayload::RunDelegated {
            delegated_run_id: delegated_run_id(),
            role: Some(RoleName::Builder),
            target: DelegatedTarget::Worker,
        },
        EventPayload::AuditPrepared { snapshot: agent_control_plane::workspace::git::audit::Snapshot {
            version: 1, selection: agent_control_plane::workspace::git::audit::Selection { base_ref: "main".into(),
                target: agent_control_plane::workspace::git::audit::Target::Revision { revision: "HEAD".into() } },
            base_sha: PRE_SHA.into(), tree_sha: POST_SHA.into(), worktree: WORKTREE.into(), diff_path: DIFF_PATH.into(),
            diff_hash: DIFF_HASH.into(), files: vec!["src/adder.ts".into()], manifest_path: "/state/tracked-files.json".into(), manifest_hash: DIFF_HASH.into(), source_hash: DIFF_HASH.into(),
        } },
        EventPayload::AuditChecked { check: agent_control_plane::core::types::AuditCheck {
            attempt_id: attempt_id(), role: RoleName::Verifier, diff_hash: DIFF_HASH.into(),
            outcome: agent_control_plane::core::types::AuditOutcome::NothingToRun, summary: "No test command".into(),
        } },
        EventPayload::SecurityVerdict { attempt_id: attempt_id(), builder_attempt_id: attempt_id(),
            verdict: Verdict::Pass, findings: vec![], diff_hash: DIFF_HASH.into() },
        EventPayload::RunRecovered { recovery: agent_control_plane::core::recovery::Record {
            request: agent_control_plane::core::recovery::Request { run_id: run_id(), source_agent_id: agent_id(),
                expected_seq: 32, request_id: uuid::Uuid::parse_str("99999999-9999-4999-8999-999999999999").unwrap(),
                builder: agent_control_plane::core::team::Assignment { provider: ProviderName::Codex, model: "gpt-5.5".into(), effort: None },
                feedback: "Continue this draft".into() },
            agent_id: "88888888-8888-4888-8888-888888888888".parse().unwrap(),
            by: Actor::Socket { client_name: "acp-mac".into() }, gate_ids: vec![gate_id()],
        } },
    ]
}

fn fixtures() -> Vec<Value> {
    match serde_json::from_str::<Value>(EVENT_FIXTURES).expect("EVENT_FIXTURES is valid JSON") {
        Value::Array(items) => items,
        other => panic!("EVENT_FIXTURES must be an array, got {other}"),
    }
}

/// The event the registry would have appended for `payloads()[i]`: `seq` = i + 1, one fixed run.
fn event(seq: usize, payload: EventPayload) -> Event {
    Event {
        base: EventBase {
            seq: seq as u64,
            ts: TS.into(),
            run_id: run_id(),
        },
        payload,
    }
}

#[test]
fn every_design_event_kind_has_exactly_one_fixture() {
    assert_eq!(
        EVENT_KINDS.len(),
        33,
        "T94 appends an atomic recovery record"
    );
    let fixtures = fixtures();
    let kinds: Vec<&str> = fixtures
        .iter()
        .map(|f| f["kind"].as_str().expect("fixture carries a kind string"))
        .collect();
    assert_eq!(
        kinds, EVENT_KINDS,
        "fixtures must cover EVENT_KINDS in order"
    );
    assert_eq!(payloads().len(), EVENT_KINDS.len());
}

#[test]
fn every_payload_serializes_with_its_design_kind_tag() {
    for (payload, expected) in payloads().into_iter().zip(EVENT_KINDS) {
        let json = serde_json::to_value(&payload).expect("serialize payload");
        assert_eq!(
            json["kind"].as_str(),
            Some(*expected),
            "payload {payload:?} carries the wrong kind tag"
        );
    }
}

#[test]
fn every_event_round_trips_through_serde_json() {
    for (i, payload) in payloads().into_iter().enumerate() {
        let original = event(i + 1, payload);
        let text = serde_json::to_string(&original).expect("serialize event");
        let back: Event = serde_json::from_str(&text).expect("deserialize event");
        assert_eq!(back, original, "round-trip changed the event: {text}");
        assert_eq!(
            serde_json::to_string(&back).expect("re-serialize event"),
            text,
            "re-serializing a round-tripped event is not byte-identical"
        );
    }
}

#[test]
fn every_event_matches_its_checked_in_wire_fixture() {
    for ((i, payload), fixture) in payloads().into_iter().enumerate().zip(fixtures()) {
        let kind = EVENT_KINDS[i];
        let serialized = serde_json::to_value(event(i + 1, payload)).expect("serialize event");
        assert_eq!(serialized, fixture, "{kind} drifted from its wire fixture");
    }
}

#[test]
fn every_wire_fixture_deserializes_into_its_event() {
    for ((i, payload), fixture) in payloads().into_iter().enumerate().zip(fixtures()) {
        let kind = EVENT_KINDS[i];
        let parsed: Event =
            serde_json::from_value(fixture).unwrap_or_else(|err| panic!("{kind}: {err}"));
        assert_eq!(parsed, event(i + 1, payload), "{kind} deserialized wrong");
    }
}

#[test]
fn an_event_with_an_unknown_extra_key_still_deserializes() {
    let text = format!(
        r#"{{"seq":1,"ts":"{TS}","runId":"{RUN_ID}","kind":"run.status","status":"running","reason":null,"futureField":true}}"#
    );
    let parsed: Event = serde_json::from_str(&text).expect("Event carries no deny_unknown_fields");
    assert_eq!(parsed.base.seq, 1);
    assert_eq!(parsed.base.run_id, run_id());
    assert_eq!(
        parsed.payload,
        EventPayload::RunStatus_ {
            status: RunStatus::Running,
            reason: None
        }
    );
}

/// The other direction of compatibility: an event written *before* a field was added still
/// replays. `gate.resolving` gained `commit` additively, and a state dir full of older lines has
/// to keep loading — `Option<T>` defaults to `None` for a missing key, and this pins that.
#[test]
fn an_event_written_before_an_added_field_still_deserializes() {
    let text = format!(
        r#"{{"seq":21,"ts":"{TS}","runId":"{RUN_ID}","kind":"gate.resolving","gateId":"{GATE_ID}","approve":true,"feedback":null,"by":"cli"}}"#
    );
    let event: Event = serde_json::from_str(&text).expect("an older gate.resolving line");
    match event.payload {
        EventPayload::GateResolving {
            commit, approve, ..
        } => {
            assert!(
                commit.is_none(),
                "a missing key reads as None, not an error"
            );
            assert!(approve);
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

#[test]
fn an_unknown_kind_is_rejected() {
    let text = format!(
        r#"{{"seq":1,"ts":"{TS}","runId":"{RUN_ID}","kind":"run.exploded","status":"running"}}"#
    );
    assert!(
        serde_json::from_str::<Event>(&text).is_err(),
        "the kind tag is a closed set"
    );
}

#[test]
fn task_round_trips_through_serde_json() {
    let json = serde_json::to_value(task()).expect("serialize task");
    assert_eq!(json["id"], "T08");
    assert_eq!(
        json["acceptance"][0],
        "cargo test --test types_roundtrip exits 0"
    );
    let back: Task = serde_json::from_value(json).expect("deserialize task");
    assert_eq!(back, task());
}

#[test]
fn agent_handle_round_trips_through_serde_json() {
    let handle = AgentHandle {
        agent_id: agent_id(),
        run_id: run_id(),
        role: RoleName::Builder,
        provider: ProviderName::Claude,
        model: "claude-sonnet-4-5".into(),
        lineage_id: Some(lineage_id()),
        depth: 1,
        parent_agent_id: None,
        origin: Origin::Lead,
        writes: true,
        worktree: Some(PathBuf::from(WORKTREE)),
        cwd: PathBuf::from(WORKTREE),
        session_id: Some(SESSION_ID.into()),
        status: AgentStatus::Running,
        resumable: true,
        attempt_ids: vec![attempt_id()],
        created_at: TS.into(),
    };
    let json = serde_json::to_value(&handle).expect("serialize agent handle");
    assert_eq!(json["agentId"], AGENT_ID);
    assert_eq!(json["lineageId"], LINEAGE_ID);
    assert_eq!(json["parentAgentId"], Value::Null);
    assert_eq!(json["sessionId"], SESSION_ID);
    assert_eq!(json["attemptIds"][0], ATTEMPT_ID);
    assert_eq!(json["createdAt"], TS);
    let back: AgentHandle = serde_json::from_value(json).expect("deserialize agent handle");
    assert_eq!(back, handle);
}

#[test]
fn attempt_round_trips_through_serde_json() {
    let attempt = Attempt {
        attempt_id: attempt_id(),
        agent_id: agent_id(),
        run_id: run_id(),
        kind: AttemptKind::Resume,
        dir: PathBuf::from(ATTEMPT_DIR),
        pid: Some(41_234),
        pgid: Some(41_234),
        start_time: Some("Sat Aug 22 22:00:00 2026".into()),
        status: AttemptStatus::InvalidOutput,
        error: Some(AttemptError {
            code: ErrorCode::SchemaInvalid,
            message: "the final message was not a build-result document".into(),
        }),
        started_at: TS.into(),
        finished_at: Some(TS.into()),
        pre_sha: PRE_SHA.into(),
        post_sha: Some(POST_SHA.into()),
        exit_code: Some(0),
        signal: None,
        cost_usd: 0.026_235_7,
        tokens: Some(tokens()),
        src_line: 31,
        byte_offset: 8_192,
        timeout_sec: 900,
        spawn_budget_usd: 1.5,
        result_path: Some(PathBuf::from(RESULT_PATH)),
        structured_valid: Some(false),
        structured: Some(structured_build_result()),
        violations: vec![PolicyViolation {
            kind: ViolationKind::DenylistHit,
            detail: "Sub/App.xcconfig is denylisted".into(),
            files: Some(vec!["Sub/App.xcconfig".into()]),
            pre_sha: None,
            post_sha: None,
        }],
        diff_path: Some(PathBuf::from(DIFF_PATH)),
    };
    let json = serde_json::to_value(&attempt).expect("serialize attempt");
    assert_eq!(json["attemptId"], ATTEMPT_ID);
    assert_eq!(json["startTime"], "Sat Aug 22 22:00:00 2026");
    assert_eq!(json["preSha"], PRE_SHA);
    assert_eq!(json["costUsd"], 0.026_235_7);
    assert_eq!(json["tokens"]["cachedInput"], 32_147);
    assert_eq!(json["srcLine"], 31);
    assert_eq!(json["byteOffset"], 8_192);
    assert_eq!(json["timeoutSec"], 900);
    assert_eq!(json["spawnBudgetUsd"], 1.5);
    assert_eq!(json["structuredValid"], false);
    assert_eq!(json["violations"][0]["kind"], "denylist_hit");
    assert_eq!(json["diffPath"], DIFF_PATH);
    let back: Attempt = serde_json::from_value(json).expect("deserialize attempt");
    assert_eq!(back, attempt);
}

#[test]
fn gate_round_trips_through_serde_json() {
    let gate = Gate {
        gate_id: gate_id(),
        run_id: run_id(),
        kind: GateKind::Integrate,
        status: GateStatus::Approved,
        summary: "Integrate T08 - 1 file changed".into(),
        payload_path: PathBuf::from(GATE_PAYLOAD_PATH),
        requested_by: Origin::ControlPlane,
        created_at: TS.into(),
        resolved_at: Some(TS.into()),
        resolved_by: Some(Actor::Socket {
            client_name: "acp-mac".into(),
        }),
        approve: Some(true),
        feedback: None,
        sha: Some(INTEGRATE_SHA.into()),
        commit: Some(commit_target()),
    };
    let json = serde_json::to_value(&gate).expect("serialize gate");
    assert_eq!(json["gateId"], GATE_ID);
    assert_eq!(json["kind"], "integrate");
    assert_eq!(json["payloadPath"], GATE_PAYLOAD_PATH);
    assert_eq!(json["requestedBy"], "control-plane");
    assert_eq!(json["resolvedBy"], "acp-mac");
    assert_eq!(json["resolvedAt"], TS);
    assert_eq!(json["commit"]["worktree"], WORKTREE);
    let back: Gate = serde_json::from_value(json).expect("deserialize gate");
    assert_eq!(back, gate);
}

/// `MessageRole` is a closed wire enum: `assistant` for the lead's prose and — since the B3
/// walkthrough fix — `user` for the human's follow-up turn. Pinned here so this side and the app's
/// tolerant `MessageRole(rawValue:)` can never drift on the spelling.
#[test]
fn message_roles_serialize_to_their_lowercase_wire_names() {
    for (role, wire) in [
        (MessageRole::Assistant, "assistant"),
        (MessageRole::User, "user"),
    ] {
        let json = serde_json::to_value(role).expect("serialize role");
        assert_eq!(json, json!(wire));
        let back: MessageRole = serde_json::from_value(json).expect("deserialize role");
        assert_eq!(back, role);
    }
    assert!(
        serde_json::from_value::<MessageRole>(json!("system")).is_err(),
        "the enum stays closed: a third speaker is a wire change, not data"
    );
}

/// `SchemaName` is the closed set of result contracts. `free-text` names a lead's result: a
/// conversational turn validated against nothing, which the log must say rather than borrow the
/// builder's `build-result` (the B3 walkthrough's "invalid structured result" label).
#[test]
fn schema_names_serialize_to_their_kebab_case_wire_names() {
    for (name, wire) in [
        (SchemaName::BuildResult, "build-result"),
        (SchemaName::ReviewVerdict, "review-verdict"),
        (SchemaName::VerifyReport, "verify-report"),
        (SchemaName::FreeText, "free-text"),
    ] {
        let json = serde_json::to_value(name).expect("serialize schema name");
        assert_eq!(json, json!(wire));
        let back: SchemaName = serde_json::from_value(json).expect("deserialize schema name");
        assert_eq!(back, name);
    }
}

/// `run.delegated`'s two shapes differ structurally, not just by value: a worker target carries a
/// `role`, a plan container carries `role: null`. `EVENT_FIXTURES`/`payloads()` pin the worker
/// shape (T84's rule: one fixture per kind); this test pins the container shape's exact bytes the
/// same way — hand-written, not generated from the type, so a `target`/`role` mix-up in either
/// direction fails here rather than round-tripping invisibly.
#[test]
fn run_delegated_pins_the_plan_container_shape_too() {
    let payload = EventPayload::RunDelegated {
        delegated_run_id: delegated_run_id(),
        role: None,
        target: DelegatedTarget::Plan,
    };
    let original = event(29, payload);
    let serialized = serde_json::to_value(&original).expect("serialize container run.delegated");
    let fixture = json!({
        "seq": 29, "ts": TS, "runId": RUN_ID,
        "kind": "run.delegated",
        "delegatedRunId": DELEGATED_RUN_ID,
        "role": null,
        "target": "plan"
    });
    assert_eq!(
        serialized, fixture,
        "the plan-container run.delegated shape drifted from its wire fixture"
    );
    let parsed: Event = serde_json::from_value(fixture).expect("deserialize container fixture");
    assert_eq!(parsed, original, "the container fixture deserialized wrong");
}
