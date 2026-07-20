---
description: Codex engineering prompt with YAMS-first distributed memory
argument-hint: "[TASK=<description>] [PHASE=<start|checkpoint|complete>]"
---

# Codex engineering workflow

This prompt defines the reusable operating loop for Codex-style work in Glove.
Repository-specific security, C++ conventions, and gates remain in
[`AGENTS.md`](../../AGENTS.md).

## Priorities

- Use YAMS as durable task memory for decisions, evidence, and handoffs.
- Prefer small, reversible changes with explicit security boundaries.
- Retrieve before broad exploration; hydrate saved artifacts before relying on
  them.
- Verify the narrowest relevant behavior before running broader gates.
- Index concise context before a handoff or approved push.

Agent identity: `codex-<task-slug>`, using lowercase ASCII and dashes.

## Retrieval contract

YAMS search results identify candidates; they are not the full saved artifact.
Hydrate selected notes, decisions, research, or evidence before using them.

| Question | First operation |
|---|---|
| Exact symbol, string, or pattern | `yams grep "<pattern>" --cwd .` |
| Callers, dependencies, or related tests | `yams graph --explore "<symbol-or-file>" --max-files 8` |
| Prior decision, task, or concept | `yams search "<query>" --limit 10` |
| Selected saved artifact | run the emitted `yams cat --hash <hash>` command |
| Repository entry point | `yams graph --topology-clusters`, then inspect one cluster |
| Exact detail in a selected file | read the local file |

Rules:

- Hydrate the most relevant one to three saved-memory hits; do not claim
  recovered context from result snippets alone.
- Use graph exploration to narrow code context before opening many files.
- Treat graph edges as navigation evidence and verify important claims in code
  or tests.
- Local discovery is appropriate when the user supplied an exact path, YAMS
  identified the file, the file changed in the current turn, or YAMS is
  unavailable or insufficient. State the exception.

## Execution loop

1. **Retrieve.** Check YAMS for relevant decisions and code relationships, then
   hydrate selected artifacts.
2. **Claim.** Record the task, scope, goal, and next action when durable
   coordination is useful.
3. **Design.** Identify the observable behavior, security boundary, and
   smallest testable seam.
4. **Test.** Add or identify a failing behavior test before changing production
   behavior. Characterize existing behavior before a refactor.
5. **Implement.** Make the minimum change required for the behavior and keep
   failure paths explicit.
6. **Refactor.** Improve structure only while focused tests remain green.
7. **Verify.** Run formatting, focused builds/tests, and the broader repository
   gate required by `AGENTS.md`.
8. **Checkpoint.** Index changed files and a short note containing decisions,
   open questions, risks, and the next action.
9. **Complete.** Store the handoff, re-index changed files with complete
   metadata, and report the exact verification performed.

## YAMS records

Use metadata on every durable task record:

- required: `task`, `phase=start|checkpoint|complete`, `owner=codex`, and
  `source=code|note|decision|research|evidence`;
- recommended: `agent_id`, `status=open|blocked|done`, and `trace_id`.

Example task claim:

```sh
yams status
yams add - --name "claim-<task>.md" \
  --metadata "task=<task>,phase=start,owner=codex,source=note,agent_id=codex-<task>"
```

Send a concise `TASK`, `SCOPE`, `GOAL`, and `NEXT` record on standard input.
Index the repository recursively only when the index is absent or stale; do not
retag a healthy repository for one task.

## Session recovery

```sh
yams list --format json --show-metadata \
  --metadata "owner=codex" --metadata "task=<task>" \
  --metadata "source=note" --limit 10
yams cat --hash <selected-hash>
```

Recovery is incomplete until the selected artifacts are hydrated. Record their
hashes in the handoff so another session can reproduce the context.

## Ask-first actions

Ask before pushing, deleting files, installing dependencies, publishing
artifacts, or running destructive verification. A commit does not authorize a
push or a public release.

## Handoff

```text
TASK: <task> | PHASE: <phase> | AGENT: codex-<task>
CONTEXT: <hydrated YAMS hashes or explicit retrieval exception>
ACTIONS: <changed behavior and files>
VERIFIED: <commands and results>
INDEXED: <artifacts and metadata, or reason indexing was skipped>
RISKS: <remaining security or correctness risks>
NEXT: <next concrete action>
```
