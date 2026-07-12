# Founders Sprint — Build → Validate → Secure Agent Prompt

A drop-in system prompt / project-instructions file that runs any AI coding
agent through three mandatory phases on **every** task:

1. **BUILD** — implement the feature, matching existing codebase conventions.
2. **VALIDATE** — write tests (happy path + edge + failure), run the full suite
   and the linter/type-checker, report results plainly.
3. **SECURE** — review the diff against a security checklist (injection,
   broken object-level authorization, secrets, dependency typosquatting, data
   exposure, cookie flags, rate limiting) before the task is considered done.

The agent is not allowed to treat a task as "done" until all three phases pass,
and it won't let phrasing like *"just make it work"* or *"no time to test"* skip
a phase — it flags the trade-off instead.

## Usage

Pick the file that matches your agent and place it at the root of your project:

| Agent / tool | File to use |
| --- | --- |
| Claude Code | [`CLAUDE.md`](CLAUDE.md) |
| Cursor | [`.cursorrules`](.cursorrules) |
| Generic system message / other agents | [`system-prompt.md`](system-prompt.md) |

All three files contain the same instructions — copy whichever fits your setup,
or paste the contents directly into a system message.

## Why

Most "vibe-coded" features fail in one of two ways: they ship without proof they
work, or they ship with a security hole (very often broken access control — user
A editing user B's record by changing an ID). This prompt makes verification and
a security pass non-optional parts of finishing a task, not afterthoughts.

## Output contract

Every task ends with a structured summary rather than prose:

```
BUILD:    <one line, what changed>
VALIDATE: <tests added/run, pass/fail summary>
SECURE:   <checklist items that applied, and their status>
```

Security-critical logic (auth, permissions, payments) is never silently patched:
the agent flags the issue and proposed fix for human review first.
