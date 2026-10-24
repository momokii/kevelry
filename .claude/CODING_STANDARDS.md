# Coding Standards

Stack-agnostic by design. This file is imported into every session, so keep it short.
When the stack is confirmed, replace general guidance with concrete conventions and cite
representative file paths.

## Principles

- **Clarity over cleverness.** Code is read far more often than it is written.
- **One responsibility** per function, file, and module. If describing it needs "and",
  split it.
- **Explicit over implicit.** Avoid hidden side effects, magic values, and action at a
  distance.
- **Fail fast and loudly.** Validate assumptions at the boundary and raise a clear error
  instead of continuing in an unknown state.
- **Smallest change that solves the problem.** No opportunistic refactors in a feature
  or bug-fix change.

## Naming

- Follow the ecosystem's idiom once it is known (for example `snake_case` vs
  `camelCase`); record the choice in `state/DECISIONS_LOG.md` if it is not obvious.
- Functions are descriptive verb-noun: `calculate_total`, `send_invite`, `parse_config`.
- Constants use `UPPER_SNAKE_CASE`.
- Booleans read as predicates: `is_active`, `has_access`, `should_retry`, `can_edit`.
- Avoid abbreviations except well-known domain terms; spell names out.

## Error Handling

- Never swallow an error. Catch only what you can handle, and let the rest propagate.
- Log with enough context to reproduce the problem: operation, identifiers, and cause.
- Never log secrets, tokens, passwords, full request bodies, or personal data.
- Never expose internals or stack traces to end users; return a generic message and keep
  details server-side.
- Distinguish expected failures (validation, not found) from unexpected ones (bugs,
  outages); they need different responses and alerts.

## Testing

- Every feature has tests. Every bug fix has a regression test that fails before the fix
  and passes after it.
- Tests run with a single documented command.
- Security-relevant behavior has negative tests: unauthenticated, wrong role, malformed
  input, oversized input.
- Tests are isolated and deterministic; no dependency on shared external state unless the
  test is explicitly an integration test.
- Assertions are specific: assert the value and the failure mode, not just "no error".

## Quality Tooling

- Configure a formatter, a linter, and a type checker (where the language supports it)
  during project setup, before feature work.
- Run all three before declaring a task done. Fix findings; do not suppress them.
- Never disable a rule inline without a comment explaining why and a tracked issue.

## Documentation

- Public functions and modules document their contract: inputs, outputs, errors, and
  side effects.
- Non-obvious decisions get a short *why* comment, not a *what* comment.
- Update `.env.example` and relevant docs in the same change that adds configuration.
- Keep documentation next to the code it describes; link rather than duplicate.

## Version Control

- Small, focused commits with clear messages: what changed and why.
- One logical change per commit; no unrelated formatting or refactoring mixed in.
- Never commit secrets, generated files, or local configuration.
- Do not commit or push unless the user asks. Never use `--no-verify`. Never force-push.

> **Self-update:** when the stack is confirmed, replace this file with concrete language
> and framework conventions, linter configuration references, and patterns observed in
> the actual code, citing representative file paths.
