# Working on this tool

- Recommend Python3.12; preserve Python>=3.9 compatibility and fixed dependencies.
- Keep target-project inspection offline. Do not execute its scripts/plugins or launch Unity.
- Preserve Context/FD, scope, protection, fingerprint, budget, and cooperative-lock boundaries.
- Test behavior and failure/recovery paths when changing runtime code. Fixtures containing invalid data or simulated secrets are intentional test inputs.
- Skill sources are under skill/. Local deployment is separate and must preserve unknown edits.
- Do not run the large synthetic validation drivers unless their scope and resource cost are intended. See docs/TESTING.md.
- Git commits, pushes, releases, and external writes require the current task's authorization.
