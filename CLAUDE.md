# CLAUDE.md

This repository's canonical agent-instruction file is
**[AGENTS.md](./AGENTS.md)** at the workspace root.

Claude Code reads `CLAUDE.md` by default, so this file simply points at
`AGENTS.md` to keep a single source of truth. Everything that used to
live here -- project overview, development commands, module structure,
testing strategy -- is now in `AGENTS.md`, along with the rules every
contributing agent must follow (running the full clippy / fmt / docs
matrix locally, updating `crates/aptos-sdk/CHANGELOG.md` for any
user-visible change, pinning BCS wire-format tests when touching
authenticators, etc.).

If you are editing this repository as an automated agent, **read
`AGENTS.md` before making any change**, regardless of which assistant
launched you.
