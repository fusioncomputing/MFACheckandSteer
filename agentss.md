# MFA Check & Steer — Agent Notes

These notes capture the current repo status, the practical limitations of running the Codex agent on Windows, and the mitigations and standing tasks the agent should keep in mind.

## Environment Snapshot
- Host OS: Windows (PowerShell is the default shell exposed to the agent).
- Repository: `MFACheckandSteer` (currently empty).
- Harness: Codex CLI with GPT-5 model (`approval_policy=never`, `danger-full-access`, network enabled).
- File system: NTFS semantics (case-insensitive by default, CRLF newlines common).

## Windows-Centric Constraints & Mitigations
- **Shell differences** — Bash-centric commands (`ls`, `touch`, pipelines relying on GNU tools) may be missing or behave differently. *Mitigation:* Prefer PowerShell-native commands (`Get-ChildItem`, `New-Item`) or bundled cross-platform tools (`rg`, `python`, `node`). When Bash syntax is unavoidable, explicitly invoke it via an installed compatibility layer (check before assuming availability).
- **Path handling** — Windows uses backslashes and has legacy `MAX_PATH` issues. *Mitigation:* Wrap paths in double quotes inside PowerShell, favor shorter relative paths, and avoid extremely deep directory trees unless long-path support is confirmed.
- **Line endings** — Default editors produce CRLF, which can create noisy diffs or tool friction. *Mitigation:* Configure `.gitattributes` early (e.g., `* text eol=lf` for code) and verify editors respect the policy.
- **Executable bits & scripts** — Windows ignores Unix executable permissions; shebang lines may not work. *Mitigation:* Provide explicit interpreter invocations in documentation/scripts (`pwsh script.ps1`, `python script.py`) and add PowerShell equivalents for critical developer tooling.
- **Case sensitivity** — Paths are case-insensitive, so modules/files that differ only by case cannot co-exist. *Mitigation:* Enforce kebab-case or snake_case naming conventions and run case-collision checks when bringing in third-party assets.
- **Symlink limitations** — Creating symlinks often requires Developer Mode or admin privilege. *Mitigation:* Prefer copy-based workflows or document the requirement explicitly if symlinks become necessary.
- **Environment variables** — PowerShell uses `$env:VAR`, while Bash scripts expect `$VAR`. *Mitigation:* Keep config in `.env` files that tooling can parse cross-platform, and document shell-specific export syntax when needed.

## Standing Operating Procedure
- Always set the `workdir` when invoking shell commands; avoid `cd` side effects.
- Favor idempotent PowerShell commands when scaffolding files/directories.
- Double-check third-party tool availability before relying on it; if missing, propose minimal installation steps or alternatives that ship with the repo.
- Document any manual prerequisites for Windows developers as you introduce them (e.g., installing Python, enabling WSL).
- Keep outputs concise; summarize command results instead of dumping entire logs unless the user explicitly requests the full output.

## Near-Term Tasks for the Agent
1. Draft project scaffolding proposals (language/runtime, directory layout) so the user can confirm a direction before implementation.
2. Prepare a `.gitattributes` recommendation to manage newline normalization and binary detection.
3. Outline automation/tooling needs (testing commands, linting, CI approach) with Windows compatibility in mind.
4. Create contribution guidelines that highlight Windows-friendly workflows (PowerShell command snippets, avoiding unsupported POSIX tooling).
5. Once requirements are clear, scaffold the initial application structure and include scripts that run identically on Windows and other platforms.

Keep this document updated as platform assumptions change or new constraints emerge.
