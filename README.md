# claude-setup

My portable Claude Code setup: one clone and one command sets up a new machine the same way.

## What's in it

| Path | What it is |
|---|---|
| `claude/CLAUDE.md` | Global rules, work-safe (no personal identities or repo rules). Installed to `~/.claude/CLAUDE.md` |
| `claude/plugins.txt` | The 9 plugins: LSPs (Python, TypeScript), security-guidance, context7, playwright, review and quality agents |
| `setup.ps1` | Installs everything; safe to re-run; `-DryRun` shows the plan first |
| `tools/scan_skill.py` | Layer-1 skill sanitization and prompt-injection scanner. Exit `0` pass, `2` review, `1` block |
| `tests/test_scanner.py` | 11 tests; attack fixtures are generated at runtime, never committed |
| `reports/` | *Claude Coding Field Manual* and *Skill Authoring Playbook* as standalone HTML. Open them in a browser |

## New machine

```powershell
git clone https://github.com/ofra123/claude-setup.git
cd claude-setup
powershell -ExecutionPolicy Bypass -File .\setup.ps1 -DryRun   # review the plan
powershell -ExecutionPolicy Bypass -File .\setup.ps1           # install
```

Prerequisites: Claude Code, Node.js (npm), Git and Python 3. Restart Claude Code afterwards.

On my **personal PC**, run with `-SkipClaudeMd`, because that machine's CLAUDE.md also has my personal GitHub identity and repo rules.

## On a company-managed laptop

- **Check policy first.** Confirm that cloning a personal repo and installing plugins is allowed. If it isn't, copy `claude/CLAUDE.md` in by hand. It's plain text with no personal data.
- **Managed settings win.** Company Claude Code policy can block plugins or marketplaces. `setup.ps1` reports each blocked plugin as `[FAIL]` instead of failing silently.
- **npm behind a proxy.** If the language servers fail to install, configure the company npm registry first (`npm config set registry ...`).
- **Security review model.** Change it with `-SecurityReviewModel <model-id>` if the company uses a different provider (for example a Bedrock or Vertex model ID).
- **Artifacts.** The published report links live on my personal claude.ai account. Use the HTML copies in `reports/` instead.

## Using the scanner in a skills registry

```bash
python tools/scan_skill.py path/to/skill --allow-domain yourcompany.com
```

Layer 1 only: it catches invisible Unicode, hidden HTML, encoded payloads, fetch-and-run, binaries and override phrases. Pair it with adversarial LLM review, human review, least-privilege `allowed-tools`, and signed, pinned releases. See `reports/skill-authoring-playbook.html`.
