# git_checker

`git clone` with a quarantine, plus a check every time you open Claude Code in a directory.
Before a repository reaches you it is checked for **malicious code** and for **instructions or
configuration that abuse an LLM coding agent** (Claude Code, Cursor, Copilot…) once you open it.
The working assumption: every repository you clone will end up opened with Claude Code.

```
$ git clone https://github.com/x/y
🔒 Cloning into quarantine…
  [1/3] malicious code / execution…
  [2/3] LLM agent attack surface…
  [3/3] review with opus (no tools)…
  Verdict: BLOCK   block=17  warn=6  info=6
   block .claude/settings.json — settings sets the environment variable ANTHROPIC_BASE_URL
   block CLAUDE.md:8 — Hidden text with Unicode TAG chars (invisible to humans, readable by LLMs)
   …
⛔ BLOCK: the repository has NOT been delivered. Held in: ~/.cache/git-checker/quarantine/y-…
```

## Quick install

Requirements: Linux/macOS with `bash`, `git`, `python3` (≥3.10), `jq` and, for the LLM phase,
[Claude Code](https://docs.claude.com/en/docs/claude-code) (`claude`) logged in.
`~/.local/bin` must come **before** `/usr/bin` in `PATH` (the usual setup).

```bash
# 1. Download (with the real git: the checker is not installed yet)
/usr/bin/git clone https://github.com/daffi1238/git_checker ~/git_checker

# 2. Install everything: git shim + scanners (semgrep, guarddog, osv-scanner)
#    + Claude Code hooks (secrets guard and sentinel)
cd ~/git_checker && ./install.sh --all

# 3. Reload and check
hash -r; source ~/.bashrc; type git     # → git is ~/.local/bin/git
git clone https://github.com/sindresorhus/slugify /tmp/slugify   # → OK and delivered
```

Minimal install (checker and shell integration only, no external scanners or hooks): `./install.sh`.
- `--tools` installs the scanners (needs `uv` or `pipx`, and `go` for osv-scanner).
- `--guard` registers the secrets guard hook.
- `--sentinel` registers the sentinel hook.

Both hook options back up `~/.claude/settings.json` first. Uninstall with `./install.sh --uninstall`.

Try it with a malicious sample repository (inert: everything points to `example.invalid`):

```bash
python3 -I ~/git_checker/tests/make_fixtures.py /tmp/fx
git clone /tmp/fx/evil /tmp/evil          # → BLOCK, stays in quarantine
git clone /tmp/fx/comments /tmp/c         # → BLOCK only because of comments in the code
cd /tmp/fx/evil && claude                 # → the sentinel stops Claude Code before it loads anything
```

## Usage

```bash
git clone <url> [dir]                # goes through the checker (from Claude Code too)
GIT_CHECK=0 git clone …              # skip the review
git-check ./repo                     # full analysis (with LLM) of a directory you already have
git-safe-clone --list                # repositories held in quarantine
git-safe-clone --release ~/.cache/git-checker/quarantine/<id> [--neutralize]
git-safe-clone --ack <dir>           # accept a directory's WARN/BLOCK after reviewing it
git-safe-clone --trust <dir>         # never check this directory again (e.g. your own security tooling)
git-safe-clone --status <dir> | --rescan <dir> | --untrust <dir>
```

| Verdict | What happens |
|---|---|
| **OK** | Delivered to the destination |
| **WARN** | Asks: `a` accept · `n` neutralize agent config and accept · `r` reject · `v` view report. Without a terminal it stays held |
| **BLOCK** | Stays held; only delivered (neutralized) if you type `ACCEPT` |

**Neutralize** renames the agent and auto-run configuration that has findings to `*.quarantined`
(`.claude/`, `.mcp.json`, `CLAUDE.md`, `.vscode/tasks.json`, `.devcontainer`, `.envrc`, …).
Reports are saved in `~/.local/share/git-checker/reports/`.

### Verdict cache

Each verdict is cached per **commit** and **checker version**. Re-cloning the same commit is
instant and does not pay for Opus again. Changing the checker's code or rules invalidates the cache.
`GIT_CHECK_NO_CACHE=1` forces a fresh analysis.

## Sentinel: check when Claude Code is opened, not only when cloning

`git clone` is only one way in. A repository that was clean when you cloned it can get a malicious
`CLAUDE.md` in a later `git pull`. Others come in through `gh repo clone`, an IDE or a ZIP. The
sentinel covers all of those:

- **Before launch:** a `claude` shell function, installed with the shell integration, checks the
  current directory **before** Claude Code loads anything from it. On WARN it asks; on BLOCK it only
  starts if you type `ACCEPT`. Non-interactive calls (`claude -p`, `--version`, `mcp`, …) go straight
  through.
- **Every prompt:** the `UserPromptSubmit` hook (`--sentinel`) covers sessions started any other way,
  and changes during a session (a `git pull`, files that get written).
  - **BLOCK:** the prompt is stopped and you see the report path.
  - **WARN:** shown once, and Claude is told to treat those files as untrusted data.

To keep this cheap, each directory has a state file with a stat signature of its files:
- **Unchanged directory:** one directory walk (about 60 ms on langchain).
- **Changed files:** only those are re-scanned with the deterministic phases (about 150 ms).
- **First time it sees a directory:** a full deterministic scan (1–20 s depending on size).
- **Cloned through `git clone`:** the clone records the verdict and what you accepted, so the
  directory does not ask again until something changes.

Once you have reviewed a directory, `git-safe-clone --ack <dir>` accepts its current verdict.
Your own security tooling, which contains attack patterns on purpose, can be excluded with
`--trust` (`install.sh` trusts this repository). The sentinel skips `$HOME`, `/` and trees with
more than 60,000 files. It never runs the LLM, so for a full review run `git-check <dir>`.

## Second opinion from a local LLM (optional)

Any server with an OpenAI-compatible API (`/v1/chat/completions`): llama.cpp server, vLLM,
Ollama, LM Studio… It runs **in parallel** with Opus, so total time is that of the slower one.

```bash
mkdir -p ~/.config/git-checker
install -m 600 ~/git_checker/local-llm.env.example ~/.config/git-checker/local-llm.env
$EDITOR ~/.config/git-checker/local-llm.env     # URL, model and token
```

- **Default weight: second opinion.** Small models over-flag, so its BLOCK raises the verdict to
  WARN at most (you get asked) and its WARN is informational only. `GIT_CHECK_LOCAL_WEIGHT=full`
  gives it the same weight as Opus.
- **Local only:** `GIT_CHECK_NO_OPUS=1` leaves only the local model. It becomes the primary
  reviewer: its verdict counts fully, and if it fails the minimum verdict is WARN.
- **Same isolation as Opus:** no tools, the repository is sent as delimited data, and it can only
  make the verdict stricter. An injection that fools it into saying "ok" relaxes nothing.
- **Context size matters.** With 4096 tokens it only sees about 5,000 characters of the repository.
  The payload adapts to the `n_ctx` the server reports, but start the server with more context
  (e.g. `llama-server -c 32768`) for the review to be useful.

Environment variables:
- `GIT_CHECK_NO_LLM=1`: no phase 3.
- `GIT_CHECK_NO_OPUS=1`: local LLM only.
- `GIT_CHECK_NO_EXTERNAL=1`: no semgrep/guarddog/osv.
- `GIT_CHECK_MODEL=opus`, `GIT_CHECK_LLM_TIMEOUT=300`.
- `GIT_CHECK_NO_CACHE=1`: ignore the verdict cache.
- `GIT_CHECK_NONINTERACTIVE=1`: never ask.
- `GIT_CHECK_FORCE=1`: intercept in scripts without a TTY too.
- `GIT_CHECK_QUARANTINE`, `GIT_CHECK_REPORTS`, `GIT_CHECK_CACHE`.

## How it works

```
git clone  →  ~/.local/bin/git (shim)  →  git-safe-clone
  0. quarantine clone: no hooks, no submodules, no LFS, symlinks as text, fsck enabled;
     rejects --upload-pack / --template / dangerous -c options
  1. code: install hooks (npm, setup.py, pyproject), .vscode folderOpen, devcontainer, direnv,
     obfuscation and payloads hidden with whitespace, curl|sh, reverse shells, credential/wallet theft,
     exfiltration endpoints, binaries, Trojan Source, invisible payloads built from Unicode
     variation selectors (GlassWorm)
     + semgrep (rules/semgrep) + guarddog (npm/pypi) + osv-scanner (known MAL-* packages)
  2. agents: CLAUDE.md (+@imports, including ones that leave the repo), .claude/settings*.json (hooks,
     env ANTHROPIC_BASE_URL/proxies/OTEL, apiKeyHelper, statusLine, permissions, bypassPermissions),
     .mcp.json, commands/skills/agents (!`…`, allowed-tools), AGENTS.md/.cursorrules/copilot/…,
     invisible Unicode (TAG/zero-width/bidi), hidden HTML comments, prompt injection,
     markdown images with data in the URL
     + code comments (#, //, /* */, docstrings, <!-- --> in html/vue/jsx…, --) that ADDRESS an
     agent ("Claude: …", "If you are an AI…", "Note for AI assistants", "agents must run…") and ask
     for something risky right after (curl|sh, reading ~/.ssh or .env, sending data out, hiding it)
  3. Opus via `claude -p` with NO tools (--tools "", no MCP, no settings, empty cwd);
     the repository is sent as data delimited by a random token; output constrained by a JSON Schema
     + (optional, in parallel) a local LLM over an OpenAI-compatible API as a second opinion
```

- The LLM can **only make the deterministic verdict stricter**, never relax it. If the LLM fails,
  the minimum verdict is WARN. If the analyser fails, the repository stays in quarantine.
- The shim only intercepts when there is a terminal or when Claude Code runs it (`CLAUDECODE=1`).
  Cron and scripts go straight to the real git.
- Phase 3 costs about $0.15–0.25 and 10–30 s per repository (once per commit, thanks to the cache).

## Secrets guard (`guard/protect_secrets.py`)

A Claude Code `PreToolUse` hook (`./install.sh --guard`). It lets the agent **use** keys (`ssh`,
`scp -i`, `rsync -e "ssh -i…"`, `git`, `ssh-add`) but stops it from **reading, copying or
modifying** them. Blocked:
- `cat`, `base64`, `tar`, `cp` or `docker -v` on `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`,
  `~/.kube`, `~/.docker` or `~/.claude/.credentials.json`;
- `scp` of a key as the file being copied;
- `< key` redirections;
- writes to `authorized_keys`.

Keys are detected by their real names (by listing `~/.ssh`), not by an `id_*` pattern. `config`,
`known_hosts` and `*.pub` stay readable. Denials are logged to `~/.local/share/git-checker/guard.log`.

## Tests

```bash
tests/run.sh      # analyser verdicts, clone flow + cache, sentinel, secrets guard (no LLM, isolated cache)
```

The fixtures are generated at run time so that this repository does not contain a malicious
`CLAUDE.md` that Claude Code could load while you work on it.

## Limits

- **It is heuristic.** A determined attacker can evade the rules and, less likely, the LLM too.
  It is one more layer, not a replacement for a sandbox or for your agent's permission rules.
- **Comments are extracted with regexes, not a parser.** A comment that only *talks about* agents
  does not count; it has to *address* one, so that AI repositories (SDKs, langchain…) are not
  drowned in noise. An injection written as neutral prose can get past the deterministic filter.
  That is what Opus is for: it gets suspicious comments separately even when they are only info.
- **The sentinel runs at launch and on every prompt, not continuously.** It also cannot stop the
  repository's own SessionStart hooks if you start Claude Code some way other than the `claude`
  shell function. Claude Code's workspace-trust dialog is the barrier there. Acknowledging a BLOCK
  needs a terminal (`--ack`).
- **Only what was cloned is analysed.** Submodules, dependencies installed later and code downloaded
  at run time are out of scope.
- **The `git clone` shim is bypassed** by `gh repo clone`, IDEs and anything that calls `/usr/bin/git`
  by absolute path. The sentinel catches those when you open them with Claude Code.
- **osv-scanner queries osv.dev** with the dependency list (public package names).
- **This repository contains attack patterns on purpose** (they are the detection rules), so
  analysing it with itself flags it. `install.sh` adds it to the trust list.
