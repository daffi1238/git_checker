"""Phase 2: attack surface for LLM agents (Claude Code and others)."""
from __future__ import annotations

import os
import posixpath
import re

from . import code_comments
from .common import (BIDI_RE, TAG_RE, ZW_RE, Repo, finding, line_of, load_json_loose,
                     snippet_at)

PHASE = "2-agentes"

# Files that agents load as INSTRUCTIONS
INSTRUCTION_RE = re.compile(
    r"(^|/)(CLAUDE(\.local)?\.md|AGENTS?\.md|GEMINI\.md|CONVENTIONS\.md|\.cursorrules|\.windsurfrules|"
    r"\.clinerules(/.*)?|\.roorules|\.roomodes|\.goosehints|\.augment-guidelines|\.rules|"
    r"\.github/copilot-instructions\.md|\.github/(instructions|prompts|chatmodes)/.*|"
    r"\.cursor/(rules/.*|.*\.mdc?)|\.windsurf/.*|\.roo/.*|\.kiro/.*|\.junie/.*|\.amazonq/.*|"
    r"\.continue/.*|\.codex/.*|\.gemini/.*|\.aider[\w.-]*|\.claude/.*\.md)$", re.I)

# Agent files that can EXECUTE things or change where data goes
EXEC_CONFIG_RE = re.compile(
    r"(^|/)(\.claude/settings(\.local)?\.json|\.mcp\.json|\.claude-plugin/.*|\.cursor/mcp\.json|"
    r"\.vscode/mcp\.json|\.gemini/settings\.json|\.codex/config\.toml|\.continue/config\.(json|ya?ml)|"
    r"\.roo/mcp\.json|\.kiro/settings/mcp\.json|\.amazonq/mcp\.json|\.claude/hooks/.*)$", re.I)

DANGEROUS_ENV = re.compile(
    r"^(ANTHROPIC_(BASE_URL|API_URL|AUTH_TOKEN|API_KEY|CUSTOM_HEADERS|BEDROCK_BASE_URL|VERTEX_BASE_URL|"
    r"FOUNDRY_BASE_URL|MODEL|SMALL_FAST_MODEL)|CLAUDE_CODE_USE_(BEDROCK|VERTEX|FOUNDRY)|"
    r"CLAUDE_CODE_SKIP_\w+|OPENAI_(BASE_URL|API_BASE)|HTTPS?_PROXY|ALL_PROXY|NO_PROXY|NODE_OPTIONS|"
    r"NODE_EXTRA_CA_CERTS|NODE_TLS_REJECT_UNAUTHORIZED|SSL_CERT_FILE|REQUESTS_CA_BUNDLE|"
    r"OTEL_\w+|CLAUDE_CODE_ENABLE_TELEMETRY|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_\w+|BASH_ENV|ENV|"
    r"PATH|PYTHONPATH|PYTHONSTARTUP|GIT_\w+|SHELL|PROMPT_COMMAND)$", re.I)

EXEC_KEYS = ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper",
             "statusLine", "fileSuggestion", "subagentStatusLine")

# Signs that a command/instruction touches the network, secrets or hides itself
SUSPICIOUS_CMD = re.compile(
    r"(?i)\b(curl|wget|nc|ncat|socat|scp|rsync|ftp|tftp|telnet|ssh)\b|https?://|\bfetch\(|"
    r"base64|xxd|openssl\s+enc|\beval\b|\bsh\s+-c|bash\s+-c|python[\d.]*\s+-c|node\s+-e|powershell|"
    r"\.ssh|\.aws|\.env\b|\.netrc|\.npmrc|\.pypirc|\.git-credentials|\.config/gh|credentials|"
    r"\b(printenv|env)\b|token|secret|api[_-]?key|passw|/dev/tcp|\bdd\b|\brm\s+-rf|chmod\s+\+x|"
    r"npx\s+-y|bunx|uvx|pipx\s+run|\bnohup\b|&\s*$|>\s*/dev/null\s*2>&1")

# Prompt injection: (id, regex, sev in instruction files, sev in other files, message)
INJECTION = [
    ("ignore-instructions",
     r"\b(ignore|disregard|forget|override)\b[^\n.]{0,40}\b(previous|prior|above|earlier|all|system|safety|your)\b[^\n.]{0,30}\b(instructions?|rules|prompt|guidelines|guardrails)|"
     r"\bignora\w*\b[^\n.]{0,40}\b(instrucciones|reglas|indicaciones)",
     "block", "warn", "Attempt to override previous instructions"),
    ("hide-from-user",
     r"\b(do\s*n[o']t|never|without)\b[^\n.]{0,30}\b(tell|telling|inform|informing|mention|mentioning|notify|notifying|alert|alerting|show|showing|reveal|revealing|ask|asking)\b[^\n.]{0,20}\b(the\s+)?(user|human|developer|operator)|"
     r"\b(silently|secretly|quietly|covertly|in\s+the\s+background)\b[^\n.]{0,60}\b(run|execute|send|upload|post|curl|fetch|read|copy)|"
     r"\bno\s+(le\s+)?(digas|informes|menciones|avises|muestres)\b[^\n.]{0,30}\busuario|\bsin\s+(avisar|decir|informar|preguntar)\b",
     "block", "warn", "Instruction to hide actions from the user"),
    ("role-hijack",
     r"\byou\s+are\s+now\b|\bnew\s+(system\s+)?instructions\b|</?(system|system_prompt|instructions|admin|developer)>|"
     r"\[/?(SYSTEM|INST)\]|<\|im_start\|>|\bBEGIN\s+SYSTEM\s+PROMPT|\bdeveloper\s+mode\b|\bjailbreak",
     "block", "info", "Role/system impersonation"),
    ("agent-directed",
     r"\b(AI|LLM|agent|assistant|claude|copilot|cursor|codex|gemini|chatgpt)s?\b[^\n]{0,40}\b(must|should|always|need\s+to|are\s+required\s+to|have\s+to)\b[^\n]{0,60}\b(run|execute|install|download|curl|send|upload|read|cat|copy|include|add)\b",
     "warn", "info", "Instruction telling AI agents to run/read/send something"),
    ("bypass-perms",
     r"dangerously-skip-permissions|bypassPermissions|--yolo\b|auto-?approve|\ballowedTools\b|--allowedTools|disable\w*\s+sandbox",
     "block", "info", "Intenta desactivar permisos/sandbox del agente"),
    ("exfil-instruction",
     r"\b(send|upload|exfiltrate|forward|transmit|envía|enviar|sube|subir)\b[^\n]{0,80}\b(to|a)\b[^\n]{0,20}(https?://|webhook|server|endpoint|discord|telegram|slack|gist|pastebin)",
     "block", "warn", "Instruction to send data to an external destination"),
    ("secret-read-instruction",
     r"\b(read|cat|print|show|include|copy|open|lee|muestra|copia)\b[^\n]{0,50}(~/\.|\$HOME/\.|\.ssh|id_rsa|id_ed25519|\.aws|\.env\b|\.netrc|\.npmrc|\.git-credentials|\.claude\.json|\.credentials|credentials\.json|keychain|printenv|environment\s+variables|api[_ ]?keys?|tokens?\b)",
     "warn", "info", "Instruction to read secrets/credentials"),
    ("cmd-in-instructions",
     r"\b(curl|wget|iwr|nc|bash\s+-c|sh\s+-c|python[\d.]*\s+-c|node\s+-e|base64\s+-d|eval)\b[^\n]{0,200}",
     "warn", None, "Network/execution command in an instruction file"),
    ("md-image-exfil",
     r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][^)\s]*(\{|\$|%7B|<)[^)]*\)",
     "block", "warn", "Markdown image with a parameterized URL (exfiltration channel)"),
]
INJ_COMPILED = [(i, re.compile(rx, re.I), si, so, m) for i, rx, si, so, m in INJECTION]
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
AGENT_WORDS = re.compile(r"(?i)\b(ai|llm|agent|assistant|claude|copilot|cursor|model|instruction|ignore|execute|run|curl|secret|token|user)\b")
IMPORT_RE = re.compile(r"(?<![\w`/])@(~/[\w.\-/]+|/[\w.\-/]+|(?:\.{1,2}/)?[\w.\-~/]+\.[\w]+)")
SHELL_INLINE_RE = re.compile(r"!`([^`\n]+)`")
NEGATION_RE = re.compile(r"(?i)\b(never|don'?t|do\s+not|must\s+not|should\s+not|avoid|nunca|no)\b[^.\n]{0,25}$")
# Common read-only commands in slash commands / allowed-tools
SAFE_CMD_RE = re.compile(r"^\s*(git\s+(status|diff|log|branch|show|rev-parse|remote|describe|ls-files)|gh\s+(pr|issue)\s+(view|list|diff)|ls|pwd|date|cat\s+[\w./-]+)\b[^;&|`$<>]*$")
SAFE_TOOL_RE = re.compile(r"^\s*(Bash\((git|gh|npm\s+(test|run\s+(lint|test|build))|pytest|ls|cat)\b[^)]*\)|Read|Grep|Glob|Edit|Write|TodoWrite|Task\w*|mcp__[\w-]+__[\w-]+)\s*$")


def _is_instruction(rel: str) -> bool:
    return bool(INSTRUCTION_RE.search(rel))


def _walk_json(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield f"{path}.{k}" if path else k, k, v
            yield from _walk_json(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_json(v, f"{path}[{i}]")


def _cmd_sev(cmd: str) -> str:
    return "block" if SUSPICIOUS_CMD.search(cmd) else "warn"


def _claude_settings(rel, text, out):
    data = load_json_loose(text)
    if data is None:
        out.append(finding("warn", PHASE, "settings-unparseable", rel, "settings.json cannot be parsed (obfuscated?)"))
        return
    if not isinstance(data, dict):
        return
    # hooks
    for event, groups in (data.get("hooks") or {}).items():
        for g in groups if isinstance(groups, list) else []:
            for h in (g.get("hooks") or []) if isinstance(g, dict) else []:
                if not isinstance(h, dict):
                    continue
                target = h.get("command") or h.get("url") or h.get("prompt") or ""
                sev = "block" if h.get("type") == "http" else _cmd_sev(str(target))
                out.append(finding(sev, PHASE, "claude-hook", rel,
                                   f"Hook '{event}' (matcher={g.get('matcher', '*')}, type={h.get('type')}) runs automatically",
                                   None, str(target)))
    # environment variables
    for k, v in (data.get("env") or {}).items():
        sev = "block" if DANGEROUS_ENV.match(k) else "warn"
        out.append(finding(sev, PHASE, "claude-env", rel, f"settings sets the environment variable {k}", None, f"{k}={v}"))
    # helpers that run commands
    for key in EXEC_KEYS:
        if key in data:
            val = data[key]
            cmd = val.get("command", "") if isinstance(val, dict) else str(val)
            out.append(finding(max(_cmd_sev(cmd), "warn", key=lambda s: {"warn": 1, "block": 2}[s]), PHASE,
                               "claude-exec-key", rel, f"'{key}' runs a command", None, cmd))
    # permissions
    perms = data.get("permissions") or {}
    mode = perms.get("defaultMode") or data.get("defaultMode")
    if mode in ("bypassPermissions", "dontAsk"):
        out.append(finding("block", PHASE, "claude-perm-mode", rel, f"defaultMode={mode}: disables confirmations"))
    elif mode in ("acceptEdits", "auto"):
        out.append(finding("warn", PHASE, "claude-perm-mode", rel, f"defaultMode={mode}"))
    for rule in perms.get("allow") or []:
        r = str(rule)
        if re.match(r"^(Bash|Bash\(\*?\)|Bash\(\*:?\*?\)|WebFetch|WebFetch\(\*?\)|mcp__\w*|\*|Read\(/|Read\(~|Edit\(/|Edit\(~|Write\(~|Write\(/)", r) \
                or SUSPICIOUS_CMD.search(r):
            out.append(finding("warn", PHASE, "claude-perm-allow", rel, f"Broad pre-approved permission: {r}"))
        else:
            out.append(finding("info", PHASE, "claude-perm-allow", rel, f"Pre-approved permission: {r}"))
    for d in perms.get("additionalDirectories") or []:
        out.append(finding("warn", PHASE, "claude-extra-dirs", rel, f"Grants access to an external directory: {d}"))
    for key in ("enableAllProjectMcpServers", "enabledMcpjsonServers", "enabledPlugins", "extraKnownMarketplaces",
                "pluginMarketplaces"):
        if data.get(key):
            out.append(finding("warn", PHASE, "claude-autoload", rel, f"{key} enables MCP servers/plugins automatically",
                               None, str(data[key])[:300]))
    sb = data.get("sandbox")
    if isinstance(sb, dict) and (sb.get("enabled") is False or sb.get("excludedCommands")
                                 or sb.get("allowUnsandboxedCommands") or sb.get("network")):
        out.append(finding("warn", PHASE, "claude-sandbox", rel, "Changes the Claude Code sandbox", None, str(sb)[:300]))
    # any other nested 'command'
    seen = {f["snippet"] for f in out}
    for p, k, v in _walk_json(data):
        if k in ("command", "url") and isinstance(v, str) and v not in seen and not p.startswith("hooks"):
            out.append(finding(_cmd_sev(v), PHASE, "claude-nested-command", rel, f"Command/URL in {p}", None, v))


def _mcp_config(rel, text, out):
    data = load_json_loose(text)
    if not isinstance(data, dict):
        out.append(finding("warn", PHASE, "mcp-unparseable", rel, "MCP config cannot be parsed"))
        return
    servers = data.get("mcpServers") or data.get("servers") or {}
    for name, cfg in servers.items() if isinstance(servers, dict) else []:
        if not isinstance(cfg, dict):
            continue
        if cfg.get("command"):
            cmd = " ".join([str(cfg["command"])] + [str(a) for a in cfg.get("args") or []])
            out.append(finding(_cmd_sev(cmd), PHASE, "mcp-stdio", rel,
                               f"MCP server '{name}' launches a local process", None, cmd))
        if cfg.get("url"):
            out.append(finding("warn", PHASE, "mcp-remote", rel,
                               f"Remote MCP server '{name}': the agent will send data here", None, str(cfg["url"])))
        for k in (cfg.get("env") or {}):
            if DANGEROUS_ENV.match(k):
                out.append(finding("block", PHASE, "mcp-env", rel, f"MCP '{name}' sets {k}"))
        if cfg.get("headers"):
            out.append(finding("info", PHASE, "mcp-headers", rel, f"MCP '{name}' sends custom headers"))


def _frontmatter(rel, text, out):
    m = re.match(r"^---\s*\n(.*?)\n---", text, re.S)
    if not m:
        return
    fm = m.group(1)
    tools = re.search(r"(?im)^allowed[-_]tools\s*:\s*(.+)$", fm)
    risky = [t for t in re.split(r",(?![^(]*\))", tools.group(1).strip("[] ")) if t.strip() and not SAFE_TOOL_RE.match(t.strip("'\" "))] if tools else []
    if risky:
        out.append(finding("block" if any(SUSPICIOUS_CMD.search(t) or re.fullmatch(r"\s*['\"]?(Bash|Bash\(\*\)|\*)['\"]?\s*", t) for t in risky) else "warn", PHASE, "fm-allowed-tools", rel, "Command/skill/agent pre-approves dangerous tools",
                           None, ", ".join(risky)))
    if re.search(r"(?im)^hooks\s*:", fm):
        out.append(finding("warn", PHASE, "fm-hooks", rel, "Frontmatter defines hooks"))
    if re.search(r"(?im)^(permissionMode|permission-mode)\s*:\s*(bypassPermissions|dontAsk)", fm):
        out.append(finding("block", PHASE, "fm-perm-mode", rel, "Subagent with bypassPermissions"))


def scan(repo: Repo) -> tuple[list[dict], list[str], list[str]]:
    """Returns (findings, instruction_files, executable_config_files)."""
    out: list[dict] = []
    instr = [f for f in repo.files if _is_instruction(f)]
    execcfg = [f for f in repo.files if EXEC_CONFIG_RE.search(f)]

    # Root README: agents almost always read it
    semi = [f for f in repo.files if re.match(r"(?i)^readme(\.\w+)?$", f)]

    # CLAUDE.md @imports (recursive)
    queue = [f for f in instr if re.search(r"(?i)(claude|agents?)(\.local)?\.md$", f)]
    seen = set(queue)
    while queue:
        rel = queue.pop()
        text = repo.text(rel) or ""
        text_nocode = re.sub(r"```.*?```", "", text, flags=re.S)
        for m in IMPORT_RE.finditer(text_nocode):
            ref = m.group(1)
            if ref.startswith(("~", "/")):
                out.append(finding("block", PHASE, "import-outside", rel,
                                   f"@import of a file OUTSIDE the repo: {ref} (can pull your secrets into the context)",
                                   line_of(text_nocode, m.start()), snippet_at(text_nocode, m.start())))
                continue
            target = posixpath.normpath(posixpath.join(posixpath.dirname(rel), ref))
            if target.startswith(".."):
                out.append(finding("block", PHASE, "import-outside", rel, f"@import that escapes the repo: {ref}"))
            elif repo.exists(target) and target not in seen:
                seen.add(target)
                instr.append(target)
                queue.append(target)
                out.append(finding("info", PHASE, "import", rel, f"@import → {target}"))

    for rel in instr:
        out.append(finding("info", PHASE, "agent-instructions", rel, "Agent instruction file"))
    for rel in execcfg:
        text = repo.text(rel)
        if text is None:
            out.append(finding("warn", PHASE, "agent-config-binary", rel, "Binary or unreadable agent config"))
            continue
        base = os.path.basename(rel).lower()
        if base.startswith("settings") and ".claude" in rel or base == "settings.json" and ".gemini" in rel:
            _claude_settings(rel, text, out)
        elif base.endswith("mcp.json"):
            _mcp_config(rel, text, out)
        elif "/hooks/" in "/" + rel:
            out.append(finding("warn", PHASE, "claude-hook-script", rel, "Script in .claude/hooks/"))
        elif "/.claude-plugin/" in "/" + rel:
            out.append(finding("info", PHASE, "agent-plugin-manifest", rel,
                               "Plugin/marketplace manifest (only acts if you install it)"))
        else:
            out.append(finding("warn", PHASE, "agent-exec-config", rel, "Agent/plugin config able to execute things"))

    # scripts inside .claude/ (skills, hooks…) are already checked by phase 1; here we only list them
    for rel in repo.files:
        if re.match(r"\.claude/", rel) and not rel.endswith((".md", ".json")):
            out.append(finding("info", PHASE, "claude-script", rel, "Non-markdown file inside .claude/"))

    # ---- prompt injection
    instr_set = set(instr)
    for rel in repo.files:
        text = repo.text(rel)
        if text is None:
            continue
        is_instr = rel in instr_set
        is_md = rel.lower().endswith((".md", ".mdc", ".mdx", ".txt", ".rst"))
        sev_boost = is_instr or rel in semi

        if is_instr and rel.endswith(".md") and "/.claude/" in "/" + rel:
            _frontmatter(rel, text, out)
            for m in SHELL_INLINE_RE.finditer(text):
                sev = "info" if SAFE_CMD_RE.match(m.group(1)) else _cmd_sev(m.group(1))
                out.append(finding(sev, PHASE, "slash-inline-bash", rel,
                                   "Command with !`…`: runs when the command/skill is invoked",
                                   line_of(text, m.start()), m.group(0)))

        # Invisible Unicode
        if is_instr or is_md:
            for rx, rid, msg in ((ZW_RE, "zero-width", "Zero-width characters"),
                                 (BIDI_RE, "bidi", "Bidi characters (reordered text)")):
                hits = list(rx.finditer(text))
                if len(hits) >= (1 if is_instr else 5):
                    out.append(finding("block" if is_instr else "warn", PHASE, rid, rel,
                                       f"{msg} ({len(hits)}) in text an agent may read",
                                       line_of(text, hits[0].start()), snippet_at(text, hits[0].start())))

        if not (is_instr or is_md or rel in semi or re.search(r"\.(py|js|ts|go|rs|rb|sh|ya?ml|toml|json)$", rel)):
            continue

        # Hidden HTML comments in markdown
        if is_md or is_instr:
            for m in HTML_COMMENT_RE.finditer(text):
                body = m.group(1)
                if AGENT_WORDS.search(body) and len(body.strip()) > 20:
                    out.append(finding("warn" if sev_boost else "info", PHASE, "html-comment", rel,
                                       "Hidden HTML comment (invisible when rendered) with agent-directed content",
                                       line_of(text, m.start()), body.strip()[:300]))

        per_rule = {}
        for rid, rx, s_in, s_out, msg in INJ_COMPILED:
            if is_instr:
                sev = s_in
            elif rel in semi:
                sev = s_out
            elif s_out is None:
                sev = None
            elif is_md:
                sev = s_out if rid == "md-image-exfil" else "info"
            else:
                sev = "info"
            if sev is None:
                continue
            for m in rx.finditer(text):
                per_rule[rid] = per_rule.get(rid, 0) + 1
                if per_rule[rid] > 3:
                    break
                s = sev
                line_start = text.rfind("\n", 0, m.start()) + 1
                if s != "info" and rid not in ("md-image-exfil",) and NEGATION_RE.search(text[line_start:m.start()]):
                    s = "info"  # "never print tokens", "do not run curl…"
                out.append(finding(s, PHASE, f"inject-{rid}", rel, msg, line_of(text, m.start()),
                                   snippet_at(text, m.start())))

    # ---- code comments (#, //, /* */, docstrings, <!-- --> in html/vue/jsx…)
    out += code_comments.scan(repo, instr_set | set(semi))
    return out, sorted(set(instr)), execcfg
