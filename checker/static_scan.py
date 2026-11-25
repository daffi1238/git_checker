"""Phase 1: classic malware, command execution and exfiltration (deterministic)."""
from __future__ import annotations

import os
import posixpath
import re

from .common import (BIDI_RE, TAG_RE, VS_RUN_RE, ZW_RE, Repo, finding, line_of, load_json_loose,
                     max_sev, snippet_at)

PHASE = "1-codigo"

# Files that run by themselves on install/open/build/test
AUTOEXEC_RE = re.compile(
    r"(^|/)(setup\.py|conftest\.py|build\.rs|\.envrc|Makefile|GNUmakefile|"
    r"package\.json|binding\.gyp|.*\.gemspec|Rakefile|\.pre-commit-config\.yaml|"
    r"\.vscode/tasks\.json|\.vscode/settings\.json|\.devcontainer/.*|\.husky/.*|"
    r"(postcss|tailwind|next|vite|webpack|babel|eslint|jest|vitest|nuxt|svelte|astro)\.config\.[cm]?[jt]s|"
    r"\.eslintrc\.[cm]?js|\.babelrc\.js|\.claude/.*|\.mcp\.json)$", re.I)

CODE_EXT = re.compile(r"\.(py|pyw|js|mjs|cjs|jsx|ts|tsx|sh|bash|zsh|ps1|rb|php|pl|go|rs|java|kt|lua|cs)$", re.I)
NOBLOB_RE = re.compile(r"(\.lock|lock\.json|lock\.yaml|go\.sum|\.svg|\.map|\.min\.[jc]ss?|\.min\.js|"
                       r"\.ipynb|\.pem|\.crt|\.asc|\.snap|\.csv|\.json)$", re.I)

# (id, regex, severity, message)
PATTERNS = [
    ("pipe-to-shell", r"\b(curl|wget|iwr|Invoke-WebRequest)\b[^\n]{0,300}\|\s*(sudo\s+)?(ba|z|da|k)?sh\b", "warn",
     "Download piped straight into a shell (curl|sh)"),
    ("decode-to-shell", r"base64\s+(-d|--decode|-D)\b[^\n]{0,200}\|\s*(ba|z)?sh\b", "block",
     "Base64 payload decoded and run in a shell"),
    ("py-exec-decoded", r"\b(exec|eval)\s*\(\s*(compile\s*\()?\s*(__import__\(['\"](base64|zlib|codecs|marshal)['\"]\)|"
     r"base64\.|zlib\.|codecs\.decode|marshal\.loads|bytes\.fromhex)", "block",
     "exec/eval of decoded content (Python)"),
    ("js-eval-decoded", r"\b(eval|Function)\s*\(\s*[^)]{0,80}(atob\s*\(|Buffer\.from\s*\([^)]{0,200}base64)", "block",
     "eval/Function of decoded content (JS)"),
    ("js-remote-eval", r"\b(eval|new\s+Function)\s*\([^)]{0,120}\b(res|resp|response|r|data)\.(data|body|text)\b", "warn",
     "eval of an HTTP response ('Contagious Interview' pattern)"),
    ("ps-encoded", r"(?i)powershell[^\n]{0,80}\s-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", "block",
     "PowerShell with an encoded command"),
    ("reverse-shell", r"/dev/tcp/|\bbash\s+-i\s*>&|\bnc(at)?\s+(-\w+\s+)*-e\s|\bmkfifo\b[^\n]{0,100}\bnc\b|socat\s+[^\n]*exec:", "block",
     "Reverse shell pattern"),
    ("env-exfil", r"\b(env|printenv|set)\b\s*\|\s*(curl|wget|nc|base64)|"
     r"(os\.environ|process\.env)\b[^\n]{0,80}\b(requests\.post|fetch|axios\.post|urlopen|http\.request)", "block",
     "Environment variables sent over the network"),
    ("miner", r"(?i)\bxmrig\b|stratum\+tcp://|\bcoinhive\b|minexmr", "block", "Cryptocurrency miner"),
    ("sensitive-paths",
     r"(~|\$HOME|os\.homedir\(\)|expanduser\(['\"]~)[^\n]{0,20}/?\.(ssh|aws|gnupg|kube|docker/config|config/gh|npmrc|pypirc|netrc|git-credentials|claude)\b|"
     r"\bid_(rsa|ed25519|ecdsa)\b|\.aws/credentials|/etc/shadow|\.bash_history|wallet\.dat|"
     r"(?i:Login Data|Local State|cookies\.sqlite|key4\.db|logins\.json|Exodus|MetaMask|nkbihfbeogaeaoehlefnkodbefgpgknn)",
     "warn", "Access to user credentials/sensitive data"),
    ("exfil-endpoint",
     r"(?i)discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/services|"
     r"webhook\.site|pipedream\.net|requestbin|\bngrok(-free)?\.(io|app)|trycloudflare\.com|"
     r"pastebin\.com/raw|transfer\.sh|interact\.sh|\boast\.(pro|live|site|online|fun|me)\b|burpcollaborator|"
     r"\b(?!(?:127|10|0)\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)(\d{1,3}\.){3}\d{1,3}:\d{2,5}\b",  # public IP:port
     "warn", "Typical exfiltration / C2 endpoint"),
    ("hidden-offscreen", r"\S[ \t]{150,}\S", "warn",
     "Code pushed off-screen with whitespace (payload-hiding technique)"),
    ("chmod-exec-download", r"(curl|wget)[^\n]{0,200}(-o|-O|>)\s*\S+[^\n]{0,100}&&[^\n]{0,60}chmod\s+\+?[0-7x]+", "warn",
     "Downloads a binary and makes it executable"),
    ("persistence", r"(?i)crontab\s+-|/etc/cron|\.bashrc|\.zshrc|\.profile\b|LaunchAgents|systemctl\s+--user\s+enable|"
     r"CurrentVersion\\\\Run", "info", "Possible persistence mechanism"),
]
COMPILED = [(i, re.compile(rx), s, m) for i, rx, s, m in PATTERNS]
# Only these patterns are raised to BLOCK when they appear in an auto-run file
ESCALATE = {"pipe-to-shell", "exfil-endpoint", "js-remote-eval", "chmod-exec-download", "hidden-offscreen"}
# Documentation (not agent instructions): code patterns there are informational only
DOC_RE = re.compile(r"(\.(md|mdx|rst|txt|adoc|html?|xml|d\.ts)$|(^|/)(CHANGELOG|CHANGES|HISTORY|NEWS)[^/]*$)", re.I)
TESTDOC_DIR_RE = re.compile(r"(^|/)(tests?|testing|spec|docs?|examples?|fixtures?|samples?)/", re.I)
BLOB_RE = re.compile(r"[A-Za-z0-9+/]{400,}={0,2}|(?:\\x[0-9a-fA-F]{2}){100,}|[0-9a-fA-F]{600,}")
BINARY_MAGIC = {b"\x7fELF": "ELF", b"MZ": "PE/Windows", b"\xcf\xfa\xed\xfe": "Mach-O", b"\xca\xfe\xba\xbe": "Mach-O/Java"}
BIN_EXT = re.compile(r"\.(exe|dll|so|dylib|node|jar|bin|scr|msi|pyc|apk|dex)$", re.I)

KNOWN_BACKENDS = {"setuptools.build_meta", "setuptools.build_meta:__legacy__", "poetry.core.masonry.api",
                  "poetry.masonry.api", "hatchling.build", "flit_core.buildapi", "pdm.backend", "pdm.pep517.api",
                  "maturin", "scikit_build_core.build", "mesonpy", "uv_build", "sipbuild.api", "whey"}
NPM_HOOKS = ("preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "prepublish")


def _add(out, counts, f, per_rule_file=3):
    key = (f["rule"], f["file"])
    counts[key] = counts.get(key, 0) + 1
    if counts[key] <= per_rule_file:
        out.append(f)


def scan(repo: Repo) -> list[dict]:
    out: list[dict] = []
    counts: dict = {}

    # ---- symlinks
    for path, target in repo.symlinks.items():
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
        if target.startswith(("/", "~")) or resolved.startswith(".."):
            out.append(finding("block", PHASE, "symlink-escape", path,
                               f"Symlink pointing outside the repository → {target}"))
        else:
            out.append(finding("info", PHASE, "symlink", path, f"Internal symlink → {target}"))

    for rel in repo.files:
        base = os.path.basename(rel)
        autoexec = bool(AUTOEXEC_RE.search(rel))

        # ---- binaries
        head = repo.head_bytes(rel)
        kind = next((k for m, k in BINARY_MAGIC.items() if head.startswith(m)), None)
        if kind or BIN_EXT.search(rel):
            out.append(finding("warn", PHASE, "binary", rel,
                               f"Bundled binary/executable ({kind or 'extension ' + rel.rsplit('.', 1)[-1]})"))

        text = repo.text(rel)
        if text is None:
            if repo.size(rel) > 2_000_000:
                out.append(finding("info", PHASE, "too-big", rel, "File >2MB not analyzed"))
            continue

        # ---- patterns
        is_doc = bool(DOC_RE.search(rel)) and not rel.startswith(".claude/")
        in_testdoc = bool(TESTDOC_DIR_RE.search(rel))
        for rid, rx, sev, msg in COMPILED:
            if rid == "hidden-offscreen" and not (CODE_EXT.search(rel) or autoexec):
                continue
            for m in rx.finditer(text):
                s, extra = sev, ""
                if is_doc:
                    s = "info"
                elif autoexec and rid in ESCALATE:
                    s, extra = "block", " [in an auto-run file]"
                elif in_testdoc and rid in ("sensitive-paths", "exfil-endpoint") and s == "warn":
                    s = "info"
                _add(out, counts, finding(s, PHASE, rid, rel, msg + extra, line_of(text, m.start()),
                                          snippet_at(text, m.start())))

        # ---- obfuscated blobs
        if not NOBLOB_RE.search(rel):
            m = BLOB_RE.search(text)
            if m:
                sev = "warn" if (CODE_EXT.search(rel) or autoexec) else "info"
                _add(out, counts, finding(sev, PHASE, "encoded-blob", rel,
                                          f"Encoded blob of {len(m.group())} characters",
                                          line_of(text, m.start()), m.group()[:120] + "…"))

        # ---- minified/obfuscated outside dist
        if re.search(r"\.[cm]?js$", rel) and not re.search(r"(\.min\.js$|(^|/)(dist|build|vendor|public|static|node_modules)/)", rel):
            longest = max((len(l) for l in text.splitlines()), default=0)
            if longest > 5000:
                out.append(finding("warn" if autoexec else "info", PHASE, "minified-js", rel,
                                   f"Minified/obfuscated JS (line of {longest} chars) outside dist/"))

        # ---- Trojan Source / invisible Unicode in code
        if CODE_EXT.search(rel):
            m = BIDI_RE.search(text)
            if m:
                _add(out, counts, finding("info" if TESTDOC_DIR_RE.search(rel) else "warn", PHASE, "trojan-source", rel,
                                          "Unicode bidi characters in code (Trojan Source)",
                                          line_of(text, m.start()), snippet_at(text, m.start())))
            zw = ZW_RE.findall(text)
            if zw:
                _add(out, counts, finding("info", PHASE, "zero-width-code", rel,
                                          f"Zero-width characters in code ({len(zw)})",
                                          line_of(text, text.find(zw[0])), snippet_at(text, text.find(zw[0]))))
        vs = max(VS_RUN_RE.findall(text), key=len, default="")
        if vs:
            i = text.find(vs)
            _add(out, counts, finding("block" if len(vs) >= 16 else "warn", PHASE, "unicode-variation-payload", rel,
                                      f"Invisible run of {len(vs)} Unicode variation selectors (hidden payload, GlassWorm technique)",
                                      line_of(text, i), snippet_at(text, i)))
        m = TAG_RE.search(text)
        if m:
            _add(out, counts, finding("block", PHASE, "unicode-tags", rel,
                                      "Hidden text using Unicode TAG chars (invisible to humans, readable by LLMs)",
                                      line_of(text, m.start()), snippet_at(text, m.start())))

        # ---- file-specific checks
        if base == "package.json":
            data = load_json_loose(text) or {}
            scripts = data.get("scripts") or {}
            if isinstance(scripts, dict):
                for hook in NPM_HOOKS:
                    if hook in scripts:
                        cmd = str(scripts[hook])
                        sev = "warn"
                        if re.search(r"curl|wget|node\s+-e|eval|base64|\bsh\s+-c|https?://|powershell", cmd):
                            sev = "block"
                        out.append(finding(sev, PHASE, "npm-install-hook", rel,
                                           f"npm script '{hook}' runs on install", None, cmd))
            for k in ("dependencies", "devDependencies", "optionalDependencies"):
                for name, ver in (data.get(k) or {}).items():
                    if isinstance(ver, str) and re.match(r"(https?:|git\+|github:|file:|\.\.?/)", ver):
                        out.append(finding("warn", PHASE, "npm-url-dep", rel,
                                           f"Dependency '{name}' from a URL/path: {ver}"))
        elif base == "setup.py":
            sev = "info"
            if re.search(r"\b(urllib|requests|socket|http\.client|subprocess|os\.system|exec\(|eval\()", text):
                sev = "warn"
            out.append(finding(sev, PHASE, "setup-py", rel,
                               "setup.py runs on install" + (" and uses network/subprocess/exec" if sev == "warn" else "")))
        elif base == "pyproject.toml":
            m = re.search(r'build-backend\s*=\s*["\']([^"\']+)', text)
            if m and m.group(1) not in KNOWN_BACKENDS:
                out.append(finding("warn", PHASE, "py-build-backend", rel,
                                   f"Non-standard build backend: {m.group(1)}"))
            if re.search(r"backend-path\s*=", text):
                out.append(finding("warn", PHASE, "py-backend-path", rel,
                                   "backend-path: the build backend is local code from the repo"))
        elif rel.replace("\\", "/").endswith(".vscode/tasks.json"):
            if re.search(r'"runOn"\s*:\s*"folderOpen"', text):
                out.append(finding("block", PHASE, "vscode-folderopen", rel,
                                   "VS Code task that runs when the folder is opened (runOn: folderOpen)"))
        elif rel.endswith(".vscode/settings.json"):
            for m in re.finditer(r'"([\w.]*(\.path|Path|executable|interpreter\w*|shellArgs[\w.]*|terminal\.integrated\.\w+[\w.]*))"\s*:', text):
                _add(out, counts, finding("warn", PHASE, "vscode-exec-setting", rel,
                                          f"VS Code setting that defines an executable: {m.group(1)}",
                                          line_of(text, m.start()), snippet_at(text, m.start())))
        elif "/.devcontainer/" in "/" + rel or base == ".devcontainer.json":
            for key in ("initializeCommand", "onCreateCommand", "postCreateCommand", "postStartCommand",
                        "postAttachCommand", "updateContentCommand"):
                m = re.search(rf'"{key}"\s*:', text)
                if m:
                    out.append(finding("warn" if key == "initializeCommand" else "info", PHASE, "devcontainer-cmd", rel,
                                       f"devcontainer '{key}'" + (" (runs on the HOST)" if key == "initializeCommand" else ""),
                                       line_of(text, m.start()), snippet_at(text, m.start())))
        elif base == ".envrc":
            out.append(finding("warn", PHASE, "direnv", rel, ".envrc: direnv runs it when you enter the directory"))
        elif base == ".gitmodules":
            for m in re.finditer(r"(?m)^\s*(url|path)\s*=\s*(.+)$", text):
                val = m.group(2).strip()
                if val.startswith("-") or val.startswith("file:") or ".." in val or val.startswith("/"):
                    out.append(finding("block", PHASE, "submodule-evil", rel, f"Suspicious submodule: {val}"))
            out.append(finding("info", PHASE, "submodules", rel,
                               "The repo has submodules (NOT cloned; review them before 'git submodule update')"))
        elif base == ".gitattributes" and re.search(r"\bfilter\s*=", text):
            out.append(finding("info", PHASE, "git-filter", rel, ".gitattributes defines filters (they only act if configured)"))
        elif base in (".semgrepignore", ".guarddogignore"):
            out.append(finding("info", PHASE, "scanner-ignore", rel, f"{base}: tries to exclude files from scanners"))
        elif base == ".yarnrc.yml" and re.search(r"yarnPath\s*:", text):
            out.append(finding("info", PHASE, "yarnpath", rel, "yarnPath: yarn will run a JS file shipped in the repo"))

    return out
