"""Fase 1: malware clásico, ejecución de comandos y exfiltración (determinista)."""
from __future__ import annotations

import os
import posixpath
import re

from .common import (BIDI_RE, TAG_RE, Repo, finding, line_of, load_json_loose,
                     max_sev, snippet_at)

PHASE = "1-codigo"

# Ficheros que se ejecutan solos al instalar/abrir/compilar/testear
AUTOEXEC_RE = re.compile(
    r"(^|/)(setup\.py|conftest\.py|build\.rs|\.envrc|Makefile|GNUmakefile|"
    r"package\.json|binding\.gyp|.*\.gemspec|Rakefile|\.pre-commit-config\.yaml|"
    r"\.vscode/tasks\.json|\.vscode/settings\.json|\.devcontainer/.*|\.husky/.*|"
    r"(postcss|tailwind|next|vite|webpack|babel|eslint|jest|vitest|nuxt|svelte|astro)\.config\.[cm]?[jt]s|"
    r"\.eslintrc\.[cm]?js|\.babelrc\.js|\.claude/.*|\.mcp\.json)$", re.I)

CODE_EXT = re.compile(r"\.(py|pyw|js|mjs|cjs|jsx|ts|tsx|sh|bash|zsh|ps1|rb|php|pl|go|rs|java|kt|lua|cs)$", re.I)
NOBLOB_RE = re.compile(r"(\.lock|lock\.json|lock\.yaml|go\.sum|\.svg|\.map|\.min\.[jc]ss?|\.min\.js|"
                       r"\.ipynb|\.pem|\.crt|\.asc|\.snap|\.csv|\.json)$", re.I)

# (id, regex, severidad, mensaje)
PATTERNS = [
    ("pipe-to-shell", r"\b(curl|wget|iwr|Invoke-WebRequest)\b[^\n]{0,300}\|\s*(sudo\s+)?(ba|z|da|k)?sh\b", "warn",
     "Descarga y ejecución directa (curl|sh)"),
    ("decode-to-shell", r"base64\s+(-d|--decode|-D)\b[^\n]{0,200}\|\s*(ba|z)?sh\b", "block",
     "Payload base64 decodificado y ejecutado en shell"),
    ("py-exec-decoded", r"\b(exec|eval)\s*\(\s*(compile\s*\()?\s*(__import__\(['\"](base64|zlib|codecs|marshal)['\"]\)|"
     r"base64\.|zlib\.|codecs\.decode|marshal\.loads|bytes\.fromhex)", "block",
     "exec/eval de contenido decodificado (Python)"),
    ("js-eval-decoded", r"\b(eval|Function)\s*\(\s*[^)]{0,80}(atob\s*\(|Buffer\.from\s*\([^)]{0,200}base64)", "block",
     "eval/Function de contenido decodificado (JS)"),
    ("js-remote-eval", r"\b(eval|new\s+Function)\s*\([^)]{0,120}\b(res|resp|response|r|data)\.(data|body|text)\b", "warn",
     "eval de una respuesta HTTP (patrón 'Contagious Interview')"),
    ("ps-encoded", r"(?i)powershell[^\n]{0,80}\s-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", "block",
     "PowerShell con comando codificado"),
    ("reverse-shell", r"/dev/tcp/|\bbash\s+-i\s*>&|\bnc(at)?\s+(-\w+\s+)*-e\s|\bmkfifo\b[^\n]{0,100}\bnc\b|socat\s+[^\n]*exec:", "block",
     "Patrón de reverse shell"),
    ("env-exfil", r"\b(env|printenv|set)\b\s*\|\s*(curl|wget|nc|base64)|"
     r"(os\.environ|process\.env)\b[^\n]{0,80}\b(requests\.post|fetch|axios\.post|urlopen|http\.request)", "block",
     "Variables de entorno enviadas por red"),
    ("miner", r"(?i)\bxmrig\b|stratum\+tcp://|\bcoinhive\b|minexmr", "block", "Minero de criptomonedas"),
    ("sensitive-paths",
     r"(~|\$HOME|os\.homedir\(\)|expanduser\(['\"]~)[^\n]{0,20}/?\.(ssh|aws|gnupg|kube|docker/config|config/gh|npmrc|pypirc|netrc|git-credentials|claude)\b|"
     r"\bid_(rsa|ed25519|ecdsa)\b|\.aws/credentials|/etc/shadow|\.bash_history|wallet\.dat|"
     r"(?i:Login Data|Local State|cookies\.sqlite|key4\.db|logins\.json|Exodus|MetaMask|nkbihfbeogaeaoehlefnkodbefgpgknn)",
     "warn", "Acceso a credenciales/datos sensibles del usuario"),
    ("exfil-endpoint",
     r"(?i)discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/services|"
     r"webhook\.site|pipedream\.net|requestbin|\bngrok(-free)?\.(io|app)|trycloudflare\.com|"
     r"pastebin\.com/raw|transfer\.sh|interact\.sh|\boast\.(pro|live|site|online|fun|me)\b|burpcollaborator|"
     r"\b(\d{1,3}\.){3}\d{1,3}:\d{2,5}\b",
     "warn", "Endpoint típico de exfiltración / C2"),
    ("hidden-offscreen", r"\S[ \t]{150,}\S", "warn",
     "Código desplazado fuera de pantalla con espacios (técnica para esconder payloads)"),
    ("chmod-exec-download", r"(curl|wget)[^\n]{0,200}(-o|-O|>)\s*\S+[^\n]{0,100}&&[^\n]{0,60}chmod\s+\+?[0-7x]+", "warn",
     "Descarga un binario y le da permisos de ejecución"),
    ("persistence", r"(?i)crontab\s+-|/etc/cron|\.bashrc|\.zshrc|\.profile\b|LaunchAgents|systemctl\s+--user\s+enable|"
     r"CurrentVersion\\\\Run", "info", "Posible mecanismo de persistencia"),
]
COMPILED = [(i, re.compile(rx), s, m) for i, rx, s, m in PATTERNS]
# Solo estos patrones suben a BLOCK cuando aparecen en un fichero de auto-ejecución
ESCALATE = {"pipe-to-shell", "exfil-endpoint", "js-remote-eval", "chmod-exec-download", "hidden-offscreen"}
# Documentación (no instrucciones de agente): los patrones de código ahí son solo informativos
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
                               f"Symlink que apunta fuera del repositorio → {target}"))
        else:
            out.append(finding("info", PHASE, "symlink", path, f"Symlink interno → {target}"))

    for rel in repo.files:
        base = os.path.basename(rel)
        autoexec = bool(AUTOEXEC_RE.search(rel))

        # ---- binarios
        head = repo.head_bytes(rel)
        kind = next((k for m, k in BINARY_MAGIC.items() if head.startswith(m)), None)
        if kind or BIN_EXT.search(rel):
            out.append(finding("warn", PHASE, "binary", rel,
                               f"Binario/ejecutable incluido ({kind or 'extensión ' + rel.rsplit('.', 1)[-1]})"))

        text = repo.text(rel)
        if text is None:
            if repo.size(rel) > 2_000_000:
                out.append(finding("info", PHASE, "too-big", rel, "Fichero >2MB no analizado"))
            continue

        # ---- patrones
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
                    s, extra = "block", " [en fichero de auto-ejecución]"
                elif in_testdoc and rid in ("sensitive-paths", "exfil-endpoint") and s == "warn":
                    s = "info"
                _add(out, counts, finding(s, PHASE, rid, rel, msg + extra, line_of(text, m.start()),
                                          snippet_at(text, m.start())))

        # ---- blobs ofuscados
        if not NOBLOB_RE.search(rel):
            m = BLOB_RE.search(text)
            if m:
                sev = "warn" if (CODE_EXT.search(rel) or autoexec) else "info"
                _add(out, counts, finding(sev, PHASE, "encoded-blob", rel,
                                          f"Blob codificado de {len(m.group())} caracteres",
                                          line_of(text, m.start()), m.group()[:120] + "…"))

        # ---- minificado/ofuscado fuera de dist
        if re.search(r"\.[cm]?js$", rel) and not re.search(r"(\.min\.js$|(^|/)(dist|build|vendor|public|static|node_modules)/)", rel):
            longest = max((len(l) for l in text.splitlines()), default=0)
            if longest > 5000:
                out.append(finding("warn" if autoexec else "info", PHASE, "minified-js", rel,
                                   f"JS minificado/ofuscado (línea de {longest} chars) fuera de dist/"))

        # ---- Trojan Source / Unicode invisible en código
        if CODE_EXT.search(rel):
            m = BIDI_RE.search(text)
            if m:
                _add(out, counts, finding("info" if TESTDOC_DIR_RE.search(rel) else "warn", PHASE, "trojan-source", rel,
                                          "Caracteres bidi Unicode en código (Trojan Source)",
                                          line_of(text, m.start()), snippet_at(text, m.start())))
        m = TAG_RE.search(text)
        if m:
            _add(out, counts, finding("block", PHASE, "unicode-tags", rel,
                                      "Texto oculto con Unicode TAG chars (invisible para humanos, legible para LLMs)",
                                      line_of(text, m.start()), snippet_at(text, m.start())))

        # ---- específicos por fichero
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
                                           f"Script npm '{hook}' se ejecuta al instalar", None, cmd))
            for k in ("dependencies", "devDependencies", "optionalDependencies"):
                for name, ver in (data.get(k) or {}).items():
                    if isinstance(ver, str) and re.match(r"(https?:|git\+|github:|file:|\.\.?/)", ver):
                        out.append(finding("warn", PHASE, "npm-url-dep", rel,
                                           f"Dependencia '{name}' desde URL/ruta: {ver}"))
        elif base == "setup.py":
            sev = "info"
            if re.search(r"\b(urllib|requests|socket|http\.client|subprocess|os\.system|exec\(|eval\()", text):
                sev = "warn"
            out.append(finding(sev, PHASE, "setup-py", rel,
                               "setup.py se ejecuta al instalar" + (" y usa red/subprocess/exec" if sev == "warn" else "")))
        elif base == "pyproject.toml":
            m = re.search(r'build-backend\s*=\s*["\']([^"\']+)', text)
            if m and m.group(1) not in KNOWN_BACKENDS:
                out.append(finding("warn", PHASE, "py-build-backend", rel,
                                   f"Build backend no estándar: {m.group(1)}"))
            if re.search(r"backend-path\s*=", text):
                out.append(finding("warn", PHASE, "py-backend-path", rel,
                                   "backend-path: el backend de build es código local del repo"))
        elif rel.replace("\\", "/").endswith(".vscode/tasks.json"):
            if re.search(r'"runOn"\s*:\s*"folderOpen"', text):
                out.append(finding("block", PHASE, "vscode-folderopen", rel,
                                   "Tarea VS Code que se ejecuta al abrir la carpeta (runOn: folderOpen)"))
        elif rel.endswith(".vscode/settings.json"):
            for m in re.finditer(r'"([\w.]*(\.path|Path|executable|interpreter\w*|shellArgs[\w.]*|terminal\.integrated\.\w+[\w.]*))"\s*:', text):
                _add(out, counts, finding("warn", PHASE, "vscode-exec-setting", rel,
                                          f"Ajuste de VS Code que define un ejecutable: {m.group(1)}",
                                          line_of(text, m.start()), snippet_at(text, m.start())))
        elif "/.devcontainer/" in "/" + rel or base == ".devcontainer.json":
            for key in ("initializeCommand", "onCreateCommand", "postCreateCommand", "postStartCommand",
                        "postAttachCommand", "updateContentCommand"):
                m = re.search(rf'"{key}"\s*:', text)
                if m:
                    out.append(finding("warn" if key == "initializeCommand" else "info", PHASE, "devcontainer-cmd", rel,
                                       f"devcontainer '{key}'" + (" (se ejecuta en el HOST)" if key == "initializeCommand" else ""),
                                       line_of(text, m.start()), snippet_at(text, m.start())))
        elif base == ".envrc":
            out.append(finding("warn", PHASE, "direnv", rel, ".envrc: direnv lo ejecuta al entrar en el directorio"))
        elif base == ".gitmodules":
            for m in re.finditer(r"(?m)^\s*(url|path)\s*=\s*(.+)$", text):
                val = m.group(2).strip()
                if val.startswith("-") or val.startswith("file:") or ".." in val or val.startswith("/"):
                    out.append(finding("block", PHASE, "submodule-evil", rel, f"Submódulo sospechoso: {val}"))
            out.append(finding("info", PHASE, "submodules", rel,
                               "El repo tiene submódulos (NO se han clonado; revísalos antes de 'git submodule update')"))
        elif base == ".gitattributes" and re.search(r"\bfilter\s*=", text):
            out.append(finding("info", PHASE, "git-filter", rel, ".gitattributes define filtros (solo actúan si se configuran)"))
        elif base in (".semgrepignore", ".guarddogignore"):
            out.append(finding("info", PHASE, "scanner-ignore", rel, f"{base}: intenta excluir ficheros de escáneres"))
        elif base == ".yarnrc.yml" and re.search(r"yarnPath\s*:", text):
            out.append(finding("info", PHASE, "yarnpath", rel, "yarnPath: yarn ejecutará un JS incluido en el repo"))

    return out
