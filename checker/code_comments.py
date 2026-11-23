"""Prompt injection escondida en COMENTARIOS de código (fase 2).

Un agente que trabaja en el repo lee los ficheros enteros, comentarios incluidos. Aquí se extraen
comentarios (#, //, /* */, docstrings, <!-- -->, --) y se marcan los que van DIRIGIDOS a un agente
y además piden una acción de riesgo (ejecutar, leer secretos, enviar datos fuera).

Es una extracción aproximada por regex (no un parser): prefiere ver de más a ver de menos; el
veredicto lo endurecen solo las combinaciones agente+acción+riesgo, el resto queda en info.
"""
from __future__ import annotations

import re

from .common import ZW_RE, finding, line_of

PHASE = "2-agentes"

HASH_EXT = r"py|pyw|pyi|sh|bash|zsh|fish|rb|pl|pm|r|ya?ml|toml|cfg|ini|conf|ps1|psm1|tf|hcl|nix|cmake|mk|dockerfile|containerfile|gemspec|podspec"
SLASH_EXT = r"[cm]?js|jsx|ts|tsx|mts|cts|go|rs|java|kt|kts|scala|swift|c|h|cc|cpp|hpp|cxx|cs|php|dart|groovy|gradle|zig|v|sol|proto|jsonc|json5|css|scss|less"
HTML_EXT = r"html?|xhtml|vue|svelte|astro|xml|svg|jsx|tsx|php|erb|ejs|hbs|handlebars|njk|jinja2?|j2|twig|liquid|cshtml|razor|md|mdx"
DASH_EXT = r"sql|lua|hs|elm|ada|adb|ads"

HASH_FILE = re.compile(rf"(\.({HASH_EXT})$|(^|/)(Makefile|GNUmakefile|Dockerfile|Containerfile|Gemfile|Rakefile|Vagrantfile|Justfile|justfile|BUILD|WORKSPACE|\.env\w*|\.\w*rc|\.gitattributes|\.gitignore|\.editorconfig|requirements[\w.-]*\.txt|Pipfile|Procfile)$)", re.I)
SLASH_FILE = re.compile(rf"\.({SLASH_EXT})$", re.I)
HTML_FILE = re.compile(rf"\.({HTML_EXT})$", re.I)
DASH_FILE = re.compile(rf"\.({DASH_EXT})$", re.I)
PY_FILE = re.compile(r"\.pyw?$|\.pyi$", re.I)

# Comentarios de línea. El lookbehind evita URLs (https://), shebangs (#!) y '#' dentro de palabras/colores.
HASH_LINE = re.compile(r"(?m)(?:^|(?<=[\s;]))#(?![!{\[])([^\n]*)")
SLASH_LINE = re.compile(r"(?m)(?<![:\"'\w\\/])//([^\n]*)")
DASH_LINE = re.compile(r"(?m)(?:^|(?<=\s))--(?!\[)([^\n]*)")
C_BLOCK = re.compile(r"/\*(.*?)\*/", re.S)
LUA_BLOCK = re.compile(r"--\[(=*)\[(.*?)\]\1\]", re.S)
HTML_BLOCK = re.compile(r"<!--(.*?)-->", re.S)
PY_DOC = re.compile(r"(\"\"\"|''')(.*?)\1", re.S)


def _line_blocks(rx, text, group=1):
    """Agrupa comentarios de línea consecutivos en un solo bloque (instrucciones repartidas en varias líneas)."""
    blocks, cur, cur_start, last_line = [], [], 0, -2
    for m in rx.finditer(text):
        ln = text.count("\n", 0, m.start())
        if ln != last_line + 1 and cur:
            blocks.append((cur_start, "\n".join(cur)))
            cur = []
        if not cur:
            cur_start = m.start()
        cur.append(m.group(group))
        last_line = ln
    if cur:
        blocks.append((cur_start, "\n".join(cur)))
    return blocks


def extract(rel: str, text: str) -> list[tuple[int, str]]:
    """[(offset, cuerpo_del_comentario)] para los lenguajes que reconoce."""
    out: list[tuple[int, str]] = []
    if HASH_FILE.search(rel):
        out += _line_blocks(HASH_LINE, text)
    if SLASH_FILE.search(rel):
        out += _line_blocks(SLASH_LINE, text)
        out += [(m.start(), m.group(1)) for m in C_BLOCK.finditer(text)]
    if DASH_FILE.search(rel):
        out += [(m.start(), m.group(2)) for m in LUA_BLOCK.finditer(text)]
        out += _line_blocks(DASH_LINE, text)
    if PY_FILE.search(rel):
        out += [(m.start(), m.group(2)) for m in PY_DOC.finditer(text)]
    if HTML_FILE.search(rel) and not rel.lower().endswith((".md", ".mdx")):  # md ya lo cubre agent_surface
        out += [(m.start(), m.group(1)) for m in HTML_BLOCK.finditer(text)]
    return out


# ¿A quién va dirigido? (excluye "user agent", "ssh-agent", "gpg-agent"…)
_T = (r"(?<![\w-])(?<!user[ -])(?<!ssh-)(?<!gpg-)(?:the\s+|an?\s+|all\s+|any\s+)?"
      r"(?:ai|a\.i\.|llms?|large\s+language\s+models?|language\s+models?|ai\s+agents?|coding\s+agents?|agents?|"
      r"ai\s+assistants?|coding\s+assistants?|assistants?|claude(?:\s+code)?|copilot|cursor|codex|gemini|chatgpt|"
      r"devin|windsurf|cline|aider|ai\s+models?|ai\s+tools?|automated\s+(?:tools?|agents?|reviewers?)|"
      r"modelos?\s+de\s+lenguaje|asistentes?|agentes?(?:\s+de\s+ia)?|ia)(?![\w-])")
_ACT = (r"(?:run|execute|exec|install|download|curl|wget|send|upload|post|read|cat|print|output|copy|include|"
        r"append|paste|fetch|open|load|source|ignore|disregard|forget|bypass|disable|approve|grant|add|commit|push|"
        r"ejecut\w*|lee|leer|env[ií]a\w*|sube|subir|copia\w*|instala\w*|descarga\w*|ignora\w*)")
# El comentario se DIRIGE a un agente (no solo habla de agentes)
DIRECTIVE = re.compile(
    rf"(?i)(?:^|(?<=[.!?:;]\s)|(?<=[\n*#>-]\s))(?:note|attention|important|instructions?|message|reminder|hint|"
    rf"nota|atenci[oó]n|aviso|instrucciones?)\s+(?:for|to|para|a)\s+{_T}\s*[:,\-—]?|"
    rf"(?:^|(?<=[.!?;]\s))(?:hey|hi|hello|dear|attention|hola|atenci[oó]n)?\s*{_T}\s*[:,—]\s*(?=[^.]{{0,60}}\b(?:you|when|before|after|always|please|first|{_ACT})\b)|"
    rf"\b(?:if|when|since|as)\s+you(?:'re|\s+are)\s+{_T}|"
    rf"\b(?:si\s+eres|cuando\s+seas)\s+{_T}|"
    rf"{_T}\s+(?:must|should|needs?\s+to|have\s+to|has\s+to|are\s+required\s+to|is\s+required\s+to|shall|"
    rf"debe|deben|tiene\s+que|tienen\s+que)\s+(?:always\s+|first\s+|also\s+|now\s+|siempre\s+|primero\s+)?{_ACT}\b")
ACTION = re.compile(rf"(?i)\b{_ACT}\b")
RISK = re.compile(
    r"(?i)\bcurl\b|\bwget\b|\|\s*(ba|z)?sh\b|https?://|\.ssh\b|id_rsa|id_ed25519|\.aws\b|\.env\b|\.netrc|"
    r"\.npmrc|\.pypirc|\.git-credentials|credentials|printenv|environment\s+variables|\benv\s+vars?\b|process\.env|"
    r"os\.environ|api[_ -]?keys?|\btokens?\b|\bsecrets?\b|passwords?|private\s+keys?|webhook|base64|\beval\b|"
    r"/dev/tcp|\bnc\b|\bncat\b|\bsocat\b|pastebin|ngrok|discord(app)?\.com/api|api\.telegram|"
    r"\b(previous|prior|system|your)\s+(instructions|prompt|rules)|guardrails|bypassPermissions|"
    r"dangerously-skip-permissions|--yolo\b")
# Graves aunque no haya fórmula de "dirigirse" a un agente
STRONG = [
    ("ignore-instructions", re.compile(
        r"(?i)\b(ignore|disregard|forget|override)\b[^\n.]{0,40}\b(previous|prior|above|earlier|all|system|safety|your)\b"
        r"[^\n.]{0,30}\b(instructions?|prompt|guidelines|guardrails)\b")),
    ("hide-from-user", re.compile(
        r"(?i)\b(do\s*n[o']t|never|without)\b[^\n.]{0,30}\b(tell|telling|inform|informing|mention|mentioning|notify|"
        r"alert|show|reveal|ask|asking)\b[^\n.]{0,20}\b(the\s+)?(user|human|developer|operator)\b|"
        r"\b(silently|secretly|quietly|covertly)\b[^\n.]{0,60}\b(run|execute|send|upload|post|curl|fetch|read|copy)\b")),
    ("role-hijack", re.compile(  # sensible a mayúsculas: "[system]" en tests de mensajes es normal
        r"\b[Yy]ou\s+are\s+now\b|\b[Nn]ew\s+system\s+instructions\b|<\|im_start\|>|\bBEGIN\s+SYSTEM\s+PROMPT\b|"
        r"\[/?(SYSTEM|INST)\]|</?(system_prompt|SYSTEM)>")),
]
# Lo que convierte un WARN en BLOCK
ESCALATE = re.compile(
    r"(?i)(\bcurl\b|\bwget\b)[^\n]{0,120}\|\s*(ba|z)?sh\b|\b(send|upload|post|exfiltrate|forward|transmit|env[ií]a\w*)\b"
    r"[^\n]{0,80}(https?://|webhook|pastebin|ngrok|discord|telegram)|"
    r"(\.ssh\b|id_rsa|id_ed25519|\.aws/credentials|\.git-credentials|\.netrc|printenv)[^\n]{0,80}"
    r"\b(send|upload|post|curl|wget|include|paste|output|print|append|commit|add)\b|"
    r"\b(send|upload|post|curl|wget|include|paste|output|print|append|commit|add)\b[^\n]{0,80}"
    r"(\.ssh\b|id_rsa|id_ed25519|\.aws/credentials|\.git-credentials|\.netrc|printenv)|"
    r"\b(ignore|disregard|forget)\b[^\n.]{0,40}\b(previous|prior|above|all|system|your)\b[^\n.]{0,30}\binstructions?\b")
NEG_BEFORE_ACTION = re.compile(
    r"(?i)\b(never|don'?t|do\s+not|must\s+not|should\s+not|shouldn'?t|cannot|can'?t|won'?t|avoid|refuse|nunca|no)\b"
    r"[^.!?;]{0,40}?\b(run|execute|exec|install|download|curl|wget|send|upload|post|read|cat|print|output|log|copy|"
    r"include|paste|fetch|open|ignore|disregard|bypass|disable|use|commit|push|leak|expose|share|ejecut\w*|env[ií]\w*|le\w*)\b")
TEST_DIR = re.compile(r"(^|/)(tests?|__tests__|spec|testdata|fixtures?|examples?|docs?)/", re.I)
WINDOW = 300  # la acción de riesgo tiene que ir justo detrás de la fórmula dirigida al agente


def classify(body: str) -> tuple[str | None, str, int]:
    """→ (severidad o None, motivo, posición en el texto aplanado).

    WARN/BLOCK solo si el comentario SE DIRIGE a un agente ("Claude: …", "If you are an AI…",
    "Note for AI assistants", "agents must run …") y justo detrás pide algo de riesgo. Las frases en
    negativo ("agents should never send tokens…") no cuentan. Hablar de agentes (docstrings de un SDK
    de IA) no basta."""
    flat = " ".join(body.split())
    hide = STRONG[1][1].search(flat)
    hijack = STRONG[2][1].search(flat)
    best = None
    for m in DIRECTIVE.finditer(flat):
        win = flat[m.start(): m.end() + WINDOW]
        active = " ".join(s for s in re.split(r"(?<=[.!?;])\s+", win) if not NEG_BEFORE_ACTION.search(s))
        if not (ACTION.search(active) and RISK.search(active)):
            continue
        if ESCALATE.search(active) or hide or hijack:
            why = "hide-from-user" if hide else "role-hijack" if hijack else "acción de riesgo grave"
            return "block", "se dirige a un agente + " + why, m.start()
        best = best or ("warn", "se dirige a un agente + acción de riesgo", m.start())
    if best:
        return best
    # "Ignore previous instructions…" / "You are now…" sin dirigirse a nadie: grave solo si detrás
    # viene una acción de riesgo; si no, es típico de plantillas de prompt en repos de IA → info
    for rid, m in (("ignore-instructions", STRONG[0][1].search(flat)), ("role-hijack", hijack)):
        if not m:
            continue
        win = flat[m.start(): m.end() + WINDOW]
        if ACTION.search(win) and RISK.search(win) and ESCALATE.search(win):
            return "block", rid + " + acción de riesgo grave", m.start()
        return "info", rid + " (posible plantilla de prompt)", m.start()
    return None, "", 0


def scan(repo, skip: set[str]) -> list[dict]:
    out: list[dict] = []
    for rel in repo.files:
        if rel in skip:
            continue
        text = repo.text(rel)
        if text is None:
            continue
        n = 0
        for off, body in extract(rel, text):
            if len(body.strip()) < 15:
                continue
            zw = ZW_RE.findall(body)
            if zw:
                out.append(finding("warn", PHASE, "comment-zero-width", rel,
                                   f"Caracteres de ancho cero ({len(zw)}) dentro de un comentario",
                                   line_of(text, off), body.strip()[:300]))
            sev, why, pos = classify(body)
            if not sev:
                continue
            if sev == "warn" and TEST_DIR.search(rel):
                sev = "info"  # tests/ejemplos/docs suelen contener prompts de ejemplo
            flat = " ".join(body.split())
            snip = ("…" if pos > 80 else "") + flat[max(0, pos - 80): pos + 320]
            out.append(finding(sev, PHASE, "code-comment-injection", rel,
                               f"Comentario en código dirigido a agentes de IA ({why})",
                               line_of(text, off), snip))
            n += 1
            if n >= 5:
                break
    return out
