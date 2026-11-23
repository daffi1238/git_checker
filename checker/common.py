"""Utilidades compartidas: modelo de hallazgos, recorrido del repo y saneado de texto.

Todo el contenido del repositorio analizado es NO FIABLE. Nada de aquí lo ejecuta:
solo se lee como bytes/texto.
"""
from __future__ import annotations

import json
import os
import re
import subprocess

SEV_ORDER = {"info": 0, "warn": 1, "block": 2}
MAX_TEXT_BYTES = 2_000_000
SKIP_DIRS = {".git"}

# --------------------------------------------------------------------------- Unicode

TAG_RE = re.compile("[\U000E0000-\U000E007F]+")          # "ASCII smuggling" invisible
ZW_RE = re.compile("[​-‍⁠-⁤᠎­]")
BIDI_RE = re.compile("[‪-‮⁦-⁩‎‏؜]")
# Rachas de selectores de variación: no se ven y sirven para esconder payloads (técnica GlassWorm)
VS_RUN_RE = re.compile("[\uFE00-\uFE0F\U000E0100-\U000E01EF]{4,}")
# Controles C0/C1 (salvo \t \n \r): evitan inyección de secuencias ANSI en la terminal
CTRL_RE = re.compile("[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]")


def decode_tags(run: str) -> str:
    return "".join(chr(ord(c) - 0xE0000) for c in run if 0xE0020 <= ord(c) <= 0xE007E)


def reveal(text: str) -> str:
    """Hace visible todo lo invisible/peligroso para mostrarlo a humanos o al LLM."""
    text = TAG_RE.sub(lambda m: f'⟦OCULTO-TAGS:"{decode_tags(m.group())}"⟧', text)
    text = VS_RUN_RE.sub(lambda m: f"⟦OCULTO-VS x{len(m.group())}⟧", text)
    text = ZW_RE.sub(lambda m: f"⟦ZW U+{ord(m.group()):04X}⟧", text)
    text = BIDI_RE.sub(lambda m: f"⟦BIDI U+{ord(m.group()):04X}⟧", text)
    text = CTRL_RE.sub(lambda m: f"⟦CTRL 0x{ord(m.group()):02X}⟧", text)
    return text


# --------------------------------------------------------------------------- Hallazgos

def finding(sev, phase, rule, path, msg, line=None, snippet=None):
    return {
        "severity": sev,
        "phase": phase,
        "rule": rule,
        "file": path,
        "line": line,
        "message": msg,
        "snippet": reveal(snippet)[:400] if snippet else None,
    }


def max_sev(a: str, b: str) -> str:
    return a if SEV_ORDER[a] >= SEV_ORDER[b] else b


def line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def snippet_at(text: str, idx: int, width: int = 200) -> str:
    start = text.rfind("\n", 0, idx) + 1
    end = text.find("\n", idx)
    end = len(text) if end == -1 else end
    line = text[start:end]
    if len(line) > width:
        col = idx - start
        lo = max(0, col - width // 2)
        line = ("…" if lo else "") + line[lo:lo + width] + "…"
    return line.strip()


# --------------------------------------------------------------------------- Repo

class Repo:
    def __init__(self, root: str):
        self.root = os.path.realpath(root)
        self.files: list[str] = []          # rutas relativas
        self._text: dict[str, str | None] = {}
        self.symlinks: dict[str, str] = {}  # ruta -> destino (según el índice de git)
        self._walk()
        self._load_git_symlinks()

    def _walk(self):
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                ap = os.path.join(dirpath, fn)
                self.files.append(os.path.relpath(ap, self.root))
            for d in dirnames:  # symlinks a directorios aparecen como dirs
                ap = os.path.join(dirpath, d)
                if os.path.islink(ap):
                    self.files.append(os.path.relpath(ap, self.root))
        self.files.sort()

    def _load_git_symlinks(self):
        """Con core.symlinks=false los symlinks se escriben como ficheros de texto;
        el índice de git conserva el modo 120000 y el destino real."""
        if not os.path.isdir(os.path.join(self.root, ".git")):
            return
        try:
            out = subprocess.run(
                ["git", "-c", "core.hooksPath=/dev/null", "-C", self.root, "ls-files", "-s", "-z"],
                capture_output=True, timeout=60, check=False).stdout
        except Exception:
            return
        for entry in out.split(b"\0"):
            if not entry.startswith(b"120000 "):
                continue
            meta, _, path = entry.partition(b"\t")
            sha = meta.split()[1].decode()
            target = subprocess.run(
                ["git", "-C", self.root, "cat-file", "blob", sha],
                capture_output=True, timeout=30, check=False).stdout
            self.symlinks[path.decode("utf-8", "replace")] = target.decode("utf-8", "replace")

    def abspath(self, rel: str) -> str:
        return os.path.join(self.root, rel)

    def exists(self, rel: str) -> bool:
        return os.path.lexists(self.abspath(rel))

    def text(self, rel: str) -> str | None:
        """Devuelve el contenido como texto o None si es binario/enorme/symlink."""
        if rel in self._text:
            return self._text[rel]
        ap = self.abspath(rel)
        val = None
        try:
            if not os.path.islink(ap) and os.path.isfile(ap):
                with open(ap, "rb") as fh:
                    data = fh.read(MAX_TEXT_BYTES + 1)
                if len(data) <= MAX_TEXT_BYTES and b"\x00" not in data[:8192]:
                    val = data.decode("utf-8", "replace")
        except OSError:
            pass
        self._text[rel] = val
        return val

    def head_bytes(self, rel: str, n: int = 8) -> bytes:
        try:
            with open(self.abspath(rel), "rb") as fh:
                return fh.read(n)
        except OSError:
            return b""

    def size(self, rel: str) -> int:
        try:
            return os.lstat(self.abspath(rel)).st_size
        except OSError:
            return 0


def load_json_loose(text: str):
    """JSON tolerante a comentarios // y /* */ y comas finales (jsonc)."""
    try:
        return json.loads(text)
    except Exception:
        pass
    t = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    t = re.sub(r'(?m)^(\s*)//.*$', r"\1", t)
    t = re.sub(r",(\s*[}\]])", r"\1", t)
    try:
        return json.loads(t)
    except Exception:
        return None
