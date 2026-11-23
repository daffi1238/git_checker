#!/usr/bin/env python3
"""Hook PreToolUse de Claude Code: impide que el agente LEA, COPIE o MODIFIQUE claves
privadas y almacenes de credenciales, pero deja USARLAS (ssh, scp -i, git, ssh-add…).

- Read/Grep/Edit/Write/NotebookEdit sobre un directorio protegido → deny
  (salvo ~/.ssh/config, known_hosts* y *.pub, que solo se pueden leer).
- Bash: cada segmento del comando (separado por | ; && || & $( ` ) que mencione una
  ruta protegida o el nombre de una clave privada tiene que empezar por un programa
  que USA claves sin volcarlas (ssh, scp, git, ssh-add…). Además se eliminan los
  argumentos -i <clave> / IdentityFile=…; si sigue apareciendo la clave como origen
  de scp/rsync/redirección < → deny.

Es una defensa más, no una garantía: un comando suficientemente ofuscado puede
esquivarla. Lo que de verdad protege una clave robada es la passphrase.
"""
import json
import os
import re
import sys
import time

HOME = os.path.expanduser("~")
LOG = os.path.join(HOME, ".local/share/git-checker/guard.log")

PROTECTED_DIRS = [os.path.join(HOME, d) for d in
                  (".ssh", ".gnupg", ".aws", ".config/gh", ".kube", ".docker", ".password-store")]
PROTECTED_FILES = [os.path.join(HOME, f) for f in
                   (".claude/.credentials.json", ".netrc", ".git-credentials", ".pypirc", ".npmrc")]
SSH_DIR = os.path.join(HOME, ".ssh")
SSH_READABLE = re.compile(r"^(config|known_hosts(\.old)?|.*\.pub)$")

ALLOW_PROGS = {"ssh", "scp", "sftp", "rsync", "ssh-add", "ssh-keygen", "ssh-copy-id", "ssh-keyscan",
               "git", "ls", "chmod", "stat", "mkdir", "test", "[", "true"}
COPY_PROGS = {"scp", "rsync", "sftp"}
WRAPPERS = {"sudo", "command", "exec", "nohup", "time", "env", "timeout", "nice", "ionice", "stdbuf"}

DIR_WORDS = r"\.(ssh|gnupg|aws|kube|docker|password-store)\b|\.config/gh\b"
FILE_WORDS = r"\.claude/\.credentials\.json|(~|\$\{?HOME\}?|" + re.escape(HOME) + r")/\.(netrc|git-credentials|pypirc|npmrc)\b"


def private_key_names():
    names = set()
    try:
        for fn in os.listdir(SSH_DIR):
            p = os.path.join(SSH_DIR, fn)
            if os.path.isfile(p) and not SSH_READABLE.match(fn) and fn != "authorized_keys":
                names.add(fn)
    except OSError:
        pass
    return names


def deny(reason, detail=""):
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, "a") as fh:
            fh.write(f"{time.strftime('%F %T')} DENY {reason} :: {detail[:500]}\n")
    except OSError:
        pass
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": f"protect_secrets: {reason}. Si necesitas esto de verdad, pide al usuario que lo haga él."}}))
    sys.exit(0)


def resolve(path, cwd):
    if not path:
        return ""
    p = os.path.expanduser(path)
    if not os.path.isabs(p):
        p = os.path.join(cwd or os.getcwd(), p)
    return os.path.realpath(p)


def protected_path(real):
    for d in PROTECTED_DIRS:
        if real == d or real.startswith(d + os.sep):
            return d
    return real if real in PROTECTED_FILES else None


def check_file_tool(tool, inp, cwd):
    path = inp.get("file_path") or inp.get("notebook_path") or inp.get("path") or ""
    real = resolve(path, cwd)
    where = protected_path(real)
    if not where:
        return
    if tool == "Read" and where == SSH_DIR and SSH_READABLE.match(os.path.basename(real)):
        return  # config / known_hosts / .pub: no son secretos
    deny(f"{tool} sobre {path} (zona protegida {where})", path)


SPLIT_RE = re.compile(r"\|\||&&|[|;&\n]|\$\(|`|<\(|>\(")


def strip_identity_args(seg):
    seg = re.sub(r"(^|\s)-i\s*\S+", " ", seg)
    seg = re.sub(r"(?i)-o\s*['\"]?IdentityFile[= ]\S+", " ", seg)
    seg = re.sub(r"(?i)IdentityFile[= ]\S+", " ", seg)
    return seg


ENV_ASSIGN_RE = re.compile(r"""^\s*(\w+=("[^"]*"|'[^']*'|\S*)\s+)+""")
PUBLIC_RE = re.compile(r"\S*\.ssh/(config|known_hosts(\.old)?|[\w.-]+\.pub)(?![\w.-])")


def first_prog(seg):
    toks = ENV_ASSIGN_RE.sub("", seg).strip().split()
    while toks and (re.match(r"^\w+=", toks[0]) or toks[0] in WRAPPERS or toks[0].startswith("-")):
        toks.pop(0)
    return os.path.basename(toks[0]) if toks else ""


def check_bash(cmd):
    keys = private_key_names()
    key_re = re.compile(r"(?<![\w.-])(" + "|".join(map(re.escape, sorted(keys))) + r")(?![\w.-])") if keys else None
    prot_re = re.compile(DIR_WORDS + "|" + FILE_WORDS)

    def mentions(s, strip=False):
        if strip:  # solo para ssh/scp/git…: '-i clave' es USARLA, no leerla
            s = strip_identity_args(s)
        s = PUBLIC_RE.sub(" ", s)  # config, known_hosts y *.pub no son secretos
        return bool(prot_re.search(s) or (key_re and key_re.search(s)))

    if not mentions(cmd):
        return
    segments = [s for s in SPLIT_RE.split(cmd) if s.strip()]
    # 'cd ~/.ssh && cat github_devia' → todo el comando cuenta como dentro de la zona
    entered = any(first_prog(s) in ("cd", "pushd") and mentions(s) for s in segments)
    for seg in segments:
        prog = first_prog(seg)
        if prog in ("cd", "pushd"):
            continue
        if not (mentions(seg, strip=prog in ALLOW_PROGS) or entered):
            continue
        if prog not in ALLOW_PROGS:
            deny(f"'{prog}' tocaría credenciales protegidas", cmd)
        rest = strip_identity_args(seg)
        if re.search(r"<\s*\S*(" + DIR_WORDS + ")", rest) or (key_re and re.search(r"<\s*\S*" + key_re.pattern, rest)):
            deny("redirección de una clave como entrada", cmd)
        if re.search(r">>?\s*\S*(" + DIR_WORDS + ")", rest):
            deny("escritura en zona protegida (p.ej. authorized_keys)", cmd)
        if prog in COPY_PROGS and mentions(rest):
            deny(f"{prog} con una clave/credencial como fichero a copiar", cmd)
        if prog == "git" and re.search(r"\b(add|commit|archive|bundle|send-email|hash-object|show|cat-file)\b", seg) and mentions(rest):
            deny("git manipularía una clave como fichero", cmd)


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        return
    tool = data.get("tool_name", "")
    inp = data.get("tool_input") or {}
    cwd = data.get("cwd") or ""
    try:
        if tool in ("Read", "Edit", "MultiEdit", "Write", "NotebookEdit", "Grep"):
            check_file_tool(tool, inp, cwd)
        elif tool == "Bash":
            check_bash(str(inp.get("command", "")))
    except SystemExit:
        raise
    except Exception as e:  # fallo cerrado si el comando huele a credenciales
        blob = json.dumps(inp)
        if re.search(DIR_WORDS, blob):
            deny(f"error interno del guard ({e}); bloqueo preventivo", blob)


if __name__ == "__main__":
    main()
