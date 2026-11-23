"""Analiza un repositorio ya clonado (en cuarentena) y emite un veredicto.

Uso:  python3 -I -m checker.main <repo> [--json out.json] [--report out.md] [--no-llm] [--no-external]
Salida: 0 = OK, 10 = WARN, 20 = BLOCK, 2 = error
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys

from . import agent_surface, external, llm_review, static_scan
from .common import SEV_ORDER, Repo, reveal

EXIT = {"ok": 0, "warn": 10, "block": 20}
C = {"ok": "\033[1;32m", "warn": "\033[1;33m", "block": "\033[1;31m", "info": "\033[2m", "x": "\033[0m"}
LABEL = {"ok": "OK", "warn": "WARN", "block": "BLOCK"}

# Rutas que se renombran a *.quarantined si el usuario elige "neutralizar"
NEUTRALIZABLE = (".claude", ".mcp.json", "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "GEMINI.md", ".cursorrules",
                 ".cursor", ".windsurfrules", ".clinerules", ".github/copilot-instructions.md", ".vscode/tasks.json",
                 ".vscode/settings.json", ".vscode/mcp.json", ".devcontainer", ".envrc", ".gemini", ".codex")


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def neutralize_targets(repo, findings):
    hit = {f["file"] for f in findings if f["severity"] != "info"
           and (f["phase"].startswith("2") or any(f["file"].startswith(p) for p in NEUTRALIZABLE))}
    targets = set()
    for path in hit:
        for n in NEUTRALIZABLE:
            if path == n or path.startswith(n + "/"):
                targets.add(n)
                break
        else:
            if os.path.basename(path) in ("CLAUDE.md", "AGENTS.md", "CLAUDE.local.md", "GEMINI.md"):
                targets.add(path)
    return sorted(t for t in targets if repo.exists(t))


def render_report(name, verdict, findings, llm, instr, execcfg, targets):
    L = [f"# Informe git-check: {name}", "",
         f"- **Veredicto:** {LABEL[verdict]}",
         f"- **Fecha:** {dt.datetime.now().isoformat(timespec='seconds')}",
         f"- **Hallazgos:** " + ", ".join(f"{k}={sum(f['severity'] == k for f in findings)}" for k in ("block", "warn", "info")),
         ""]
    if llm:
        L += ["## Revisión LLM (Opus, sin herramientas)", ""]
        if "error" in llm:
            L += [f"⚠️ No disponible: {llm['error']}", ""]
        else:
            L += [f"**Veredicto LLM:** {llm['verdict']}"
                  + (" — ⚠️ **INTENTO DE INYECCIÓN CONTRA EL REVISOR**" if llm.get("injection_attempt_against_reviewer") else ""),
                  "", reveal(llm.get("summary", "")), ""]
            for f in llm.get("findings", []):
                L.append(f"- **[{f['severity']}] {f['category']}** `{reveal(f['file'])}`: {reveal(f['explanation'])}"
                         + (f"\n  > {reveal(f.get('evidence', ''))[:300]}" if f.get("evidence") else ""))
            if llm.get("cost_usd") is not None:
                L += ["", f"_coste: ${llm['cost_usd']:.4f}, payload {llm['payload_chars']} chars_"]
            L.append("")
    L += ["## Superficie de agentes", "",
          "**Instrucciones:** " + (", ".join(f"`{x}`" for x in instr) or "ninguna"),
          "", "**Config ejecutable:** " + (", ".join(f"`{x}`" for x in execcfg) or "ninguna"), ""]
    if targets:
        L += ["**Neutralizables:** " + ", ".join(f"`{t}`" for t in targets), ""]
    L += ["## Hallazgos deterministas", ""]
    for sev in ("block", "warn", "info"):
        group = [f for f in findings if f["severity"] == sev]
        if not group:
            continue
        L += [f"### {sev.upper()} ({len(group)})", ""]
        for f in group:
            loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
            L.append(f"- `{f['rule']}` **{loc}** — {f['message']}")
            if f.get("snippet"):
                L.append(f"  ```\n  {f['snippet']}\n  ```")
        L.append("")
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--json")
    ap.add_argument("--report")
    ap.add_argument("--name")
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--no-external", action="store_true")
    a = ap.parse_args(argv)

    repo = Repo(a.repo)
    name = a.name or os.path.basename(repo.root)
    log(f"🔎 git-check: {len(repo.files)} ficheros en {name}")

    log("  [1/3] código malicioso / ejecución…")
    findings = static_scan.scan(repo)
    if not a.no_external:
        findings += external.scan(repo)
    log("  [2/3] superficie de agentes LLM…")
    f2, instr, execcfg = agent_surface.scan(repo)
    findings += f2

    # dedupe
    seen, uniq = set(), []
    for f in findings:
        k = (f["rule"], f["file"], f["line"], f["message"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    findings = sorted(uniq, key=lambda f: (-SEV_ORDER[f["severity"]], f["file"], f["line"] or 0))

    sevs = {f["severity"] for f in findings}
    verdict = "block" if "block" in sevs else "warn" if "warn" in sevs else "ok"

    llm = None
    if not a.no_llm:
        log(f"  [3/3] revisión con {llm_review.MODEL} (sin herramientas)…")
        llm = llm_review.review(repo, findings, instr, execcfg)
        if "error" in llm:
            log(f"      ⚠️  LLM no disponible: {llm['error']}")
            verdict = "warn" if verdict == "ok" else verdict
        else:
            lv = "block" if llm.get("injection_attempt_against_reviewer") else llm["verdict"]
            # el LLM solo endurece
            if lv != "ok" and (verdict == "ok" or SEV_ORDER[lv] > SEV_ORDER[verdict]):
                verdict = lv

    targets = neutralize_targets(repo, findings)
    result = {"repo": name, "verdict": verdict, "findings": findings, "llm": llm,
              "agent_instruction_files": instr, "agent_exec_configs": execcfg, "neutralize": targets}
    if a.json:
        with open(a.json, "w") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=1)
    if a.report:
        with open(a.report, "w") as fh:
            fh.write(render_report(name, verdict, findings, llm, instr, execcfg, targets))

    # resumen en terminal (todo saneado con reveal() en finding())
    log("")
    log(f"  Veredicto: {C[verdict]}{LABEL[verdict]}{C['x']}   "
        + "  ".join(f"{k}={sum(f['severity'] == k for f in findings)}" for k in ("block", "warn", "info")))
    if llm and "error" not in llm:
        log(f"  LLM: {llm['verdict']}"
            + (" ⚠️ intentó manipular al revisor" if llm.get("injection_attempt_against_reviewer") else "")
            + f" — {reveal(llm.get('summary', ''))[:600]}")
    shown = [f for f in findings if f["severity"] != "info"][:25]
    for f in shown:
        loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
        log(f"   {C[f['severity']]}{f['severity']:5}{C['x']} {loc} — {f['message']}")
    rest = sum(f["severity"] != "info" for f in findings) - len(shown)
    if rest > 0:
        log(f"   … y {rest} más (ver informe)")
    return EXIT[verdict]


if __name__ == "__main__":
    sys.exit(main())
