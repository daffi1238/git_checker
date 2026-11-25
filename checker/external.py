"""Integration with (optional) external scanners: semgrep, guarddog, osv-scanner.

They all run with cwd set to an empty temporary directory, so they don't pick up
config/ignore files planted in the repo being analyzed.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile

from .common import finding

PHASE = "1-externo"
HERE = os.path.dirname(os.path.abspath(__file__))
RULES = os.path.join(os.path.dirname(HERE), "rules", "semgrep")
EXTRA_PATHS = [os.path.expanduser("~/.local/bin"), os.path.expanduser("~/go/bin")]

GUARDDOG_BLOCK = {"threat-network-reverse-shell", "threat-process-download-exec", "threat-network-exfiltration",
                  "threat-network-exfil-messenger", "threat-process-cryptomining",
                  "threat-runtime-obfuscation-base64exec", "threat-runtime-obfuscation-hidden-code",
                  "threat-network-exfil-sysinfo", "threat-runtime-keylogging", "threat-runtime-self-propagation",
                  "threat-process-powershell-encoded", "threat-setup-network-in-install", "threat-filesystem-autostart"}


def _which(name):
    return shutil.which(name) or next((os.path.join(p, name) for p in EXTRA_PATHS
                                       if os.access(os.path.join(p, name), os.X_OK)), None)


def _run(cmd, timeout):
    with tempfile.TemporaryDirectory(prefix="gitcheck-") as cwd:
        env = dict(os.environ, SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)


def semgrep(root):
    exe = _which("semgrep")
    if not exe:
        return [finding("info", PHASE, "tool-missing", "-", "semgrep not installed")]
    try:
        p = _run([exe, "scan", "--config", RULES, "--metrics=off", "--json", "--quiet", "--no-git-ignore",
                  "--disable-version-check", "--timeout", "20", "--max-target-bytes", "2000000", root], 600)
        data = json.loads(p.stdout or "{}")
    except Exception as e:
        return [finding("warn", PHASE, "tool-error", "-", f"semgrep failed: {e}")]
    sevmap = {"ERROR": "block", "WARNING": "warn", "INFO": "info"}
    out = []
    for r in data.get("results", []):
        ex = r.get("extra", {})
        out.append(finding(sevmap.get(ex.get("severity"), "warn"), PHASE, "semgrep:" + r["check_id"].split(".")[-1],
                           os.path.relpath(r["path"], root), ex.get("message", ""), r.get("start", {}).get("line"),
                           ex.get("lines")))
    return out


def guarddog(root, ecosystems):
    exe = _which("guarddog")
    if not exe:
        return [finding("info", PHASE, "tool-missing", "-", "guarddog not installed")]
    out = []
    for eco in ecosystems:
        data = None
        for sandbox in ("--sandbox", "--no-sandbox"):  # the kernel sandbox may not be available
            try:
                p = _run([exe, eco, "scan", root, "--output-format", "json", sandbox], 600)
                data = json.loads(p.stdout or "null")
                if data is not None:
                    break
            except Exception:
                continue
        if not isinstance(data, dict):
            out.append(finding("warn", PHASE, "tool-error", "-", f"guarddog {eco} produced no result"))
            continue
        for rule, res in (data.get("results") or {}).items():
            if not res:
                continue
            if rule.startswith("capability-"):
                sev = "info"
            else:
                sev = "block" if rule in GUARDDOG_BLOCK else "warn"
            if isinstance(res, list):
                for item in res[:5]:
                    loc = str(item.get("location", "-"))
                    path, _, line = loc.rpartition(":")
                    path = path or loc
                    if os.path.isabs(path):
                        path = os.path.relpath(path, root)
                    s2 = "info" if sev == "warn" and re.search(r"(^|/)(tests?|docs?|examples?|fixtures?)/", path) else sev
                    out.append(finding(s2, PHASE, f"guarddog:{rule}", path, item.get("message", rule),
                                       int(line) if line.isdigit() else None, item.get("code")))
            else:
                out.append(finding(sev, PHASE, f"guarddog:{rule}", "-", str(res)[:300]))
    return out


def osv(root):
    exe = _which("osv-scanner")
    if not exe:
        return [finding("info", PHASE, "tool-missing", "-", "osv-scanner not installed")]
    try:
        p = _run([exe, "scan", "source", "-r", "--format", "json", root], 300)
        data = json.loads(p.stdout or "{}")
    except Exception as e:
        return [finding("info", PHASE, "tool-error", "-", f"osv-scanner failed: {e}")]
    out, vuln_pkgs = [], []
    for res in data.get("results") or []:
        src = os.path.relpath(res.get("source", {}).get("path", root), root)
        for pkg in res.get("packages") or []:
            info = pkg.get("package", {})
            ids = [v.get("id", "") for v in pkg.get("vulnerabilities") or []]
            mal = [i for i in ids if i.startswith("MAL-")]
            name = f"{info.get('ecosystem')}/{info.get('name')}@{info.get('version')}"
            if mal:
                out.append(finding("block", PHASE, "osv-malicious-package", src,
                                   f"Known MALICIOUS dependency: {name} ({', '.join(mal)})"))
            elif ids:
                vuln_pkgs.append(f"{name} ({len(ids)})")
    if vuln_pkgs:
        out.append(finding("info", PHASE, "osv-vulns", "-",
                           f"{len(vuln_pkgs)} dependencies with known CVEs: " + ", ".join(vuln_pkgs[:15])))
    return out


def scan(repo):
    root = repo.root
    findings = semgrep(root)
    ecos = []
    if any(os.path.basename(f) == "package.json" for f in repo.files):
        ecos.append("npm")
    if any(os.path.basename(f) in ("setup.py", "pyproject.toml", "setup.cfg") for f in repo.files):
        ecos.append("pypi")
    findings += guarddog(root, ecos)
    findings += osv(root)
    return findings
