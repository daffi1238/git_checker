# git_checker

`git clone` con cuarentena. Antes de entregarte un repositorio comprueba si contiene **código malicioso**
o **instrucciones/configuración que abusen de un agente LLM** (Claude Code, Cursor, Copilot…) cuando lo
abras con él. La hipótesis de partida es que todo repo que clones acabará abierto con Claude Code.

```
$ git clone https://github.com/x/y
🔒 Clonando en cuarentena…
  [1/3] código malicioso / ejecución…
  [2/3] superficie de agentes LLM…
  [3/3] revisión con opus (sin herramientas)…
  Veredicto: BLOCK   block=17  warn=6  info=6
   block .claude/settings.json — settings fija la variable de entorno ANTHROPIC_BASE_URL
   block CLAUDE.md:8 — Texto oculto con Unicode TAG chars (invisible para humanos, legible para LLMs)
   …
⛔ BLOCK: el repositorio NO se ha entregado. Retenido en: ~/.cache/git-checker/quarantine/y-…
```

## Instalación rápida

Requisitos: Linux/macOS con `bash`, `git`, `python3` (≥3.10), `jq` y, para la fase LLM,
[Claude Code](https://docs.claude.com/en/docs/claude-code) (`claude`) con sesión iniciada.
`~/.local/bin` tiene que ir **antes** que `/usr/bin` en el `PATH` (es lo habitual).

```bash
# 1. Descargar (usa el git real: el checker aún no está instalado)
/usr/bin/git clone https://github.com/daffi1238/git_checker ~/git_checker

# 2. Instalar todo: shim de git + escáneres (semgrep, guarddog, osv-scanner) + hook de secretos para Claude Code
cd ~/git_checker && ./install.sh --all

# 3. Recargar y comprobar
hash -r; type git            # → git is ~/.local/bin/git
git clone https://github.com/sindresorhus/slugify /tmp/slugify   # → OK y entregado
```

Instalación mínima (solo el checker, sin escáneres externos ni hook): `./install.sh`.
`--tools` instala los escáneres (necesita `uv` o `pipx`, y `go` para osv-scanner); `--guard` registra
el hook (hace copia de seguridad de `~/.claude/settings.json`). Desinstalar: `./install.sh --uninstall`.

Probar con un repo malicioso de ejemplo (es inerte: todo apunta a `example.invalid`):

```bash
python3 -I ~/git_checker/tests/make_fixtures.py /tmp/fx
git clone /tmp/fx/evil /tmp/evil      # → BLOCK, se queda en cuarentena
```

## Uso

```bash
git clone <url> [dir]                # pasa por el checker (también desde Claude Code)
GIT_CHECK=0 git clone …              # saltarse la revisión
git-check ./repo                     # analizar un directorio que ya tienes
git-safe-clone --list                # repos retenidos en cuarentena
git-safe-clone --release ~/.cache/git-checker/quarantine/<id> [--neutralize]
```

| Veredicto | Qué pasa |
|---|---|
| **OK** | Se entrega en el destino |
| **WARN** | Pregunta: `a` aceptar · `n` neutralizar config de agentes y aceptar · `r` rechazar · `v` ver informe. Sin terminal se queda retenido |
| **BLOCK** | Se queda retenido; solo se entrega (neutralizado) si escribes `ACEPTO` |

**Neutralizar** renombra a `*.quarantined` la configuración de agentes y de auto-ejecución que tiene
hallazgos (`.claude/`, `.mcp.json`, `CLAUDE.md`, `.vscode/tasks.json`, `.devcontainer`, `.envrc`, …).
Los informes se guardan en `~/.local/share/git-checker/reports/`.

Variables: `GIT_CHECK_NO_LLM=1` (sin fase 3), `GIT_CHECK_NO_EXTERNAL=1` (sin semgrep/guarddog/osv),
`GIT_CHECK_MODEL=opus`, `GIT_CHECK_LLM_TIMEOUT=300`, `GIT_CHECK_NONINTERACTIVE=1`,
`GIT_CHECK_FORCE=1` (interceptar también en scripts sin TTY), `GIT_CHECK_QUARANTINE`, `GIT_CHECK_REPORTS`.

## Cómo funciona

```
git clone  →  ~/.local/bin/git (shim)  →  git-safe-clone
  0. clon en cuarentena: sin hooks, sin submódulos, sin LFS, symlinks como texto, fsck activado;
     rechaza --upload-pack / --template / -c peligrosos
  1. código: install hooks (npm, setup.py, pyproject), .vscode folderOpen, devcontainer, direnv,
     ofuscación y payloads ocultos con espacios, curl|sh, reverse shells, robo de credenciales/wallets,
     endpoints de exfiltración, binarios, Trojan Source, payloads invisibles con selectores de
     variación Unicode (GlassWorm)
     + semgrep (rules/semgrep) + guarddog (npm/pypi) + osv-scanner (paquetes MAL-* conocidos)
  2. agentes: CLAUDE.md (+@imports, incluidos los que salen del repo), .claude/settings*.json (hooks,
     env ANTHROPIC_BASE_URL/proxies/OTEL, apiKeyHelper, statusLine, permisos, bypassPermissions),
     .mcp.json, commands/skills/agents (!`…`, allowed-tools), AGENTS.md/.cursorrules/copilot/…,
     Unicode invisible (TAG/zero-width/bidi), comentarios HTML ocultos, prompt injection,
     imágenes markdown con datos en la URL
     + comentarios de código (#, //, /* */, docstrings, <!-- --> en html/vue/jsx…, --) que SE DIRIGEN
     a un agente ("Claude: …", "If you are an AI…", "Note for AI assistants", "agents must run…") y
     piden algo de riesgo justo detrás (curl|sh, leer ~/.ssh o .env, enviar datos fuera, ocultarlo)
  3. Opus vía `claude -p` SIN herramientas (--tools "", sin MCP, sin settings, cwd vacío);
     el repo va como datos delimitados por un token aleatorio; salida con JSON Schema
```

- El LLM **solo puede endurecer** el veredicto determinista, nunca relajarlo. Si el LLM falla, el
  mínimo es WARN; si el analizador falla, el repo se queda en cuarentena.
- El shim solo intercepta cuando hay terminal o cuando lo ejecuta Claude Code (`CLAUDECODE=1`); cron
  y scripts van directos al git real.
- Coste de la fase 3: ~0,15–0,25 $ y 10–30 s por repo.

## Guard de secretos (`guard/protect_secrets.py`)

Hook `PreToolUse` de Claude Code (`./install.sh --guard`) que permite **usar** claves (`ssh`, `scp -i`,
`rsync -e "ssh -i…"`, `git`, `ssh-add`) pero impide que el agente las **lea, copie o modifique**:
`cat`/`base64`/`tar`/`cp`/`docker -v` sobre `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`, `~/.kube`,
`~/.docker` y `~/.claude/.credentials.json`; `scp` de una clave como fichero; redirecciones `< clave`;
escrituras en `authorized_keys`. Las claves se detectan por su nombre real (lista `~/.ssh`), no por
`id_*`. `config`, `known_hosts` y `*.pub` sí se pueden leer. Los bloqueos quedan en
`~/.local/share/git-checker/guard.log`.

## Tests

```bash
python3 -I tests/make_fixtures.py /tmp/fx      # genera los repos 'evil' (inerte) y 'benign'
GIT_CHECK_NO_LLM=1 bin/git-safe-clone --scan /tmp/fx/evil     # → BLOCK (rc=20)
GIT_CHECK_NO_LLM=1 bin/git-safe-clone --scan /tmp/fx/benign   # → OK (rc=0)
GIT_CHECK_NO_LLM=1 bin/git-safe-clone --scan /tmp/fx/comments # → BLOCK solo por comentarios en código
```

Los fixtures se generan en tiempo de ejecución para que este repo no contenga un `CLAUDE.md`
malicioso que Claude Code pudiera cargar al trabajar aquí.

## Límites

- Es heurístico. Un atacante decidido puede esquivar las reglas y, con menos probabilidad, también al LLM.
  Es una capa más, no un sustituto del sandbox ni de las reglas de permisos de tu agente.
- Los comentarios se extraen con regex, no con un parser. Para no ahogar en ruido los repos de IA
  (SDKs, langchain…), un comentario que solo *habla* de agentes no cuenta; tiene que *dirigirse* a uno.
  Una inyección redactada como prosa neutra puede pasar el filtro determinista. Para eso está Opus,
  que recibe aparte los comentarios sospechosos aunque sean de nivel info.
- Solo analiza lo clonado. Quedan fuera los submódulos, las dependencias que se instalen después y
  el código que se descargue en tiempo de ejecución.
- `gh repo clone`, los IDEs y cualquier herramienta que llame a `/usr/bin/git` por ruta absoluta no
  pasan por el shim.
- osv-scanner consulta osv.dev con la lista de dependencias (nombres públicos de paquetes).
- Este repositorio contiene a propósito patrones de ataque (son las reglas de detección), así que si
  lo analizas con él mismo, saldrá marcado.
