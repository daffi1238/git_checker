#!/usr/bin/env bash
# Instala git_checker (idempotente).
#   ./install.sh            shim de git + git-safe-clone + atajo git-check
#   ./install.sh --tools    además instala semgrep, guarddog (uv) y osv-scanner (go)
#   ./install.sh --guard    además registra el hook protect_secrets en ~/.claude/settings.json
#   ./install.sh --all      todo lo anterior
#   ./install.sh --uninstall
set -euo pipefail
ROOT=$(cd "$(dirname "$0")" && pwd)
BIN="$HOME/.local/bin"
SETTINGS="$HOME/.claude/settings.json"
HOOK_CMD="/usr/bin/env python3 -I $ROOT/guard/protect_secrets.py"
TOOLS="" GUARD="" UNINSTALL=""
for a in "$@"; do
  case $a in
    --tools) TOOLS=1 ;;
    --guard) GUARD=1 ;;
    --all) TOOLS=1 GUARD=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "opción desconocida: $a" >&2; exit 2 ;;
  esac
done

if [[ -n $UNINSTALL ]]; then
  for f in git git-safe-clone; do
    [[ -L $BIN/$f && $(readlink -f "$BIN/$f") == "$ROOT"/bin/* ]] && rm -f "$BIN/$f" && echo "eliminado $BIN/$f"
  done
  for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [[ -f $rc ]] && sed -i.bak '/# git_checker$/d' "$rc" && echo "limpiado $rc"
  done
  if [[ -f $SETTINGS ]] && command -v jq >/dev/null; then
    cp -p "$SETTINGS" "$SETTINGS.bak-$(date +%Y%m%d-%H%M%S)"
    jq --arg c "protect_secrets.py" '(.hooks.PreToolUse // []) |= map(select(([.hooks[]?.command] | any(contains($c))) | not))' \
      "$SETTINGS" >"$SETTINGS.tmp" && mv "$SETTINGS.tmp" "$SETTINGS" && echo "hook eliminado de $SETTINGS"
  fi
  exit 0
fi

# ---------- requisitos
command -v python3 >/dev/null || { echo "falta python3 (>=3.10)"; exit 1; }
command -v jq >/dev/null || echo "AVISO: falta jq (necesario): sudo apt install jq"
command -v claude >/dev/null || echo "AVISO: falta claude CLI: sin él no hay fase 3 (LLM) y el veredicto mínimo será WARN"

# ---------- binarios
mkdir -p "$BIN"
chmod +x "$ROOT/bin/git-safe-clone" "$ROOT/bin/git-shim" "$ROOT/gitcheck.py" "$ROOT/guard/protect_secrets.py"
ln -sf "$ROOT/bin/git-safe-clone" "$BIN/git-safe-clone"
ln -sf "$ROOT/bin/git-shim" "$BIN/git"     # intercepta `git clone`
echo "instalado: $BIN/git (shim) y $BIN/git-safe-clone"
case ":$PATH:" in
  *":$BIN:"*) [[ $(type -P git) == "$BIN/git" ]] || echo "AVISO: $BIN no va antes que /usr/bin en el PATH; el shim no actuará" ;;
  *) echo "AVISO: $BIN no está en el PATH. Añade a tu ~/.bashrc:  export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac

LINE="[ -f \"$ROOT/shell/git-wrapper.sh\" ] && . \"$ROOT/shell/git-wrapper.sh\"  # git_checker"
for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
  [[ -f $rc ]] || continue
  grep -qF "# git_checker" "$rc" || { printf '\n%s\n' "$LINE" >>"$rc"; echo "añadido atajo git-check a $rc"; }
done

# ---------- escáneres externos (opcionales)
if [[ -n $TOOLS ]]; then
  if command -v uv >/dev/null; then
    uv tool install semgrep || true
    uv tool install guarddog || true
  elif command -v pipx >/dev/null; then
    pipx install semgrep || true
    pipx install guarddog || true
  else
    echo "AVISO: ni uv ni pipx: no instalo semgrep/guarddog (curl -LsSf https://astral.sh/uv/install.sh | sh)"
  fi
  if command -v go >/dev/null; then
    go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest || true
  else
    echo "AVISO: sin go no instalo osv-scanner (o descarga el binario de github.com/google/osv-scanner/releases)"
  fi
fi

# ---------- hook de secretos para Claude Code
if [[ -n $GUARD ]]; then
  command -v jq >/dev/null || { echo "--guard necesita jq"; exit 1; }
  mkdir -p "$(dirname "$SETTINGS")"
  [[ -f $SETTINGS ]] || echo '{}' >"$SETTINGS"
  if jq -e '[.hooks.PreToolUse[]?.hooks[]?.command] | any(contains("protect_secrets.py"))' "$SETTINGS" >/dev/null; then
    echo "hook protect_secrets ya registrado"
  else
    cp -p "$SETTINGS" "$SETTINGS.bak-$(date +%Y%m%d-%H%M%S)"
    jq --arg c "$HOOK_CMD" '.hooks.PreToolUse = ((.hooks.PreToolUse // []) + [{"matcher":"Bash|Read|Edit|MultiEdit|Write|NotebookEdit|Grep","hooks":[{"type":"command","command":$c,"timeout":10}]}])' \
      "$SETTINGS" >"$SETTINGS.tmp" && jq -e . "$SETTINGS.tmp" >/dev/null && mv "$SETTINGS.tmp" "$SETTINGS"
    echo "hook protect_secrets registrado en $SETTINGS (copia de seguridad creada)"
  fi
fi

# ---------- estado
echo
for t in jq claude semgrep guarddog osv-scanner; do
  if command -v "$t" >/dev/null || [[ -x $HOME/go/bin/$t ]]; then echo "  ✔ $t"; else echo "  ✘ $t"; fi
done
echo "Listo. Abre una terminal nueva (o: hash -r) y prueba: git clone https://github.com/sindresorhus/slugify"
